"""MCP OAuth 2.1 compound-token shim in front of LiteLLM.

Issues opaque compound bearers that bind a LiteLLM virtual key with
optional per-user Linear OAuth tokens. Claude Desktop sees ONE OAuth
issuer (this shim) and ONE access_token. Server-side, every /mcp/*
request is split into:

  - x-litellm-api-key: Bearer <virtual_key>      (LiteLLM platform auth)
  - x-mcp-linear-authorization: Bearer <linear>  (per-user Linear OAuth)

Authorize flow:
  1. /v1/mcp/oauth/authorize (GET)  → consent form (virtual key + optional Linear toggle)
  2. /v1/mcp/oauth/authorize (POST) → if Linear requested, 302 to Linear authorize;
                                       otherwise mint auth code and 302 back to client
  3. /v1/linear/callback            → exchange Linear code → store binding → 302 to client
  4. /v1/mcp/oauth/token (POST)     → PKCE verify, mint opaque compound bearer

Storage:
  - Redis-backed (sessions, codes, bearers). Survives shim restart.

Token lifecycle:
  - Linear access_token TTL is 24h. Shim auto-refreshes on /mcp/* when within
    REFRESH_LEAD seconds of expiry. Linear rotates refresh_tokens.
  - Compound bearer TTL is BEARER_TTL (default 30 days). Independent of Linear
    rotation because shim refreshes Linear in-place under the same bearer.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import redis.asyncio as redis_async
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

try:
    from langfuse import Langfuse
except ImportError:  # pragma: no cover - SDK optional
    Langfuse = None  # type: ignore[assignment]

LITELLM_BASE = os.environ["LITELLM_BASE_URL"].rstrip("/")
PUBLIC_BASE = os.environ["PUBLIC_BASE_URL"].rstrip("/")
REDIS_URL = os.environ["REDIS_URL"]

LINEAR_CLIENT_ID = os.environ.get("LINEAR_OAUTH_CLIENT_ID", "")
LINEAR_CLIENT_SECRET = os.environ.get("LINEAR_OAUTH_CLIENT_SECRET", "")
LINEAR_AUTHORIZE_URL = os.environ.get(
    "LINEAR_AUTHORIZE_URL", "https://linear.app/oauth/authorize"
)
LINEAR_TOKEN_URL = os.environ.get(
    "LINEAR_TOKEN_URL", "https://api.linear.app/oauth/token"
)
LINEAR_REVOKE_URL = os.environ.get(
    "LINEAR_REVOKE_URL", "https://api.linear.app/oauth/revoke"
)
LINEAR_REDIRECT_URI = os.environ.get("LINEAR_REDIRECT_URI", "")
LINEAR_SCOPES = os.environ.get(
    "LINEAR_OAUTH_SCOPES", "read,write,issues:create,comments:create"
)
LINEAR_ENABLED = bool(LINEAR_CLIENT_ID and LINEAR_CLIENT_SECRET and LINEAR_REDIRECT_URI)

ALLOWED_REDIRECT_PREFIXES = [
    p.strip()
    for p in os.environ.get(
        "ALLOWED_REDIRECT_PREFIXES",
        "https://claude.ai/,https://claude.com/,http://localhost,http://127.0.0.1",
    ).split(",")
    if p.strip()
]

SESSION_TTL = 600
AUTH_CODE_TTL = 300
BEARER_TTL = int(os.environ.get("MCP_BEARER_TTL", str(30 * 24 * 3600)))
REFRESH_LEAD = 60

K_SESSION = "mcp:session:"
K_CODE = "mcp:code:"
K_BEARER = "mcp:bearer:"

app = FastAPI(title="LiteLLM MCP OAuth Gateway (compound)")

client = httpx.AsyncClient(
    base_url=LITELLM_BASE,
    timeout=httpx.Timeout(30.0, connect=5.0),
)
mcp_client = httpx.AsyncClient(
    base_url=LITELLM_BASE,
    timeout=httpx.Timeout(None, connect=5.0),
    limits=httpx.Limits(max_keepalive_connections=20, keepalive_expiry=30.0),
    http2=False,
)
linear_client = httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0))
# Direct Linear MCP proxy. Bypasses LiteLLM because v1.85.0 cannot proxy
# streamable-http MCP servers (BerriAI/litellm#26700 — AnyIO cancel-scope
# bug in upstream MCP Python SDK). Streams SSE; no read timeout.
LINEAR_MCP_URL = os.environ.get("LINEAR_MCP_URL", "https://mcp.linear.app/mcp")
linear_mcp_client = httpx.AsyncClient(
    timeout=httpx.Timeout(None, connect=5.0),
    limits=httpx.Limits(max_keepalive_connections=20, keepalive_expiry=30.0),
    http2=False,
)
r = redis_async.from_url(REDIS_URL, decode_responses=True)

LANGFUSE_PUBLIC_KEY = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
LANGFUSE_SECRET_KEY = os.environ.get("LANGFUSE_SECRET_KEY", "")
LANGFUSE_HOST = os.environ.get("LANGFUSE_HOST", "")
LANGFUSE_ENABLED = bool(LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY and Langfuse is not None)

if LANGFUSE_ENABLED:
    langfuse = Langfuse(
        public_key=LANGFUSE_PUBLIC_KEY,
        secret_key=LANGFUSE_SECRET_KEY,
        host=LANGFUSE_HOST or None,
        flush_at=1,
        flush_interval=5,
    )
else:
    langfuse = None  # type: ignore[assignment]

CLIENTS: dict[str, dict[str, Any]] = {}

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-length", "content-encoding", "host",
}
TOKEN_NO_CACHE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _validate_redirect_uri(redirect_uri: str) -> None:
    try:
        parsed = urlparse(redirect_uri)
    except ValueError:
        raise HTTPException(400, "invalid_redirect_uri")
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "invalid_redirect_uri")
    if parsed.fragment:
        raise HTTPException(400, "invalid_redirect_uri")
    for prefix in ALLOWED_REDIRECT_PREFIXES:
        if redirect_uri.startswith(prefix):
            return
    raise HTTPException(400, f"redirect_uri not allowed: {redirect_uri}")


def _verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == challenge


def _bearer_from_header(auth_header: str) -> str:
    if not auth_header:
        return ""
    parts = auth_header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


@app.get("/health")
async def health() -> dict[str, bool]:
    try:
        await r.ping()
    except Exception as exc:
        raise HTTPException(503, f"redis unreachable: {exc}") from exc
    return {"ok": True, "linear": LINEAR_ENABLED}


@app.get("/.well-known/oauth-authorization-server")
async def auth_server_metadata() -> dict[str, Any]:
    return {
        "issuer": PUBLIC_BASE,
        "authorization_endpoint": f"{PUBLIC_BASE}/v1/mcp/oauth/authorize",
        "token_endpoint": f"{PUBLIC_BASE}/v1/mcp/oauth/token",
        "registration_endpoint": f"{PUBLIC_BASE}/register",
        "revocation_endpoint": f"{PUBLIC_BASE}/v1/mcp/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource{resource_path:path}")
async def protected_resource_metadata(resource_path: str = "") -> dict[str, Any]:
    resource = (
        f"{PUBLIC_BASE}{resource_path}" if resource_path else f"{PUBLIC_BASE}/mcp/"
    )
    return {
        "resource": resource,
        "authorization_servers": [PUBLIC_BASE],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    }


@app.post("/register")
async def register(request: Request) -> JSONResponse:
    body = await request.json()
    cid = "mcp_" + secrets.token_urlsafe(16)
    now = int(time.time())
    redirect_uris = body.get("redirect_uris", [])
    for uri in redirect_uris:
        _validate_redirect_uri(uri)
    CLIENTS[cid] = {
        "client_id": cid,
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", "MCP Client"),
        "issued_at": now,
    }
    return JSONResponse(
        {
            "client_id": cid,
            "client_id_issued_at": now,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "client_name": CLIENTS[cid]["client_name"],
        },
        status_code=201,
    )


_AUTHORIZE_HTML = """<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>Autorizar acesso MCP — Arara Tech</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#0f172a;min-height:100vh;display:flex;align-items:center;
       justify-content:center;padding:24px;margin:0}}
  .card{{background:#fff;border-radius:16px;padding:32px;width:460px;
        max-width:100%;box-shadow:0 25px 60px rgba(0,0,0,.35)}}
  .brand{{font-size:11px;letter-spacing:.12em;text-transform:uppercase;
         color:#94a3b8;font-weight:600;margin-bottom:14px}}
  h1{{font-size:20px;margin:0 0 6px;color:#0f172a}}
  p.sub{{font-size:14px;color:#64748b;margin:0 0 22px;line-height:1.5}}
  label{{display:block;font-size:13px;font-weight:600;color:#1e293b;margin-bottom:6px}}
  .input-wrap{{position:relative}}
  input[type=password],input[type=text]{{width:100%;padding:11px 78px 11px 13px;
        border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;outline:none;
        font-family:ui-monospace,SFMono-Regular,Menlo,monospace;box-sizing:border-box}}
  input:focus{{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.12)}}
  .reveal{{position:absolute;right:6px;top:50%;transform:translateY(-50%);
          background:transparent;border:0;color:#64748b;font-size:12px;
          cursor:pointer;padding:6px 10px;width:auto;margin:0;font-weight:500;
          border-radius:6px}}
  .reveal:hover{{color:#0f172a;background:#f1f5f9}}
  .hint{{display:block;margin-top:8px;font-size:12px;color:#94a3b8;
        font-family:ui-monospace,Menlo,monospace}}
  button.submit{{width:100%;padding:13px;background:#0f172a;color:#fff;border:0;
         border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;
         margin-top:20px}}
  button.submit:hover{{background:#1e293b}}
  button:focus-visible{{outline:3px solid #38bdf8;outline-offset:2px}}
  .meta{{background:#f8fafc;border-radius:10px;padding:12px 14px;font-size:12px;
        color:#475569;margin-bottom:18px;font-family:ui-monospace,Menlo,monospace;
        word-break:break-all}}
  .meta b{{color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,sans-serif}}
  .note{{font-size:12px;color:#94a3b8;margin-top:14px;line-height:1.5}}
  .err{{background:#fee2e2;color:#991b1b;border-radius:8px;padding:10px 12px;
       font-size:13px;margin-bottom:14px;font-weight:600}}
  .err::before{{content:"⚠ ";margin-right:2px}}
  .upstream{{margin-top:18px;padding:14px;background:#f1f5f9;border-radius:10px}}
  .upstream-title{{font-size:13px;font-weight:600;color:#0f172a;margin-bottom:8px}}
  .upstream-row{{display:flex;align-items:center;gap:10px;font-size:13px;color:#334155}}
  .upstream-row input[type=checkbox]{{width:18px;height:18px;margin:0;cursor:pointer}}
  .upstream-row label{{margin:0;font-weight:500;cursor:pointer}}
  .upstream-row small{{display:block;color:#64748b;font-weight:400;font-size:12px;margin-top:2px}}
  @media (max-width:480px){{
    .card{{padding:24px}}
    h1{{font-size:18px}}
  }}
</style></head><body><div class="card">
<div class="brand">Arara Tech · Grupo Guanabara</div>
<h1>Autorizar acesso MCP</h1>
<p class="sub">{client_name} está solicitando acesso ao seu gateway MCP do LiteLLM.
Cole sua chave virtual do LiteLLM e, opcionalmente, conecte sua conta Linear
para que ferramentas MCP do Linear operem como você.</p>
<div class="meta">
  <b>Cliente:</b> {client_name}<br>
  <b>Callback:</b> {redirect_uri}
</div>
{error_html}
<form method="POST" action="/v1/mcp/oauth/authorize">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="scope" value="{scope}">
  <label for="api_key">Chave virtual LiteLLM</label>
  <div class="input-wrap">
    <input id="api_key" name="api_key" type="password" autocomplete="off"
           placeholder="sk-..." required autofocus>
    <button type="button" class="reveal" aria-label="Mostrar chave">mostrar</button>
  </div>
  <small class="hint">Formato: sk-... (chave virtual ou master key)</small>
  {linear_block}
  <button type="submit" class="submit">Autorizar</button>
</form>
<p class="note">Chaves virtuais são emitidas no painel admin do LiteLLM, em Keys.
A master key também é aceita em laboratórios single-user.</p>
</div>
<script>
(function(){{
  var btn=document.querySelector('.reveal');
  var inp=document.getElementById('api_key');
  if(!btn||!inp)return;
  btn.addEventListener('click',function(){{
    var hidden=inp.type==='password';
    inp.type=hidden?'text':'password';
    btn.textContent=hidden?'ocultar':'mostrar';
    btn.setAttribute('aria-label',hidden?'Ocultar chave':'Mostrar chave');
  }});
}})();
</script>
</body></html>"""

_LINEAR_CHECKBOX = """
  <div class="upstream">
    <div class="upstream-title">Conectores upstream</div>
    <div class="upstream-row">
      <input type="checkbox" id="connect_linear" name="connect_linear" value="1" checked>
      <label for="connect_linear">Conectar Linear (OAuth pessoal)
        <small>Redireciona para login no Linear após autorizar.
        Desmarque se este cliente só vai usar MCPs sem auth (ex.: DeepWiki).</small>
      </label>
    </div>
  </div>
"""


def _render_authorize(
    client_id: str,
    client_name: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str,
    error: str = "",
) -> str:
    e = html.escape
    err_html = f'<div class="err">{e(error)}</div>' if error else ""
    linear_block = _LINEAR_CHECKBOX if LINEAR_ENABLED else ""
    return _AUTHORIZE_HTML.format(
        client_id=e(client_id),
        client_name=e(client_name),
        redirect_uri=e(redirect_uri),
        code_challenge=e(code_challenge),
        code_challenge_method=e(code_challenge_method),
        state=e(state),
        scope=e(scope),
        error_html=err_html,
        linear_block=linear_block,
    )


@app.get("/v1/mcp/oauth/authorize")
async def authorize_get(request: Request) -> HTMLResponse:
    qp = request.query_params
    client_id = qp.get("client_id", "")
    redirect_uri = qp.get("redirect_uri", "")
    response_type = qp.get("response_type", "code")
    code_challenge = qp.get("code_challenge", "")
    code_challenge_method = qp.get("code_challenge_method", "S256")
    state = qp.get("state", "")
    scope = qp.get("scope", "")

    if response_type != "code":
        raise HTTPException(400, "unsupported_response_type")
    if code_challenge_method != "S256":
        raise HTTPException(400, "code_challenge_required (S256)")
    if not code_challenge:
        raise HTTPException(400, "code_challenge_required")
    if not redirect_uri:
        raise HTTPException(400, "redirect_uri required")
    _validate_redirect_uri(redirect_uri)

    client = CLIENTS.get(client_id)
    if not client:
        client_name = "Cliente não registrado"
    else:
        client_name = client["client_name"]
        if client.get("redirect_uris") and redirect_uri not in client["redirect_uris"]:
            raise HTTPException(400, "redirect_uri not in registration")

    return HTMLResponse(
        _render_authorize(
            client_id, client_name, redirect_uri,
            code_challenge, code_challenge_method, state, scope,
        )
    )


async def _mint_auth_code(
    *,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str,
    scope: str,
    api_key: str,
    linear_access: str = "",
    linear_refresh: str = "",
    linear_exp: int = 0,
) -> Response:
    code = secrets.token_urlsafe(32)
    await r.setex(
        K_CODE + code,
        AUTH_CODE_TTL,
        json.dumps(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "scope": scope,
                "api_key": api_key,
                "linear_access": linear_access,
                "linear_refresh": linear_refresh,
                "linear_exp": linear_exp,
            }
        ),
    )
    params = {"code": code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return Response(
        status_code=302, headers={"Location": f"{redirect_uri}{sep}{urlencode(params)}"}
    )


@app.post("/v1/mcp/oauth/authorize")
async def authorize_post(
    client_id: str = Form(""),
    redirect_uri: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form("S256"),
    state: str = Form(""),
    scope: str = Form(""),
    api_key: str = Form(...),
    connect_linear: str = Form(""),
) -> Response:
    if code_challenge_method != "S256":
        raise HTTPException(400, "unsupported_code_challenge_method")
    _validate_redirect_uri(redirect_uri)
    if not api_key.strip():
        raise HTTPException(400, "api_key required")

    wants_linear = connect_linear == "1" and LINEAR_ENABLED
    if not wants_linear:
        return await _mint_auth_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            state=state,
            scope=scope,
            api_key=api_key.strip(),
        )

    session_id = secrets.token_urlsafe(32)
    await r.setex(
        K_SESSION + session_id,
        SESSION_TTL,
        json.dumps(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "state": state,
                "scope": scope,
                "api_key": api_key.strip(),
            }
        ),
    )
    linear_params = {
        "client_id": LINEAR_CLIENT_ID,
        "redirect_uri": LINEAR_REDIRECT_URI,
        "response_type": "code",
        "scope": LINEAR_SCOPES,
        "state": session_id,
        "actor": "user",
    }
    return Response(
        status_code=302,
        headers={"Location": f"{LINEAR_AUTHORIZE_URL}?{urlencode(linear_params)}"},
    )


@app.get("/v1/linear/callback")
async def linear_callback(
    code: str = "", state: str = "", error: str = "", error_description: str = ""
) -> Response:
    if error:
        raise HTTPException(400, f"linear_error: {error} {error_description}")
    if not state or not code:
        raise HTTPException(400, "missing code or state")

    raw = await r.get(K_SESSION + state)
    if not raw:
        raise HTTPException(400, "session_expired")
    await r.delete(K_SESSION + state)
    sess = json.loads(raw)

    tok_resp = await linear_client.post(
        LINEAR_TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": LINEAR_REDIRECT_URI,
            "client_id": LINEAR_CLIENT_ID,
            "client_secret": LINEAR_CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if tok_resp.status_code != 200:
        raise HTTPException(
            400, f"linear_token_exchange_failed: {tok_resp.status_code} {tok_resp.text}"
        )
    tok = tok_resp.json()

    return await _mint_auth_code(
        client_id=sess["client_id"],
        redirect_uri=sess["redirect_uri"],
        code_challenge=sess["code_challenge"],
        state=sess.get("state", ""),
        scope=sess.get("scope", ""),
        api_key=sess["api_key"],
        linear_access=tok["access_token"],
        linear_refresh=tok.get("refresh_token", ""),
        linear_exp=int(time.time()) + int(tok.get("expires_in", 3600)),
    )


@app.post("/v1/mcp/oauth/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(""),
    code_verifier: str = Form(...),
    client_id: str = Form(""),
) -> JSONResponse:
    if grant_type != "authorization_code":
        return JSONResponse(
            {"error": "unsupported_grant_type"}, 400, headers=TOKEN_NO_CACHE
        )

    raw = await r.get(K_CODE + code)
    if not raw:
        return JSONResponse({"error": "invalid_grant"}, 400, headers=TOKEN_NO_CACHE)
    await r.delete(K_CODE + code)
    rec = json.loads(raw)

    if redirect_uri and redirect_uri != rec["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant"}, 400, headers=TOKEN_NO_CACHE)
    if rec["client_id"] and client_id and client_id != rec["client_id"]:
        return JSONResponse({"error": "invalid_grant"}, 400, headers=TOKEN_NO_CACHE)
    if not _verify_pkce(code_verifier, rec["code_challenge"]):
        return JSONResponse({"error": "invalid_grant"}, 400, headers=TOKEN_NO_CACHE)

    bearer = "cmp_" + secrets.token_urlsafe(48)
    await r.setex(
        K_BEARER + bearer,
        BEARER_TTL,
        json.dumps(
            {
                "api_key": rec["api_key"],
                "linear_access": rec.get("linear_access", ""),
                "linear_refresh": rec.get("linear_refresh", ""),
                "linear_exp": int(rec.get("linear_exp", 0)),
            }
        ),
    )

    return JSONResponse(
        {
            "access_token": bearer,
            "token_type": "Bearer",
            "expires_in": BEARER_TTL,
            "scope": rec.get("scope", ""),
        },
        headers=TOKEN_NO_CACHE,
    )


@app.post("/v1/mcp/oauth/revoke")
async def revoke(token: str = Form(...)) -> Response:
    raw = await r.get(K_BEARER + token)
    if raw:
        bind = json.loads(raw)
        rt = bind.get("linear_refresh")
        if rt:
            try:
                await linear_client.post(
                    LINEAR_REVOKE_URL,
                    data={
                        "client_id": LINEAR_CLIENT_ID,
                        "client_secret": LINEAR_CLIENT_SECRET,
                        "token": rt,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except httpx.HTTPError:
                pass
        await r.delete(K_BEARER + token)
    return Response(status_code=200, headers=TOKEN_NO_CACHE)


MCP_PERM_TTL = int(os.environ.get("MCP_PERM_TTL", "30"))
K_PERM = "mcp:perm:"


async def _key_has_mcp(api_key: str, server: str) -> bool:
    cache_key = f"{K_PERM}{api_key}:{server}"
    cached = await r.get(cache_key)
    if cached is not None:
        return cached == "1"
    allowed = False
    try:
        resp = await client.get(
            "/v1/mcp/server",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        if resp.status_code == 200:
            data = resp.json()
            servers = data if isinstance(data, list) else data.get("data", [])
            names: set[str] = set()
            for s in servers:
                if not isinstance(s, dict):
                    continue
                for field in ("server_name", "alias", "name", "mcp_server_name"):
                    v = s.get(field)
                    if isinstance(v, str):
                        names.add(v)
            allowed = server in names
    except httpx.HTTPError:
        allowed = False
    await r.setex(cache_key, MCP_PERM_TTL, "1" if allowed else "0")
    return allowed


async def _refresh_linear(bearer: str, bind: dict[str, Any]) -> dict[str, Any]:
    rt = bind.get("linear_refresh")
    if not rt:
        return bind
    resp = await linear_client.post(
        LINEAR_TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": LINEAR_CLIENT_ID,
            "client_secret": LINEAR_CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if resp.status_code != 200:
        await r.delete(K_BEARER + bearer)
        raise HTTPException(401, f"linear_refresh_failed: {resp.status_code}")
    tok = resp.json()
    bind = {
        **bind,
        "linear_access": tok["access_token"],
        "linear_refresh": tok.get("refresh_token", rt),
        "linear_exp": int(time.time()) + int(tok.get("expires_in", 3600)),
    }
    await r.setex(K_BEARER + bearer, BEARER_TTL, json.dumps(bind))
    return bind


def _unauth_response(path: str) -> Response:
    resource_path = f"/mcp{path}" if path else "/mcp/"
    metadata_url = (
        f"{PUBLIC_BASE}/.well-known/oauth-protected-resource{resource_path}"
    )
    return Response(
        content=json.dumps(
            {"error": "unauthorized", "error_description": "OAuth required"}
        ),
        status_code=401,
        headers={
            "WWW-Authenticate": (
                f'Bearer realm="litellm-mcp", '
                f'resource_metadata="{metadata_url}"'
            ),
        },
        media_type="application/json",
    )


def _parse_mcp_request(body: bytes) -> dict[str, Any]:
    """Decode JSON-RPC body, extract method/tool_name/id. Safe on garbage."""
    if not body:
        return {}
    try:
        msg = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if isinstance(msg, list):
        msg = msg[0] if msg else {}
    if not isinstance(msg, dict):
        return {}
    out: dict[str, Any] = {
        "jsonrpc_id": msg.get("id"),
        "method": msg.get("method"),
        "params": msg.get("params"),
    }
    params = msg.get("params") or {}
    if msg.get("method") == "tools/call" and isinstance(params, dict):
        out["tool_name"] = params.get("name")
    return out


def _user_ids(bearer: str, api_key: str) -> tuple[str, str]:
    user_id = bearer[:16] if bearer else "anonymous"
    session_id = (
        hashlib.sha256(api_key.encode()).hexdigest()[:12] if api_key else ""
    )
    return user_id, session_id


def _server_from_path(path: str) -> str:
    p = path.lstrip("/")
    if p.startswith("linear"):
        return "linear_mcp"
    if p.startswith("deepwiki"):
        return "deepwiki_mcp"
    return p.split("/", 1)[0] or "mcp_root"


def _span_name(parsed: dict[str, Any]) -> str:
    method = parsed.get("method")
    tool = parsed.get("tool_name")
    if method == "tools/call" and tool:
        return f"mcp.tools/call.{tool}"
    if method:
        return f"mcp.{method}"
    return "mcp.request"


def _start_mcp_span(
    *,
    name: str,
    body: bytes,
    parsed: dict[str, Any],
    user_id: str,
    session_id: str,
    server: str,
    path: str,
    http_method: str,
):
    if not LANGFUSE_ENABLED or langfuse is None:
        return None
    span = langfuse.start_span(
        name=name,
        input={
            "body": body.decode(errors="replace"),
            "parsed": parsed,
        },
        metadata={
            "mcp.server": server,
            "mcp.method": parsed.get("method"),
            "mcp.tool_name": parsed.get("tool_name"),
            "mcp.jsonrpc_id": parsed.get("jsonrpc_id"),
            "path": path,
            "http_method": http_method,
        },
    )
    try:
        span.update_trace(
            user_id=user_id,
            session_id=session_id or None,
            tags=["mcp", server],
        )
    except Exception:
        pass
    return span


def _end_span_sync(span, *, status_code: int, output: str = "") -> None:
    if span is None:
        return
    try:
        span.update(output=output, metadata={"status_code": status_code})
    except Exception:
        pass
    try:
        span.end()
    except Exception:
        pass


def _end_span_error(span, exc: BaseException) -> None:
    if span is None:
        return
    try:
        span.update(level="ERROR", status_message=str(exc))
    except Exception:
        pass
    try:
        span.end()
    except Exception:
        pass


async def _tee_stream(upstream_iter, buf: bytearray):
    async for chunk in upstream_iter:
        buf.extend(chunk)
        yield chunk


def _make_stream_finalizer(
    upstream: httpx.Response, buf: bytearray, span, status_code: int
):
    async def _finalize() -> None:
        try:
            await upstream.aclose()
        finally:
            if span is not None:
                try:
                    span.update(
                        output=bytes(buf).decode(errors="replace"),
                        metadata={"status_code": status_code},
                    )
                except Exception:
                    pass
                try:
                    span.end()
                except Exception:
                    pass

    return _finalize


async def _send_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params,
    content: bytes,
) -> httpx.Response:
    req = client.build_request(
        method, url, headers=headers, params=params, content=content
    )
    try:
        return await client.send(req, stream=True)
    except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError):
        req2 = client.build_request(
            method, url, headers=headers, params=params, content=content
        )
        return await client.send(req2, stream=True)


async def _proxy_to_linear_direct(
    request: Request, bind: dict[str, Any], body: bytes, span
) -> Response:
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP and k.lower() != "authorization"
    }
    headers["authorization"] = f"Bearer {bind['linear_access']}"

    upstream = await _send_with_retry(
        linear_mcp_client,
        request.method,
        LINEAR_MCP_URL,
        headers=headers,
        params=request.query_params,
        content=body,
    )

    out_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP
    }
    buf = bytearray()
    return StreamingResponse(
        _tee_stream(upstream.aiter_raw(), buf),
        status_code=upstream.status_code,
        headers=out_headers,
        media_type=upstream.headers.get("content-type"),
        background=BackgroundTask(
            _make_stream_finalizer(upstream, buf, span, upstream.status_code)
        ),
    )


@app.api_route(
    "/mcp{path:path}",
    methods=["GET", "POST", "OPTIONS", "DELETE", "PUT", "PATCH", "HEAD"],
)
async def mcp_proxy(path: str, request: Request) -> Response:
    upstream_url = f"/mcp{path}" if path else "/mcp/"
    bearer = _bearer_from_header(request.headers.get("authorization", ""))
    body = await request.body()
    parsed = _parse_mcp_request(body)
    server = _server_from_path(path)

    bind: dict[str, Any] | None = None
    if bearer.startswith("cmp_"):
        raw = await r.get(K_BEARER + bearer)
        if raw:
            bind = json.loads(raw)
            if bind.get("linear_exp") and bind["linear_exp"] < time.time() + REFRESH_LEAD:
                bind = await _refresh_linear(bearer, bind)

    api_key = (bind or {}).get("api_key", "")
    user_id, session_id = _user_ids(bearer, api_key)
    span = _start_mcp_span(
        name=_span_name(parsed),
        body=body,
        parsed=parsed,
        user_id=user_id,
        session_id=session_id,
        server=server,
        path=path,
        http_method=request.method,
    )

    try:
        if not bind:
            resp = _unauth_response(path)
            _end_span_sync(span, status_code=401, output="unauthorized")
            return resp

        is_linear_path = path.startswith("/linear")
        if is_linear_path:
            if not bind.get("linear_access"):
                resp = _unauth_response(path)
                _end_span_sync(span, status_code=401, output="linear_unauth")
                return resp
            if not await _key_has_mcp(bind["api_key"], "linear_mcp"):
                resp = Response(
                    content=json.dumps(
                        {
                            "error": "forbidden",
                            "error_description": "linear_mcp not permitted for this key",
                        }
                    ),
                    status_code=403,
                    media_type="application/json",
                )
                _end_span_sync(span, status_code=403, output="forbidden")
                return resp
            return await _proxy_to_linear_direct(request, bind, body, span)

        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in HOP_BY_HOP and k.lower() != "authorization"
        }
        headers["x-litellm-api-key"] = f"Bearer {bind['api_key']}"
        if bind.get("linear_access"):
            headers["x-mcp-linear-authorization"] = f"Bearer {bind['linear_access']}"
            headers["x-mcp-linear_mcp-authorization"] = f"Bearer {bind['linear_access']}"

        upstream = await _send_with_retry(
            mcp_client,
            request.method,
            upstream_url,
            headers=headers,
            params=request.query_params,
            content=body,
        )

        out_headers = {
            k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP
        }
        buf = bytearray()
        return StreamingResponse(
            _tee_stream(upstream.aiter_raw(), buf),
            status_code=upstream.status_code,
            headers=out_headers,
            media_type=upstream.headers.get("content-type"),
            background=BackgroundTask(
                _make_stream_finalizer(upstream, buf, span, upstream.status_code)
            ),
        )
    except Exception as exc:
        _end_span_error(span, exc)
        raise


@app.on_event("shutdown")
async def _flush_langfuse() -> None:
    if LANGFUSE_ENABLED and langfuse is not None:
        try:
            langfuse.flush()
        except Exception:
            pass
