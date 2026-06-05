"""Slim MCP OAuth 2.1 shim in front of LiteLLM.

Two jobs only:

  1. AUTHENTICATE the AI client. The shim is an OAuth 2.1 Authorization Server
     (DCR, PKCE S256, .well-known) that mints an opaque bearer `cmp_*` bound to
     a single LiteLLM virtual key. Claude Desktop sees ONE issuer (this shim)
     and ONE access_token.
  2. AUTHORIZE which MCP servers the caller may use. Decision comes from OpenFGA
     (ReBAC): `user:<email> can_access mcp:<server>`, where <email> is resolved
     from the virtual key via LiteLLM /key/info → /user/info.

The shim holds NO direct MCP connections and NO upstream OAuth. Every /mcp/*
request is forwarded to LiteLLM with `x-litellm-api-key: Bearer <virtual_key>`.
All MCP connections and all upstream MCP auth (incl. OAuth, auth_type: oauth2)
live in LiteLLM config.

Authorize flow:
  1. /v1/mcp/oauth/authorize (GET)  → consent form (paste virtual key)
  2. /v1/mcp/oauth/authorize (POST) → mint auth code, 302 back to client
  3. /v1/mcp/oauth/token (POST)     → PKCE verify, mint opaque bearer `cmp_*`

Storage:
  - Redis-backed (codes, bearers). Survives shim restart.

Token lifecycle:
  - Bearer TTL is BEARER_TTL (default 30 days). The binding holds only the
    virtual key + resolved user email; no upstream tokens to refresh.
"""

from __future__ import annotations

import asyncio
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
# Admin key for resolving a virtual key -> owning user email via /key/info.
# Effectively REQUIRED: the resolved email is the OpenFGA authz subject. Without
# it, _resolve_user_email returns "" and every Check fails closed (all MCPs hidden).
LITELLM_MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "")

# OpenFGA (authorization). The shim resolves the store by name at startup unless
# OPENFGA_STORE_ID is pinned via env; OPENFGA_MODEL_ID falls back to the latest.
OPENFGA_API_URL = os.environ.get("OPENFGA_API_URL", "").rstrip("/")
OPENFGA_STORE_NAME = os.environ.get("OPENFGA_STORE_NAME", "llmops")
OPENFGA_STORE_ID = os.environ.get("OPENFGA_STORE_ID", "")
OPENFGA_MODEL_ID = os.environ.get("OPENFGA_MODEL_ID", "")
OPENFGA_ENABLED = bool(OPENFGA_API_URL)

ALLOWED_REDIRECT_PREFIXES = [
    p.strip()
    for p in os.environ.get(
        "ALLOWED_REDIRECT_PREFIXES",
        "https://claude.ai/,https://claude.com/,http://localhost,http://127.0.0.1",
    ).split(",")
    if p.strip()
]

AUTH_CODE_TTL = 300
BEARER_TTL = int(os.environ.get("MCP_BEARER_TTL", str(30 * 24 * 3600)))

K_CODE = "mcp:code:"
K_BEARER = "mcp:bearer:"
K_EMAIL = "mcp:email:"

EMAIL_TTL = int(os.environ.get("MCP_EMAIL_TTL", "3600"))

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
# OpenFGA Check client (authorization). Plain httpx — one POST /check per call,
# no SDK needed to stay slim.
fga_client = httpx.AsyncClient(
    base_url=OPENFGA_API_URL or "http://openfga:8080",
    timeout=httpx.Timeout(5.0, connect=2.0),
)
r = redis_async.from_url(REDIS_URL, decode_responses=True)

LANGFUSE_PUBLIC_KEY = os.environ.get("LANGFUSE_PUBLIC_KEY", "")
LANGFUSE_SECRET_KEY = os.environ.get("LANGFUSE_SECRET_KEY", "")
LANGFUSE_HOST = os.environ.get("LANGFUSE_HOST", "")
LANGFUSE_ENABLED = bool(
    LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY and Langfuse is not None
)

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
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "host",
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
    return {"ok": True, "openfga": OPENFGA_ENABLED and bool(OPENFGA_STORE_ID)}


@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/oauth-authorization-server{resource_path:path}")
async def auth_server_metadata(resource_path: str = "") -> dict[str, Any]:
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
  @media (max-width:480px){{
    .card{{padding:24px}}
    h1{{font-size:18px}}
  }}
</style></head><body><div class="card">
<div class="brand">Arara Tech · Grupo Guanabara</div>
<h1>Autorizar acesso MCP</h1>
<p class="sub">{client_name} está solicitando acesso ao gateway MCP do LiteLLM
para <b>{mcp_label}</b>. Cole sua chave virtual do LiteLLM para autorizar.</p>
<div class="meta">
  <b>Cliente:</b> {client_name}<br>
  <b>MCP:</b> {mcp_label}<br>
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
  <input type="hidden" name="resource" value="{resource}">
  <label for="api_key">Chave virtual LiteLLM</label>
  <div class="input-wrap">
    <input id="api_key" name="api_key" type="password" autocomplete="off"
           placeholder="sk-..." required autofocus>
    <button type="button" class="reveal" aria-label="Mostrar chave">mostrar</button>
  </div>
  <small class="hint">Formato: sk-... (chave virtual ou master key)</small>
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


def _render_authorize(
    client_id: str,
    client_name: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str,
    resource: str,
    mcp_label: str,
    error: str = "",
) -> str:
    e = html.escape
    err_html = f'<div class="err">{e(error)}</div>' if error else ""
    return _AUTHORIZE_HTML.format(
        client_id=e(client_id),
        client_name=e(client_name),
        redirect_uri=e(redirect_uri),
        code_challenge=e(code_challenge),
        code_challenge_method=e(code_challenge_method),
        state=e(state),
        scope=e(scope),
        resource=e(resource),
        mcp_label=e(mcp_label),
        error_html=err_html,
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
    resource = qp.get("resource", "")

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

    alias = _alias_from_resource(resource)
    mcp_label = alias or "MCP genérico"

    return HTMLResponse(
        _render_authorize(
            client_id,
            client_name,
            redirect_uri,
            code_challenge,
            code_challenge_method,
            state,
            scope,
            resource,
            mcp_label,
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
    resource: str = Form(""),
) -> Response:
    if code_challenge_method != "S256":
        raise HTTPException(400, "unsupported_code_challenge_method")
    _validate_redirect_uri(redirect_uri)
    if not api_key.strip():
        raise HTTPException(400, "api_key required")

    # No upstream OAuth hop: the shim binds only the virtual key. Per-MCP
    # upstream auth (incl. OAuth) is handled by LiteLLM. The `resource` form
    # field is still posted by the consent page but is unused here.
    return await _mint_auth_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        state=state,
        scope=scope,
        api_key=api_key.strip(),
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
    user_email = await _resolve_user_email(rec["api_key"])
    await r.setex(
        K_BEARER + bearer,
        BEARER_TTL,
        json.dumps(
            {
                "api_key": rec["api_key"],
                "user_email": user_email,
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
    await r.delete(K_BEARER + token)
    return Response(status_code=200, headers=TOKEN_NO_CACHE)


MCP_PERM_TTL = int(os.environ.get("MCP_PERM_TTL", "10"))
K_PERM = "mcp:perm:"


async def _resolve_openfga() -> None:
    """Resolve the OpenFGA store/model ids at startup.

    If OPENFGA_STORE_ID is pinned via env, keep it; otherwise look the store up
    by OPENFGA_STORE_NAME. Pick the latest authorization model when
    OPENFGA_MODEL_ID is empty. Retries until OpenFGA is reachable (the bootstrap
    one-shot may still be importing the store on first boot).
    """
    global OPENFGA_STORE_ID, OPENFGA_MODEL_ID
    if not OPENFGA_ENABLED:
        return
    for _ in range(30):
        try:
            if not OPENFGA_STORE_ID:
                resp = await fga_client.get("/stores")
                if resp.status_code == 200:
                    for s in resp.json().get("stores", []):
                        if s.get("name") == OPENFGA_STORE_NAME:
                            OPENFGA_STORE_ID = s.get("id", "")
                            break
            if OPENFGA_STORE_ID and not OPENFGA_MODEL_ID:
                mresp = await fga_client.get(
                    f"/stores/{OPENFGA_STORE_ID}/authorization-models",
                    params={"page_size": 1},
                )
                if mresp.status_code == 200:
                    models = mresp.json().get("authorization_models", [])
                    if models:
                        OPENFGA_MODEL_ID = models[0].get("id", "")
            if OPENFGA_STORE_ID:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(2)


async def _can_access_mcp(user_email: str, server: str) -> bool:
    """Authorize via OpenFGA: user:<email> can_access mcp:<server>.

    Fails closed on any error / missing identity / unresolved store. Cached in
    Redis (MCP_PERM_TTL) keyed on the resolved email, so revoking a team→mcp
    tuple takes effect within one cache window.
    """
    if not user_email or not server:
        return False
    if not OPENFGA_ENABLED or not OPENFGA_STORE_ID:
        return False
    cache_key = f"{K_PERM}{user_email}:{server}"
    cached = await r.get(cache_key)
    if cached is not None:
        return cached == "1"
    allowed = False
    body: dict[str, Any] = {
        "tuple_key": {
            "user": f"user:{user_email}",
            "relation": "can_access",
            "object": f"mcp:{server}",
        },
    }
    if OPENFGA_MODEL_ID:
        body["authorization_model_id"] = OPENFGA_MODEL_ID
    try:
        resp = await fga_client.post(f"/stores/{OPENFGA_STORE_ID}/check", json=body)
        if resp.status_code == 200:
            allowed = bool(resp.json().get("allowed", False))
    except httpx.HTTPError:
        allowed = False
    await r.setex(cache_key, MCP_PERM_TTL, "1" if allowed else "0")
    return allowed


def _emailish(v: Any) -> str:
    return v if isinstance(v, str) and "@" in v else ""


async def _resolve_user_email(api_key: str) -> str:
    """Resolve a LiteLLM virtual key to its owning user email.

    Two hops with the admin master key: `/key/info` yields the key's `user_id`
    (an opaque UUID in this stack), then `/user/info` maps that UUID to
    `user_email`. Falls back to the UUID when no email exists. Cached in Redis
    (empty/uuid result cached too) to avoid hammering LiteLLM. Returns "" when
    unknown/unreachable so callers fall back to a hashed key id.
    """
    if not api_key:
        return ""
    cache_key = K_EMAIL + hashlib.sha256(api_key.encode()).hexdigest()[:16]
    cached = await r.get(cache_key)
    if cached is not None:
        return cached
    email = ""
    if LITELLM_MASTER_KEY:
        hdr = {"Authorization": f"Bearer {LITELLM_MASTER_KEY}"}
        try:
            user_id = ""
            resp = await client.get("/key/info", params={"key": api_key}, headers=hdr)
            if resp.status_code == 200:
                data = resp.json()
                info = data.get("info", data) if isinstance(data, dict) else {}
                if isinstance(info, dict):
                    email = _emailish(info.get("user_email")) or _emailish(
                        info.get("user_id")
                    )
                    user_id = info.get("user_id") or ""
            # key's user_id is a UUID -> resolve the email from /user/info
            if not email and user_id:
                uresp = await client.get(
                    "/user/info", params={"user_id": user_id}, headers=hdr
                )
                if uresp.status_code == 200:
                    udata = uresp.json()
                    uinfo = (
                        udata.get("user_info", udata) if isinstance(udata, dict) else {}
                    )
                    if isinstance(uinfo, dict):
                        email = _emailish(uinfo.get("user_email"))
                # last resort: keep the UUID as a stable identity
                email = email or user_id
        except httpx.HTTPError:
            email = ""
    await r.setex(cache_key, EMAIL_TTL, email)
    return email


def _restricted_mcp_response(parsed: dict[str, Any], server: str) -> Response:
    """Synthetic MCP responses for a server this key may not use.

    Lets the transport handshake (initialize / notifications / ping) succeed so
    the connector shows as connected, while hiding tools (tools/list -> empty)
    and blocking execution (tools/call -> JSON-RPC error). Granting the MCP to
    the team makes a later refresh proxy the real tools through.
    """
    method = parsed.get("method")
    jid = parsed.get("jsonrpc_id")

    if not method:  # GET SSE open / malformed body
        return Response(status_code=202)
    if method.startswith("notifications/"):
        return Response(status_code=202)
    if method == "initialize":
        params = parsed.get("params") or {}
        proto = params.get("protocolVersion") or "2025-06-18"
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": jid,
                "result": {
                    "protocolVersion": proto,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": f"{server} (restricted)",
                        "version": "0.0.0",
                    },
                },
            },
            headers={"Mcp-Session-Id": secrets.token_urlsafe(16)},
        )
    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": jid, "result": {"tools": []}})
    if method == "ping":
        return JSONResponse({"jsonrpc": "2.0", "id": jid, "result": {}})
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": jid,
            "error": {
                "code": -32000,
                "message": f"{server} not permitted for this key",
            },
        }
    )


def _unauth_response(path: str) -> Response:
    resource_path = f"/mcp{path}" if path else "/mcp/"
    metadata_url = f"{PUBLIC_BASE}/.well-known/oauth-protected-resource{resource_path}"
    return Response(
        content=json.dumps(
            {"error": "unauthorized", "error_description": "OAuth required"}
        ),
        status_code=401,
        headers={
            "WWW-Authenticate": (
                f'Bearer realm="litellm-mcp", resource_metadata="{metadata_url}"'
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


def _user_id(email: str, api_key: str, bearer: str) -> str:
    """Langfuse user_id. Email when resolvable (the filterable identity);
    degrades to a stable hashed key id, then the bearer prefix."""
    if email:
        return email
    if api_key:
        return "key:" + hashlib.sha256(api_key.encode()).hexdigest()[:12]
    return bearer[:16] if bearer else "anonymous"


def _parse_traceparent(value: str) -> tuple[str | None, str | None]:
    """Parse W3C traceparent `00-<32hex>-<16hex>-<flags>` -> (trace_id, span_id)."""
    if not value:
        return None, None
    parts = value.strip().split("-")
    if len(parts) != 4:
        return None, None
    _, trace_id, span_id, _flags = parts
    if len(trace_id) != 32 or len(span_id) != 16:
        return None, None
    if trace_id == "0" * 32 or span_id == "0" * 16:
        return None, None
    try:
        int(trace_id, 16)
        int(span_id, 16)
    except ValueError:
        return None, None
    return trace_id, span_id


def _parse_baggage(value: str) -> dict[str, str]:
    """Parse W3C baggage `k1=v1,k2=v2` -> dict. Ignores malformed members."""
    out: dict[str, str] = {}
    if not value:
        return out
    for member in value.split(","):
        key, sep, val = member.partition("=")
        key = key.strip()
        if key and sep:
            out[key] = val.strip()
    return out


_SESSION_BAGGAGE_KEYS = (
    "session.id",
    "sessionId",
    "session_id",
    "conversation_id",
    "conversation.id",
)


def _session_id(headers, bearer: str) -> str:
    """Best-effort Claude-session id, in precedence order:

      1. Mcp-Session-Id request header (spec-compliant / non-Claude clients)
      2. session/conversation key in W3C baggage
      3. W3C traceparent trace-id (per Claude trace)
      4. hash of the bearer (per OAuth connection)

    Claude Desktop/Code echo none of the first three reliably
    (claude-code#41836), so the per-connection hash is the practical floor.
    """
    sid = headers.get("mcp-session-id", "")
    if sid:
        return sid
    bag = _parse_baggage(headers.get("baggage", ""))
    for key in _SESSION_BAGGAGE_KEYS:
        if bag.get(key):
            return bag[key]
    trace_id, _ = _parse_traceparent(headers.get("traceparent", ""))
    if trace_id:
        return trace_id
    return hashlib.sha256(bearer.encode()).hexdigest()[:16] if bearer else ""


def _client_label(user_agent: str) -> str:
    ua = (user_agent or "").strip()
    if ua.startswith("Claude"):
        return "claude"
    return ua[:40] if ua else "unknown"


def _server_from_path(path: str) -> str:
    p = path.lstrip("/")
    if p.startswith("linear"):
        return "linear_mcp"
    if p.startswith("deepwiki") or p.startswith("deep_wiki"):
        return "deepwiki_mcp"
    return p.split("/", 1)[0] or "mcp_root"


def _alias_from_resource(resource: str) -> str:
    """Pull the last path segment of resource=https://host/mcp/<alias>.

    Empty/malformed/unknown resources fall through to no-auth at the caller.
    """
    if not resource:
        return ""
    try:
        path = urlparse(resource).path
    except ValueError:
        return ""
    return path.rstrip("/").rsplit("/", 1)[-1] if path else ""


def _span_name(parsed: dict[str, Any], server: str) -> str:
    method = parsed.get("method")
    tool = parsed.get("tool_name")
    if method == "tools/call" and tool:
        return f"{server}/{tool}"
    if method:
        return f"{server}/{method}"
    return f"{server}/request"


def _start_mcp_span(
    *,
    name: str,
    body: bytes,
    parsed: dict[str, Any],
    headers,
    bearer: str,
    email: str,
    api_key: str,
    server: str,
    path: str,
    http_method: str,
):
    if not LANGFUSE_ENABLED or langfuse is None:
        return None
    user_agent = headers.get("user-agent", "")
    traceparent = headers.get("traceparent", "")
    baggage = headers.get("baggage", "")
    # Distributed-trace linking: nest the gateway span under the client's W3C
    # trace so every span Claude emits for one trace renders together.
    trace_id, parent_span_id = _parse_traceparent(traceparent)
    trace_context = (
        {"trace_id": trace_id, "parent_span_id": parent_span_id} if trace_id else None
    )
    span = langfuse.start_span(
        name=name,
        trace_context=trace_context,
        input={
            "body": body.decode(errors="replace"),
            "parsed": parsed,
        },
        metadata={
            "mcp.server": server,
            "mcp.method": parsed.get("method"),
            "mcp.tool_name": parsed.get("tool_name"),
            "mcp.jsonrpc_id": parsed.get("jsonrpc_id"),
            "mcp.protocol_version": headers.get("mcp-protocol-version"),
            "client.user_agent": user_agent,
            "w3c.traceparent": traceparent,
            "w3c.baggage": baggage,
            "path": path,
            "http_method": http_method,
        },
    )
    try:
        span.update_trace(
            user_id=_user_id(email, api_key, bearer),
            session_id=_session_id(headers, bearer) or None,
            tags=["mcp", server, _client_label(user_agent)],
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

    api_key = (bind or {}).get("api_key", "")
    email = (bind or {}).get("user_email", "")
    if api_key and "@" not in email:
        # Missing, or a UUID baked into an older binding -> resolve (cached).
        email = await _resolve_user_email(api_key)
    span = _start_mcp_span(
        name=_span_name(parsed, server),
        body=body,
        parsed=parsed,
        headers=request.headers,
        bearer=bearer,
        email=email,
        api_key=api_key,
        server=server,
        path=path,
        http_method=request.method,
    )

    try:
        if not bind:
            resp = _unauth_response(path)
            _end_span_sync(span, status_code=401, output="unauthorized")
            return resp

        # Per-server authz gate (OpenFGA: user:<email> can_access mcp:<server>).
        # Not in scope -> do NOT hard-fail: connector connects, but tools stay
        # hidden until the team is granted the MCP.
        if not await _can_access_mcp(email, server):
            resp = _restricted_mcp_response(parsed, server)
            _end_span_sync(span, status_code=200, output="restricted")
            return resp

        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in HOP_BY_HOP and k.lower() != "authorization"
        }
        headers["x-litellm-api-key"] = f"Bearer {bind['api_key']}"

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
        # Signal proxies (APISIX/nginx) to stream SSE without buffering.
        out_headers["X-Accel-Buffering"] = "no"
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


@app.on_event("startup")
async def _bootstrap_openfga() -> None:
    # Resolve store/model in the background so the app comes up even while the
    # OpenFGA bootstrap one-shot is still importing the store. Authz fails
    # closed (restricted) until the store id is known.
    asyncio.create_task(_resolve_openfga())


@app.on_event("shutdown")
async def _flush_langfuse() -> None:
    if LANGFUSE_ENABLED and langfuse is not None:
        try:
            langfuse.flush()
        except Exception:
            pass
