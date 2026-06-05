# LiteLLM-native MCP OAuth doesn't work with Claude Desktop (yet) — register MCPs on the gateway, keep LiteLLM for RBAC

> **TL;DR.** As of **LiteLLM v1.87.0**, you **cannot** connect an OAuth-protected MCP (e.g. Linear) to **Claude Desktop** through LiteLLM's native MCP OAuth. The discovery + authorize flow LiteLLM implements is incompatible with Claude's `claude.ai` callback (verified below). The only reliable way to consume MCPs from Claude **right now** is to register the upstream MCP connection (and any per-user OAuth) on the **`mcp-gateway`**, and use **LiteLLM purely as the RBAC/permission source** (not as the MCP data-plane or OAuth server). No-auth and static-token MCPs (deepwiki, Slack-with-`xoxb`) can additionally go straight through LiteLLM's proxy because the transport itself works on v1.87.
>
> This reverses, for **OAuth MCPs only**, the "all MCP connections live in LiteLLM" goal of the slim refactor. Everything else (APISIX edge, OpenFGA authz, no-auth MCPs) is unaffected.

---

## 1. The two models

| | Model A — "all in LiteLLM" (slim shim) | Model B — "gateway owns MCPs, LiteLLM = RBAC" (works today) |
|---|---|---|
| Upstream MCP connection | LiteLLM `mcp_servers` | **Gateway** registers + connects |
| Per-user upstream OAuth (Linear) | LiteLLM `auth_type: oauth2` | **Gateway** is the OAuth AS + upstream OAuth client |
| Client (Claude) OAuth AS | LiteLLM `.well-known` / `/…/authorize` | **Gateway** `.well-known` / `cmp_*` |
| LiteLLM role | data-plane + OAuth + RBAC | **RBAC only** (`object_permission` / `/v1/mcp/server`) |
| Claude Desktop + OAuth MCP | ❌ broken (this doc) | ✅ works (gateway speaks Claude's dialect) |
| Claude Desktop + no-auth / static-token MCP | ✅ works | ✅ works |

Model A is the right *destination*. Model B is what ships **until LiteLLM fixes native MCP OAuth for standard remote clients**.

---

## 2. What actually works on v1.87 (so we know the transport is fine)

The v1.85 streamable-http proxy bug (**BerriAI/litellm#26700**, AnyIO cancel-scope) is **gone in v1.87**. Verified against the live stack:

```bash
# deepwiki (auth_type: none) proxied by LiteLLM over streamable-http
POST /mcp/deepwiki/  (Authorization: Bearer <litellm-key>)  initialize  -> 200 SSE, full serverInfo
POST /mcp/deepwiki/                                          tools/list  -> 3 tools
# no cancel-scope / TaskGroup error in litellm logs
```

So **no-auth and static-token MCPs work through LiteLLM**. The problem is **exclusively** the OAuth handshake LiteLLM exposes to an external client.

---

## 3. Why Linear OAuth via LiteLLM fails with Claude Desktop (evidence)

Claude Desktop's remote connector authenticates with the callback **`https://claude.ai/api/mcp/auth_callback`** (confirmed in LiteLLM access logs). Four LiteLLM v1.87 behaviors break that flow:

### 3.1 `/mcp/<server>` returns **500, not 401** on an unauthenticated request

```bash
POST /mcp/linear/   (no Authorization)   -> HTTP 500  {"error":"MCP request failed"}
# litellm traceback: "Malformed API Key passed in. Ensure Key has `Bearer ` prefix." -> ProxyException
```

The MCP authorization spec (and Claude) rely on a **`401` + `WWW-Authenticate: … resource_metadata="…"`** to start discovery. LiteLLM raises a 500 instead, so the standard discovery entry point is broken. (Related: **LiteLLM #17272** — "OAuth discovery returns non-standard MCP URL pattern breaking standard MCP clients".)

### 3.2 Root AS metadata advertises the wrong host + a non-standard endpoint

```bash
GET /.well-known/oauth-authorization-server          # through the public https tunnel
-> { "issuer": "http://localhost:4000",              # ❌ internal host, not the public origin
     "authorization_endpoint": ".../linear_mcp/authorize", … }
```

The **per-server** doc is correct (`.../linear/authorize`, public host), but the **root** doc Claude tends to fall back to is wrong (internal `localhost` issuer; cf. **LiteLLM #15719**).

### 3.3 The aggregated authorize endpoint **requires a loopback redirect** for native clients

Claude Desktop lands on `/v1/mcp/oauth/authorize`. With its `claude.ai` callback:

```bash
GET /v1/mcp/oauth/authorize?client_id=linear_mcp&redirect_uri=https://claude.ai/api/mcp/auth_callback&…
-> HTTP 400
   {"error":"invalid_request",
    "error_description":"redirect_uri must use a loopback host (localhost or 127.0.0.0/8).",
    "hint":"Native MCP clients should register a callback on http://127.0.0.1:<port>/..."}
```

This **400 persists even with `MCP_TRUSTED_REDIRECT_ORIGINS=claude.ai,claude.com`** — the allowlist does not apply to the native-client loopback rule on the aggregated endpoint.

### 3.4 The one endpoint that accepts `claude.ai` is never reached

The **per-server** `/linear/authorize` *does* accept the `claude.ai` redirect once the origin is allowlisted:

```bash
GET /linear/authorize?client_id=linear&redirect_uri=https://claude.ai/api/mcp/auth_callback&…
-> HTTP 307  Location: https://linear.app/oauth/authorize?client_id=…&redirect_uri=https://<host>/callback&…
```

…but Claude never gets steered there, because discovery (§3.1/§3.2) sends it to the aggregated/root AS (§3.3). **Result: the flow dead-ends at the loopback 400.**

> **Claude Code (CLI) is different:** it uses a **loopback** redirect (`http://localhost:<port>`, cf. anthropics/claude-code#42765), which passes §3.3. It may connect where Desktop can't — but the §3.1 discovery 500 can still bite. This doc is about **Claude Desktop**.

### Summary

| Requirement for Claude Desktop OAuth | LiteLLM v1.87 native | mcp-gateway |
|---|---|---|
| `401` + `WWW-Authenticate` on the protected resource | ❌ 500 (§3.1) | ✅ |
| AS metadata with the **public** issuer/host | ❌ root says `localhost` (§3.2) | ✅ (built from `X-Forwarded-*`) |
| Accept a **non-loopback** `claude.ai` redirect | ❌ aggregated endpoint 400s (§3.3) | ✅ (`ALLOWED_REDIRECT_PREFIXES` incl. `claude.ai`) |
| Standard `/mcp/<server>` discovery path | ❌ non-standard (#17272) | ✅ |

---

## 4. The working pattern (Model B)

```
Claude Desktop  ──OAuth (claude.ai callback)──▶  mcp-gateway        ──RBAC check──▶  LiteLLM
   Bearer cmp_*                                  (OAuth 2.1 AS;                     (object_permission
                                                  registers MCP upstreams;          / /v1/mcp/server
                                                  does upstream OAuth, e.g.          — OR OpenFGA in
                                                  Linear actor=user; mints cmp_*)    this stack)
                                                       │
                                                       ▼ executes the tool call
                                              upstream MCP (mcp.linear.app, …)
```

- **Gateway = the only OAuth Authorization Server Claude talks to.** It accepts `claude.ai`/`claude.com` redirects, returns a proper `401`, builds metadata from the public host (`X-Forwarded-Host/Proto`), runs DCR + PKCE S256, and mints the opaque `cmp_*`.
- **Gateway registers the MCP upstream + owns per-user OAuth.** For Linear: the gateway is the OAuth client to `linear.app` (`actor=user`), stores the token in the `cmp_*` binding, and injects it on each call. (This is the gateway-side Linear OAuth that the slim refactor removed — it must be restored to serve Linear on Claude Desktop.)
- **LiteLLM = RBAC only.** It is *not* in the OAuth path and *not* the AS. The gateway consults it purely for the allow-list decision (`GET /v1/mcp/server` / `object_permission.mcp_servers`) and echoes the result (`{tools: []}` when out of scope). In this stack that authz decision is currently served by **OpenFGA** (`user → team → mcp`); LiteLLM `object_permission` is the alternative. Either way LiteLLM does **no** MCP OAuth.

### Where each MCP class lives

| MCP class | Example | Register on | Claude reaches it via | Notes |
|---|---|---|---|---|
| **Per-user OAuth** | Linear | **gateway** (upstream OAuth) | gateway `cmp_*` | LiteLLM-native OAuth can't serve Claude Desktop (§3) |
| **Static token** | Slack (`xoxb-`) | gateway **or** LiteLLM (static header) | gateway `cmp_*` | No client-side upstream OAuth → no wall |
| **No auth** | deepwiki | gateway **or** LiteLLM | gateway `cmp_*` | Transport verified on v1.87 (§2) |

For static-token/no-auth MCPs the simplest is: register in LiteLLM with the static header, and let Claude reach them through the **gateway** `cmp_*` flow (LiteLLM injects the token). The gateway flow is required regardless because Claude must OAuth against *something* that accepts `claude.ai`, and that something is the gateway.

---

## 5. When Model A becomes viable

Move OAuth MCPs back into LiteLLM once a LiteLLM release fixes the native MCP OAuth surface for standard remote clients — concretely, when:

1. `/mcp/<server>` returns **`401` + `WWW-Authenticate` with `resource_metadata`** (not 500) — **#17272**.
2. The **root** AS metadata emits the **public** issuer/host behind a TLS-terminating proxy — **#15719**.
3. A **trusted-origin allowlist applies to the authorize endpoint Claude actually uses**, so a `claude.ai` (non-loopback) redirect is accepted — not just loopback for native clients.

Until all three hold, **keep OAuth MCPs on the gateway**.

---

## 6. References

**LiteLLM issues**
- #26700 — streamable-http MCP proxy cancel-scope (v1.85; not triggered on v1.87): https://github.com/BerriAI/litellm/issues/26700
- #17272 — OAuth discovery non-standard URL pattern breaks standard MCP clients: https://github.com/BerriAI/litellm/issues/17272
- #15719 — MCP OAuth endpoints return http URLs behind an https proxy: https://github.com/BerriAI/litellm/issues/15719
- Docs — MCP OAuth: https://docs.litellm.ai/docs/mcp_oauth

**Claude**
- claude-code#42765 — OAuth `redirect_uri` uses `localhost` vs `127.0.0.1` (RFC 8252 §7.3): https://github.com/anthropics/claude-code/issues/42765
- MCP connector: https://platform.claude.com/docs/en/agents-and-tools/mcp-connector

**Internal**
- `mcp-gateway/README.md` — the OAuth AS + `cmp_*` shim
- `docs/rbac-mcp.md` — RBAC by Team/User/Virtual Key (the LiteLLM permission source)
- `docs/apisix-mcp-gateway.md` — APISIX edge × gateway BFF × LiteLLM layering

---

> **Appendix — verification environment.** LiteLLM `v1.87.0`; upstreams `mcp.linear.app/mcp` (OAuth) and `mcp.deepwiki.com/mcp` (no-auth); exposed via a public HTTPS tunnel to LiteLLM `:4000`; `MCP_TRUSTED_REDIRECT_ORIGINS=claude.ai,claude.com` set. All HTTP codes in §2–§3 were captured against this live stack on 2026-06-03.
