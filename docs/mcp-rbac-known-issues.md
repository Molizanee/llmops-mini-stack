# Known issues — LiteLLM + mcp-gateway + APISIX for MCP RBAC

Single reference for every sharp edge found wiring this stack for MCP access control. Each entry:
**symptom → root cause → evidence → impact → mitigation / status**. Read this before operating or
demoing the stack.

- **Scope:** MCP authentication, authorization (RBAC), OAuth, edge proxying. Not LLM completions.
- **Verified on:** LiteLLM `v1.87.0`; `mcp.linear.app/mcp` (OAuth), `mcp.deepwiki.com/mcp` (no-auth);
  APISIX `3.13.0-debian`; OpenFGA `v1.8`; exposed via a public HTTPS tunnel to LiteLLM `:4000` /
  APISIX `:9080`. HTTP codes/logs below were captured live on **2026-06-03**.
- **Severity:** 🔴 blocks a use case · 🟠 works only with specific config / has a caveat · 🟢 resolved.

| # | Area | Issue | Sev |
|---|---|---|---|
| 1 | LiteLLM OAuth | Native MCP OAuth can't serve Claude Desktop (Linear) | 🔴 |
| 2 | LiteLLM proxy | streamable-http proxy (#26700) | 🟢 |
| 3 | RBAC | `allowed_routes` / source-of-truth / cache | 🟠 |
| 4 | OpenFGA | bootstrap, identity, fail-closed | 🟠 |
| 5 | mcp-gateway | DCR persistence, bearer rotation, OAuth-MCP gap | 🟠 |
| 6 | APISIX | SSE buffering, no curl, standalone quirks, redis DB | 🟠 |
| 7 | Edge / ops | public-URL stability, issuer host, DB creation | 🟠 |

---

## 1. 🔴 LiteLLM-native MCP OAuth ↔ Claude Desktop (the Linear problem)

**Symptom.** Adding `https://<host>/mcp/linear` as a Claude Desktop custom connector fails. Claude
shows:

```
{"detail":{"error":"invalid_request",
 "error_description":"redirect_uri must use a loopback host (localhost or 127.0.0.0/8).",
 "hint":"Native MCP clients should register a callback on http://127.0.0.1:<port>/..."}}
```

**Root cause.** Claude Desktop's remote connector authenticates with the callback
`https://claude.ai/api/mcp/auth_callback` (seen in LiteLLM access logs). LiteLLM v1.87's native MCP
OAuth surface is incompatible with that, on four counts:

1. **`/mcp/<server>` returns `500`, not `401`, on an unauthenticated request** — breaks the standard
   MCP discovery entry point (which expects `401` + `WWW-Authenticate: … resource_metadata="…"`).
   Traceback: `Malformed API Key passed in. Ensure Key has 'Bearer ' prefix.` → `ProxyException`.
   (LiteLLM **#17272**, non-standard discovery URL pattern.)
2. **Root `/.well-known/oauth-authorization-server` advertises the wrong host:**
   `"issuer":"http://localhost:4000"` even through the public https tunnel (LiteLLM **#15719**).
3. **The aggregated `/v1/mcp/oauth/authorize` that Claude lands on requires a loopback redirect** for
   native clients → rejects `claude.ai` with the 400 above — **even with**
   `MCP_TRUSTED_REDIRECT_ORIGINS=claude.ai,claude.com` set (the allowlist does not apply to that rule).
4. **The one endpoint that accepts `claude.ai` is never reached.** The per-server `/linear/authorize`
   *does* redirect correctly once the origin is allowlisted, but discovery (1)+(2) never steers Claude
   there.

**Evidence (captured live).**

```bash
# (1) discovery entry point
POST /mcp/linear/   (no auth)                                  -> HTTP 500
# (2) root AS metadata, through the public https tunnel
GET  /.well-known/oauth-authorization-server                   -> issuer "http://localhost:4000"
# (3) aggregated authorize (Claude's path), claude.ai redirect, allowlist SET
GET  /v1/mcp/oauth/authorize?...redirect_uri=https://claude.ai/...  -> HTTP 400 "must use a loopback host"
# (4) per-server authorize, claude.ai redirect -> WORKS but unreachable
GET  /linear/authorize?...redirect_uri=https://claude.ai/...        -> HTTP 307  Location: https://linear.app/oauth/authorize?...
```

**Impact.** **Any per-user-OAuth MCP (Linear, GitHub, …) cannot be connected from Claude Desktop via
LiteLLM-native OAuth.** No LiteLLM env fixes it.

**Mitigation / status.** 🔴 upstream-blocked. Register OAuth MCPs on the **mcp-gateway** instead (it
accepts `claude.ai` redirects, returns proper `401`, builds metadata from `X-Forwarded-*`, mints
`cmp_*`); use LiteLLM only for RBAC. Full analysis + working pattern: **`litellm-mcp-oauth-limitations.md`**.

> **Claude Code (CLI) differs:** it uses a **loopback** redirect (`http://localhost:<port>`,
> cf. anthropics/claude-code#42765), so it passes rule (3) — but rule (1) (500 discovery) can still
> bite. This issue is specifically about **Claude Desktop**.

---

## 2. 🟢 LiteLLM streamable-http MCP proxy (#26700)

**Symptom (historical, v1.85.0).** Remote streamable-http MCP servers failed at session init with an
AnyIO cancel-scope `RuntimeError` (`TaskGroup` unhandled). This is why the gateway originally had a
direct-to-`mcp.linear.app` bypass ("Branch A").

**Status — resolved in v1.87.0 (verified).** LiteLLM proxies streamable-http MCP cleanly now:

```bash
POST /mcp/deepwiki/  (Authorization: Bearer <litellm-key>)  initialize  -> 200 SSE, full serverInfo
POST /mcp/deepwiki/                                          tools/list  -> 3 tools
# no cancel-scope / TaskGroup error in litellm logs
```

**Impact.** Branch A is no longer needed and was removed from the gateway. No-auth and static-token
MCPs proxy fine through LiteLLM.

**Caveat.** 🟢 but **re-test on every LiteLLM version bump** — this regressed once already.

---

## 3. 🟠 RBAC layering (allowed_routes, source-of-truth, cache, identity)

**Symptoms & causes.**

- **A virtual key sees zero MCPs / `GET /v1/mcp/server` → 403.** The key's `allowed_routes` must
  include `mcp_routes`. The LiteLLM UI "AI APIs" key type sets `["llm_api_routes"]` only → no MCP
  discovery. Use "Full Access" (`allowed_routes: []`) or create the key via API with
  `["llm_api_routes","mcp_routes"]`. (`rbac-mcp.md` §2.4.1.)
- **MCP granted but still hidden.** `object_permission.mcp_servers` must use the **server name**
  (`linear_mcp`), not the server **ID** (IDs change on config reload). Granularity is **per-server,
  not per-tool** — an allowed server exposes all its tools.
- **Two possible sources of truth.** RBAC can live in LiteLLM (`object_permission.mcp_servers`,
  echoed via `GET /v1/mcp/server`) **or** in OpenFGA (this stack's `_can_access_mcp`). Running both
  un-coordinated = divergent allow-lists. **Pick one** as authoritative; keep the other permissive.
- **Revocation lag.** The gateway caches the authz decision for `MCP_PERM_TTL` (default 10s). After
  revoking access, tools linger up to that window. Emergency: `redis-cli DEL mcp:perm:<email>:<server>`.
- **Identity requires the master key.** The OpenFGA subject is the **email** resolved from the virtual
  key via `/key/info`→`/user/info`, which needs `LITELLM_MASTER_KEY`. Without it (or with a master key
  pasted at consent, which has no email) the resolved email is `""` → **every check fails closed** →
  all MCPs hidden.

**Impact.** 🟠 Misconfigured keys silently show no tools (looks like a connection bug). Identity gaps
deny everything.

**Mitigation.** Generate MCP keys with `mcp_routes`; tie OpenFGA tuples to the **real** key-owner
email; set `LITELLM_MASTER_KEY`; choose a single RBAC authority.

---

## 4. 🟠 OpenFGA (bootstrap, identity, fail-closed)

**Symptoms & causes.**

- **store_id / model_id chicken-and-egg.** The gateway needs the OpenFGA store + model IDs to call
  `/stores/{id}/check`, but the store is created at runtime by the bootstrap one-shot. *Mitigated:* the
  gateway resolves the store **by name** (`OPENFGA_STORE_NAME`) at startup and picks the latest model,
  retrying until OpenFGA is reachable — so a single `docker compose up` suffices, no IDs file.
- **Tuples are keyed on the resolved email.** `user:<email> member team:<team>` must use the exact
  email LiteLLM returns for the consented key. The seed uses `admin@example.com`; real users must be
  added. Wrong/empty email → denied.
- **Distroless CLI has no shell.** `openfga/cli` can't run an idempotency-guard shell script.
  *Mitigated:* bootstrap is done with `curlimages/curl` against the HTTP API (`POST /stores`,
  `/authorization-models`, `/write`), guarded by a `GET /stores` name match → idempotent on re-`up`.
- **Fail-closed before resolution.** Until the store is resolved (or if OpenFGA is down), every
  `Check` returns deny → `{tools: []}`. Intentional, but looks like "no tools" during cold start.

**Evidence.** `bootstrap` log: `creating store 'llmops' → store id 01K… → model → tuples → complete`;
re-run: `store 'llmops' already exists; skipping`. Checks: `admin→deepwiki allowed:true`,
`nobody→deepwiki allowed:false`.

**Impact / status.** 🟠 works with the above mitigations; operators must seed real emails.

---

## 5. 🟠 mcp-gateway (DCR persistence, bearer, OAuth-MCP gap)

- **In-memory `CLIENTS` (DCR).** RFC 7591 client registrations live in process memory → lost on
  gateway restart. *Mitigated:* clients auto re-register on the next failed call. Durable fix: move to
  Redis/Postgres.
- **`cmp_*` bearer has no refresh/rotation.** Only the `authorization_code` grant; at `BEARER_TTL`
  (default 30d) the client must redo full consent.
- **Issuer depends on `X-Forwarded-Host`.** Behind APISIX/tunnel, if the forwarded host headers are
  dropped the gateway emits internal hosts in OAuth metadata → client issuer mismatch. APISIX must set
  `X-Forwarded-Host/Proto`; uvicorn runs with `--proxy-headers --forwarded-allow-ips *`.
- **Slim refactor removed gateway-side upstream OAuth.** The gateway is currently a pure shim
  (authn `cmp_*` + authz). To serve per-user-OAuth MCPs to Claude Desktop (issue #1) the gateway-owned
  Linear OAuth (callback, token exchange, refresh, token injection) must be **restored** ("Model B" in
  `litellm-mcp-oauth-limitations.md`). Until then OAuth MCPs do not work end-to-end from Claude Desktop.

**Impact / status.** 🟠 operational caveats; the OAuth-MCP gap is the actionable item (restore Model B).

---

## 6. 🟠 APISIX (edge)

- **SSE over HTTPS is buffered (APISIX #12665, 3.9.1+).** streamable-http would stall if APISIX
  terminated TLS. *Mitigated:* APISIX runs **HTTP-only** on `:9080`; the tunnel terminates TLS and
  forwards plain HTTP, so APISIX never sees HTTPS for the SSE hop. Keep it this way.
- **The `:debian` image ships no `curl`/`wget`.** A `curl`-based healthcheck fails with
  `sh: curl: not found` (exit 127) → container marked unhealthy though it serves fine. *Mitigated:*
  healthcheck uses openresty's `resty` for a TCP probe on `:9080`.
- **Standalone-mode quirks.** `deployment.role: data_plane` + `role_data_plane.config_provider: yaml`;
  env substitution in `apisix.yaml` is **`${{VAR}}`** (double braces, var must be in the container
  env); the file **must end with `#END`** or rules don't load; declaring `plugins:` in `config.yaml`
  **replaces** the default plugin list (list everything you use).
- **Redis DB collision.** `limit-count` with the redis policy must use **DB 3** — DB 2 is the gateway's
  `cmp_*` bindings, DB 0 is the LiteLLM cache. Reusing DB 2 corrupts bearer state.
- **Never touch `Authorization` on `/mcp*`.** The `cmp_*` bearer is opaque and validated only by the
  gateway; any `key-auth`/`jwt-auth` or `proxy-rewrite` that sets/removes `Authorization` clobbers it →
  401/auth failure. Likewise do **not** rewrite the path or drop `traceparent`/`baggage`/`Mcp-Session-Id`
  on the OAuth routes (breaks PKCE/issuer/trace nesting).
- **No OSS `proxy-buffering` plugin.** The API7-hub `proxy-buffering` plugin isn't in OSS APISIX.
  *Mitigated:* disable response buffering via an nginx `http_configuration_snippet`
  (`proxy_buffering off; proxy_read_timeout 86400s; chunked_transfer_encoding on;`).

**Impact / status.** 🟠 all mitigated in `apisix/config.yaml` + `apisix/apisix.yaml`; documented so they
aren't reintroduced.

---

## 7. 🟠 Edge / ops

- **Public URL must be stable.** If the public ingress/tunnel URL changes, you must re-set
  `PROXY_BASE_URL` (LiteLLM) / `MCP_GATEWAY_PUBLIC_URL` (gateway) and recreate the service, re-register
  the upstream OAuth callback `https://<new>/callback` in the provider app, and update the Claude
  connector URL. Use a stable domain to avoid this churn.
- **`PROXY_BASE_URL` must equal the public origin.** Otherwise OAuth metadata emits the internal host
  → issuer mismatch (LiteLLM #15719). Requires `FORWARDED_ALLOW_IPS=*` so uvicorn trusts the tunnel's
  `X-Forwarded-Proto` and emits `https`.
- **Postgres DBs aren't auto-created.** `POSTGRES_DB` creates only `litellm`; `langfuse` and `openfga`
  must exist before their migrations run. *Mitigated:* a `postgres-init` one-shot idempotently
  `createdb`s both.
- **LiteLLM `v1.85.0 → v1.87.0` bump.** Required for issue #2. Smoke-test LLM completions + deepwiki
  MCP after upgrading.

**Impact / status.** 🟠 operational; all mitigated in compose, but a changing public URL is a recurring
manual chore — use a stable domain.

---

## Decision matrix — where to register each MCP

| MCP auth class | Example | Register on | Claude reaches it via | Why |
|---|---|---|---|---|
| **Per-user OAuth** | Linear, GitHub | **mcp-gateway** (gateway-owned OAuth) | gateway `cmp_*` | LiteLLM-native OAuth can't serve Claude Desktop (issue #1) |
| **Static token** | Slack (`xoxb-`) | LiteLLM (static header) **or** gateway | gateway `cmp_*` | No client-side upstream OAuth → no wall |
| **No auth** | deepwiki | LiteLLM **or** gateway | gateway `cmp_*` | transport verified on v1.87 (issue #2) |

Claude must always OAuth against the **gateway** (the only AS that accepts `claude.ai`); LiteLLM is the
RBAC source and (for static/no-auth) the upstream proxy.

---

## Status summary

| # | Issue | Status | Exit criteria |
|---|---|---|---|
| 1 | LiteLLM-native OAuth ↔ Claude Desktop | 🔴 upstream-blocked | LiteLLM fixes #17272 (401 discovery) **and** #15719 (public issuer) **and** applies a trusted-origin allowlist to the authorize endpoint Claude uses (non-loopback `claude.ai`) |
| 2 | streamable-http proxy (#26700) | 🟢 resolved (v1.87) | — (regression-test on bumps) |
| 3 | RBAC layering | 🟠 config | choose single authority; `mcp_routes` keys; master key set |
| 4 | OpenFGA bootstrap/identity | 🟠 mitigated | seed real emails |
| 5 | gateway OAuth-MCP gap | 🟠 actionable | restore gateway-owned upstream OAuth (Model B) |
| 6 | APISIX edge quirks | 🟠 mitigated | keep HTTP-only; don't reintroduce |
| 7 | edge/ops | 🟠 operational | stable tunnel domain |

---

## References

**LiteLLM** — #26700 (streamable-http): https://github.com/BerriAI/litellm/issues/26700 ·
#17272 (discovery URL pattern): https://github.com/BerriAI/litellm/issues/17272 ·
#15719 (issuer host behind proxy): https://github.com/BerriAI/litellm/issues/15719 ·
MCP OAuth docs: https://docs.litellm.ai/docs/mcp_oauth

**APISIX** — #12665 (SSE over HTTPS): https://github.com/apache/apisix/issues/12665 ·
deployment modes: https://apisix.apache.org/docs/apisix/deployment-modes/

**Claude** — claude-code#42765 (loopback redirect_uri): https://github.com/anthropics/claude-code/issues/42765 ·
MCP connector: https://platform.claude.com/docs/en/agents-and-tools/mcp-connector

**RFCs** — 8252 (native app OAuth), 8414 (AS metadata), 9728 (protected-resource metadata),
7591 (DCR), 7636 (PKCE).

**Internal** — `litellm-mcp-oauth-limitations.md` (issue #1 deep dive + working pattern) ·
`rbac-mcp.md` (Team/User/Key RBAC) · `apisix-mcp-gateway.md` (edge × BFF × control-plane layering) ·
`mcp-gateway/README.md`.
