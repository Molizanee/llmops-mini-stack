# mcp-gateway

Shim OAuth 2.1 **slim** (`:9100`) em frente ao LiteLLM. Faz **duas** coisas, nada mais:

- **Autenticar** o cliente MCP — é um Authorization Server OAuth 2.1 (DCR, PKCE S256, `.well-known`) que emite um bearer opaco `cmp_*` vinculado **apenas** a uma virtual key do LiteLLM (`sk-...`).
- **Autorizar** quais MCPs o chamador pode usar — decisão vem do **OpenFGA** (ReBAC): `user:<email> can_access mcp:<server>`, onde `<email>` é resolvido a partir da virtual key via LiteLLM `/key/info` → `/user/info`.

O gateway **não** mantém nenhuma conexão MCP direta e **não** faz OAuth upstream. Todo request `/mcp/*` é repassado ao LiteLLM com `x-litellm-api-key: Bearer <virtual_key>`. **Todas** as conexões MCP e toda a autenticação upstream (inclusive OAuth, `auth_type: oauth2`) vivem no LiteLLM (`litellm/config.yaml`).

Em produção, o gateway fica atrás do **APISIX** (`:9080`, edge: rate-limit, CORS, X-Forwarded-*). Implementação: `app.py` (arquivo único). RBAC, threat model e troubleshooting: [`../docs/rbac-mcp.md`](../docs/rbac-mcp.md). Decisão APISIX × gateway: [`../docs/apisix-mcp-gateway.md`](../docs/apisix-mcp-gateway.md).

## Arquitetura

```
   Cliente MCP (Claude Desktop / claude.ai / Cursor)
        |  Authorization: Bearer cmp_*
        v
+-----------------------------------------------+
|  APISIX  :9080  (edge)                        |
|  rate-limit · CORS · X-Forwarded-* · SSE      |
+-----------------------+-----------------------+
                        | (preserva Authorization)
                        v
+-----------------------------------------------+
|  mcp-gateway  :9100                           |
|  /.well-known/oauth-authorization-server      |
|  /.well-known/oauth-protected-resource        |
|  /register · /v1/mcp/oauth/authorize          |
|  /v1/mcp/oauth/token  (PKCE S256, mint cmp_*) |
|  /v1/mcp/oauth/revoke · /mcp{path}            |
|                                               |
|  authn: cmp_* -> { api_key, user_email }      |
|         (Redis DB 2: mcp:bearer:cmp_*)        |
|  authz: OpenFGA Check                         |
+----+--------------------------+---------------+
     | x-litellm-api-key        | user:<email> can_access
     |   Bearer sk-...          |   mcp:<server> ?
     v                          v
+----+-------------------+   +--+---------------------+
|  litellm  :4000        |   |  openfga  :8080        |
|  TODAS as conexoes MCP |   |  user -> team -> mcp   |
|  + OAuth upstream      |   +------------------------+
|  /mcp/deepwiki --------+--> mcp.deepwiki.com/mcp
|  /mcp/linear (oauth2) -+--> mcp.linear.app/mcp  (ver #26700)
+------------------------+
```

## Endpoints

| Método | Rota | Função |
|---|---|---|
| GET | `/health` | Liveness; `ping` no Redis + flag OpenFGA |
| GET | `/.well-known/oauth-authorization-server` | Metadata do AS (RFC 8414) |
| GET | `/.well-known/oauth-protected-resource[/path]` | Metadata do Protected Resource (RFC 9728) |
| POST | `/register` | Dynamic Client Registration (RFC 7591) |
| GET | `/v1/mcp/oauth/authorize` | Tela de consent em pt-BR (form) |
| POST | `/v1/mcp/oauth/authorize` | Valida a virtual key e emite o auth code |
| POST | `/v1/mcp/oauth/token` | Verifica PKCE S256, emite `cmp_*` |
| POST | `/v1/mcp/oauth/revoke` | Revoga `cmp_*` (delete do binding) |
| ANY | `/mcp{path}` | Proxy autorizado para o LiteLLM |

> Não há mais `/v1/linear/callback` nem dispatch por provider: o OAuth upstream saiu do gateway.

## Fluxo OAuth (Authorize → Token)

1. **Discovery** — cliente lê `/.well-known/oauth-authorization-server`.
2. **DCR** — `POST /register` com `redirect_uris`; recebe `client_id` (`mcp_*`). Validação contra `ALLOWED_REDIRECT_PREFIXES`.
3. **Authorize GET** — form de consent (pt-BR); o usuário cola a virtual key (`sk-...`).
4. **Authorize POST** — valida a key e emite o auth code direto (302 de volta ao cliente). Sem segundo salto a upstream.
5. **Token** — `POST /v1/mcp/oauth/token` verifica PKCE S256 (`_verify_pkce`) e emite o bearer `cmp_*`. No mint, resolve o email do dono da key (`_resolve_user_email`) e grava o binding.

## Bearer e binding

`token()` grava em `mcp:bearer:cmp_*` (Redis DB 2) o binding `{ api_key, user_email }`. O `cmp_*` dura `BEARER_TTL` (padrão 30 dias), não rotaciona, só é revogado. Não há tokens upstream para refrescar — isso é responsabilidade do LiteLLM agora.

## Fluxo de request `/mcp{path}`

`mcp_proxy`:

1. Extrai o bearer do header `Authorization`; carrega o binding de `mcp:bearer:cmp_*`.
2. Parseia o corpo JSON-RPC (`_parse_mcp_request`) → `method` / `tool_name` / `id`.
3. Resolve o email (binding ou `_resolve_user_email`) e abre o span Langfuse.
4. Sem binding → `401` com `WWW-Authenticate` (`_unauth_response`).
5. **Autorização (OpenFGA)** — `_can_access_mcp(email, server)` faz `POST /stores/{id}/check` (`user:<email> can_access mcp:<server>`), com cache de `MCP_PERM_TTL` no Redis (keyed no email). **Fail-closed.** Se negado, devolve a resposta sintética `{tools: []}` / erro JSON-RPC (`_restricted_mcp_response`) — **não** 403, para o conector conectar mesmo restrito.
6. **Proxy** — repassa ao LiteLLM (`:4000`) com `x-litellm-api-key: Bearer sk-...` (+ headers de passthrough, exceto hop-by-hop e `Authorization`). Resposta em streaming com *tee* de buffer (`_tee_stream`) e `X-Accel-Buffering: no` para SSE.

Na inicialização (`startup`), o gateway resolve `store_id`/`model_id` do OpenFGA por **nome** (`OPENFGA_STORE_NAME`), com retry até o OpenFGA responder. Enquanto o store não é conhecido, a autz falha-fechada (tudo restrito).

## Observabilidade (Langfuse)

Um span por request. Inalterado em relação à versão anterior, exceto que não há mais tags/headers de Linear:

- **Nome**: `<server>/<tool|method>` (`_span_name`).
- **`user_id` = email** do dono da virtual key (`_resolve_user_email`, 2 saltos com `LITELLM_MASTER_KEY`, cache `mcp:email:*`).
- **`session_id`**: `Mcp-Session-Id` → `baggage` → `traceparent` → hash do bearer.
- **Distributed-trace linking** via `traceparent` (`trace_context`).
- **Tags**: `["mcp", <server>, <client_label>]`. **Metadata**: `mcp.*`, `w3c.*`, `path`, `http_method`, `status_code`.

No-op se `LANGFUSE_*` não setado.

## Configuração

| Variável | Função |
|---|---|
| `LITELLM_BASE_URL` | URL base do LiteLLM (`http://litellm:4000`) |
| `LITELLM_MASTER_KEY` | **Obrigatória de fato.** Resolve virtual key → email (o subject da autz OpenFGA). Sem ela, todo Check falha-fechado e nenhum MCP aparece. |
| `PUBLIC_BASE_URL` | URL pública (issuer no metadata OAuth). O túnel aponta para o APISIX `:9080`. |
| `REDIS_URL` | Conexão Redis; o gateway usa o **DB 2** |
| `MCP_BEARER_TTL` | TTL do `cmp_*` (padrão 2592000 = 30d) |
| `MCP_EMAIL_TTL` | TTL do cache de email (padrão 3600) |
| `MCP_PERM_TTL` | TTL do cache da decisão OpenFGA (padrão 10s) |
| `OPENFGA_API_URL` | `http://openfga:8080` |
| `OPENFGA_STORE_NAME` | Nome do store resolvido no startup (padrão `llmops`) |
| `OPENFGA_STORE_ID` / `OPENFGA_MODEL_ID` | Opcionais; se vazios, resolvidos por nome / último modelo |
| `ALLOWED_REDIRECT_PREFIXES` | Allow-list de `redirect_uri` (CSV) |
| `LANGFUSE_*` | Tracing (opcional) |

> No `.env`, `PUBLIC_BASE_URL` e `ALLOWED_REDIRECT_PREFIXES` vêm de `MCP_GATEWAY_PUBLIC_URL` e `MCP_ALLOWED_REDIRECT_PREFIXES` (mapeados no `docker-compose.yaml`).

Chaves no Redis DB 2:

| Chave | Conteúdo | TTL |
|---|---|---|
| `mcp:code:*` | Auth code pré-token | 300s |
| `mcp:bearer:cmp_*` | Binding `{ api_key, user_email }` | `BEARER_TTL` |
| `mcp:email:*` | Cache virtual key → email | `MCP_EMAIL_TTL` |
| `mcp:perm:<email>:<server>` | Cache da decisão OpenFGA | `MCP_PERM_TTL` |

## Como rodar

```bash
# a partir da raiz do stack
docker compose up -d

# healthcheck (direto no gateway)
curl -s http://localhost:9100/health     # {"ok":true,"openfga":true}

# via edge (APISIX)
curl -s http://localhost:9080/.well-known/oauth-authorization-server
```

### Adicionar um novo MCP

Não toca no gateway. Dois passos:

1. **LiteLLM** — registra a conexão em `litellm/config.yaml` (`mcp_servers`), com o `auth_type` que o upstream exigir (`none` / `api_key` / `oauth2`).
2. **OpenFGA** — habilita o MCP para um time: tupla `team:<time> enabled_team mcp:<server>` (e `user:<email> member team:<time>`). Via API: `POST /stores/{id}/write`. O nome do objeto `mcp:<server>` deve casar com o nome em `mcp_servers` e com `_server_from_path`.

## Limitações

- **`CLIENTS` in-memory** — registros de DCR somem no restart; clientes refazem o `/register`. Bindings (`cmp_*`) sobrevivem no Redis.
- **#26700 (era do v1.85)** — o LiteLLM **v1.87.0 faz proxy de MCP streamable-http normalmente** (verificado: `tools/list` do deepwiki e authorize OAuth do Linear). O bug de cancel-scope do v1.85 não dispara mais; por isso o Branch A (bypass direto) foi **removido** com segurança.
- **Bearer não rotaciona** — `cmp_*` expira em `BEARER_TTL` ou é revogado.
- **OpenFGA fail-closed** — store não resolvido, email não resolvido ou OpenFGA indisponível → tudo restrito (`{tools: []}`).

## Saiba mais

- [`../docs/rbac-mcp.md`](../docs/rbac-mcp.md) — RBAC, fluxo ponta-a-ponta, threat model, troubleshooting.
- [`../docs/apisix-mcp-gateway.md`](../docs/apisix-mcp-gateway.md) — APISIX na borda × gateway BFF × LiteLLM.
- [`ALTERNATIVES.md`](ALTERNATIVES.md) — por que o shim custom.
