# mcp-gateway

Shim OAuth 2.1 (`:9100`) em frente ao LiteLLM. Emite um bearer opaco **composto** (`cmp_*`) que vincula, em um único token, duas identidades:

- **Plataforma** — virtual key do LiteLLM (`sk-...`). Define quais MCPs e modelos a key pode acessar.
- **Pessoal** — token OAuth do provider upstream (ex.: Linear, `actor=user`). Permite executar ações no upstream **como o usuário humano** que autorizou.

O cliente MCP (Claude Desktop, claude.ai, Cursor, etc.) enxerga **um** issuer OAuth e **um** access token. O gateway desmembra cada request internamente.

Implementação: `app.py` (arquivo único, ~1035 linhas). Para o aprofundamento de RBAC (Team/User/Virtual Key), threat model e troubleshooting completo, ver [`../docs/rbac-mcp.md`](../docs/rbac-mcp.md).

## Arquitetura

```
            +--------------------------------+
            |  Cliente MCP (OAuth 2.1)       |
            |  Claude Desktop / claude.ai... |
            +---------------+----------------+
                            | Authorization: Bearer cmp_*
                            v
+----------------------------------------------------------+
|              mcp-gateway  :9100                          |
|                                                          |
|  /.well-known/oauth-authorization-server   (RFC 8414)    |
|  /.well-known/oauth-protected-resource     (RFC 9728)    |
|  /register                                 (RFC 7591)    |
|  /v1/mcp/oauth/authorize  (GET form pt-BR + POST)        |
|  /v1/linear/callback                                     |
|  /v1/mcp/oauth/token      (PKCE S256, mint cmp_*)        |
|  /v1/mcp/oauth/revoke                                    |
|  /mcp{path}               (proxy autorizado)             |
|                                                          |
|  binding em Redis DB 2:                                  |
|    mcp:bearer:cmp_* -> { api_key, linear_access,         |
|                          linear_refresh, linear_exp }    |
+----+----------------------------------+------------------+
     | x-litellm-api-key: Bearer sk-... | Authorization: Bearer <linear_access>
     | x-mcp-linear-authorization: ...  | (bypass direto — workaround #26700)
     v                                  v
+----+-------------------+      +-------+---------------------+
|  litellm  :4000        |      |  mcp.linear.app/mcp         |
|  - /v1/mcp/server      |      +-----------------------------+
|    (allow-list por key)|
|  - /mcp/deepwiki  -----+----> |  mcp.deepwiki.com/mcp       |
+------------------------+      +-----------------------------+
```

## Endpoints

| Método | Rota | Função | Ref |
|---|---|---|---|
| GET | `/health` | Liveness; faz `ping` no Redis | `app.py:188` |
| GET | `/.well-known/oauth-authorization-server` | Metadata do Authorization Server (RFC 8414) | `app.py:197` |
| GET | `/.well-known/oauth-protected-resource[/path]` | Metadata do Protected Resource (RFC 9728) | `app.py:212` |
| POST | `/register` | Dynamic Client Registration (RFC 7591) | `app.py:226` |
| GET | `/v1/mcp/oauth/authorize` | Tela de consent em pt-BR (form) | `app.py:372` |
| POST | `/v1/mcp/oauth/authorize` | Dispatch por MCP via `resource` | `app.py:452` |
| GET | `/v1/linear/callback` | Recebe o code do Linear, troca por token | `app.py:517` |
| POST | `/v1/mcp/oauth/token` | Verifica PKCE S256, emite `cmp_*` | `app.py:565` |
| POST | `/v1/mcp/oauth/revoke` | Revoga `cmp_*` + token Linear upstream | `app.py:616` |
| ANY | `/mcp{path}` | Proxy autorizado para LiteLLM / Linear | `app.py:933` |

## Fluxo OAuth (Authorize → Token)

1. **Discovery** — cliente lê `/.well-known/oauth-authorization-server` e descobre os endpoints.
2. **DCR** — `POST /register` com `redirect_uris`; recebe um `client_id` (`mcp_*`). Validação de redirect contra `ALLOWED_REDIRECT_PREFIXES` (`app.py:159`).
3. **Authorize GET** — renderiza o form de consent (pt-BR). O usuário cola a virtual key (`sk-...`). O label do MCP vem do param `resource` via `_alias_from_resource` (`app.py:760`).
4. **Authorize POST** — **dispatch por MCP**: o alias extraído de `resource` é consultado em `MCP_AUTH_REGISTRY` (`app.py:86`):
   - `auth_type: "none"` → emite o auth code direto e faz 302 de volta ao cliente.
   - `auth_type: "oauth"` → cria sessão no Redis e redireciona ao provider em `OAUTH_PROVIDERS` (`app.py:72`).
5. **Callback** (só `oauth`) — `/v1/linear/callback` valida a sessão, troca o code do Linear por `access_token`/`refresh_token` e então emite o auth code do gateway.
6. **Token** — `POST /v1/mcp/oauth/token` verifica o PKCE S256 (`_verify_pkce`, `app.py:174`) e emite o bearer composto `cmp_*`.

O **dispatch por MCP** (param `resource` + registry) é o que permite adicionar novos MCPs/providers sem uma "flag global do Linear" — cada alias declara seu requisito de auth.

## Bearer composto e ciclo de vida

`token()` grava o binding em `mcp:bearer:cmp_*` (Redis DB 2):

| Token | TTL | Refresh |
|---|---|---|
| `cmp_*` (bearer do gateway) | 30 dias (`BEARER_TTL`, `app.py:102`) | Não rotaciona; só revoga |
| `linear_access` | 24h | Auto-refresh quando faltam `< REFRESH_LEAD` (60s) para expirar — `_refresh_linear` (`app.py:672`) |
| `linear_refresh` | longo | Rotacionado pelo Linear a cada refresh |

Refresh é **in-place**: o mesmo `cmp_*` permanece válido por 30 dias enquanto os tokens do Linear rotacionam por baixo. O cliente nunca precisa reautorizar por causa do Linear.

## Fluxo de request `/mcp{path}`

`mcp_proxy` (`app.py:933`):

1. Extrai o bearer do header `Authorization`.
2. Carrega o binding de `mcp:bearer:cmp_*`. Se `linear_exp` está perto de expirar, faz refresh.
3. Parseia o corpo JSON-RPC (`_parse_mcp_request`, `app.py:720`) para extrair `method` / `tool_name` / `id`.
4. Abre o span Langfuse.
5. Sem binding → `401` com header `WWW-Authenticate` apontando o resource metadata (`_unauth_response`, `app.py:700`).
6. Checa permissão da key sobre o MCP via `_key_has_mcp` (`app.py:643`), que consulta `GET /v1/mcp/server` no LiteLLM e faz cache de 30s.
7. Roteia:
   - **Branch A — Linear** (`/mcp/linear*`): bypass **direto** para `mcp.linear.app` injetando `Authorization: Bearer <linear_access>` (`_proxy_to_linear_direct`, `app.py:899`). Workaround do bug LiteLLM [#26700](https://github.com/BerriAI/litellm/issues/26700) (v1.85.0 não faz proxy de MCP streamable-http).
   - **Branch B — demais**: proxy para o LiteLLM (`:4000`) com `x-litellm-api-key: Bearer sk-...` e, se houver, `x-mcp-linear-authorization`.
8. Resposta em streaming com *tee* de buffer (`_tee_stream`, `app.py:849`) para alimentar o tracing sem bufferizar para o cliente.

## Observabilidade (Langfuse)

Um span por request (todos os tipos: `initialize`, `notifications/*`, `ping`, `tools/list`, `tools/call`):

- **Nome**: `<server>/<tool|method>` (`_span_name`) — ex.: `linear_mcp/create_issue`, `deepwiki_mcp/tools/list`.
- **`user_id` = email do dono da virtual key** (`_resolve_user_email`), em dois saltos com o `LITELLM_MASTER_KEY`: `/key/info` → `user_id` da key (UUID neste stack) → `/user/info` → `user_email`. Cacheado no Redis (`mcp:email:*`, TTL `MCP_EMAIL_TTL`) e gravado no binding do bearer no mint; bindings antigos com UUID são re-resolvidos quando o valor não contém `@`. Sem email/master key, degrada para o UUID e, por fim, `key:<sha256(key)[:12]>` (`_user_id`). Filtrável por email no Langfuse.
- **`session_id` = sessão do Claude (best-effort)** por cadeia de precedência (`_session_id`): header `Mcp-Session-Id` → chave de sessão no `baggage` → `trace_id` do `traceparent` (W3C) → hash do bearer (por conexão). Clientes Claude (Desktop/Code) não ecoam `Mcp-Session-Id` (claude-code#41836), então o `traceparent` é o agrupador prático.
- **Distributed-trace linking**: quando há `traceparent`, o span é aberto com `trace_context={trace_id, parent_span_id}` (`_parse_traceparent`), aninhando o span do gateway sob o trace do cliente — todos os spans de um trace aparecem juntos.
- **Tags**: `["mcp", <server>, <client_label>]` (`_client_label` deriva `claude` do `user-agent`).
- **Metadata**: `mcp.server`, `mcp.method`, `mcp.tool_name`, `mcp.jsonrpc_id`, `mcp.protocol_version`, `client.user_agent`, `w3c.traceparent`, `w3c.baggage`, `path`, `http_method`, `status_code`.
- **Erro**: exceção marca o span com `level="ERROR"` (`_end_span_error`).
- **Shutdown**: `langfuse.flush()` no evento de shutdown.

Tracing é **no-op** se `LANGFUSE_PUBLIC_KEY`/`LANGFUSE_SECRET_KEY` não estiverem setados (`LANGFUSE_ENABLED`). O gateway funciona normalmente sem Langfuse.

## Configuração

Variáveis principais (fonte: `../.env.example` e a seção `mcp-gateway` do `../docker-compose.yaml`):

| Variável | Função |
|---|---|
| `LITELLM_BASE_URL` | URL base do LiteLLM (`http://litellm:4000`) |
| `LITELLM_MASTER_KEY` | Master key do LiteLLM; resolve virtual key → email via `/key/info` para o `user_id` do tracing (opcional) |
| `MCP_EMAIL_TTL` | TTL do cache email no Redis em segundos (padrão 3600) |
| `PUBLIC_BASE_URL` | URL pública do gateway (usada no metadata OAuth) |
| `REDIS_URL` | Conexão Redis; o gateway usa o **DB 2** |
| `MCP_BEARER_TTL` | TTL do `cmp_*` em segundos (padrão 2592000 = 30d) |
| `ALLOWED_REDIRECT_PREFIXES` | Allow-list de `redirect_uri` (CSV) |
| `LINEAR_OAUTH_CLIENT_ID` / `_SECRET` / `LINEAR_REDIRECT_URI` / `LINEAR_OAUTH_SCOPES` | App OAuth do Linear |
| `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` / `LANGFUSE_HOST` | Tracing (opcional) |

> A tabela usa os nomes que o **container** lê (`app.py`). No `.env`, `PUBLIC_BASE_URL` e `ALLOWED_REDIRECT_PREFIXES` são setados via `MCP_GATEWAY_PUBLIC_URL` e `MCP_ALLOWED_REDIRECT_PREFIXES` — o `docker-compose.yaml` faz o mapeamento (`PUBLIC_BASE_URL: ${MCP_GATEWAY_PUBLIC_URL}`).

Chaves no Redis DB 2:

| Chave | Conteúdo | TTL |
|---|---|---|
| `mcp:session:*` | Sessão OAuth pendente (durante callback upstream) | 600s |
| `mcp:code:*` | Auth code pré-token | 300s |
| `mcp:bearer:cmp_*` | Binding `{ api_key, linear_access, linear_refresh, linear_exp }` | `BEARER_TTL` |
| `mcp:perm:<key>:<server>` | Cache da allow-list de MCP | 30s (`MCP_PERM_TTL`) |

## Como rodar

```bash
# a partir da raiz do stack
docker compose up -d mcp-gateway

# healthcheck
curl -s http://localhost:9100/health    # {"ok":true,"linear":true}
```

### Adicionar um novo MCP

Uma linha em `MCP_AUTH_REGISTRY` (`app.py:86`), espelhando o `mcp_servers` do `litellm/config.yaml`:

```python
MCP_AUTH_REGISTRY = {
    "linear_mcp":   {"auth_type": "oauth", "provider": "linear"},
    "deepwiki_mcp": {"auth_type": "none"},
    "novo_mcp":     {"auth_type": "none"},   # <- novo
}
```

### Adicionar um novo provider OAuth

Uma linha em `OAUTH_PROVIDERS` (`app.py:72`) + um handler de callback dedicado (ver `linear_callback`, `app.py:517`).

## Limitações

- **`CLIENTS` in-memory** — registros de DCR (`app.py:149`) somem no restart; clientes refazem o `/register`. Bindings (`cmp_*`) sobrevivem porque ficam no Redis.
- **Bug LiteLLM #26700** — força o bypass direto do Branch A para o Linear. Quando corrigido, o tráfego pode voltar a passar pelo LiteLLM (que repassa `authorization` via `extra_headers`).
- **Bearer não rotaciona** — `cmp_*` não tem refresh próprio; expira em `BEARER_TTL` ou é revogado.

Avaliação de gateways alternativos: [`ALTERNATIVES.md`](ALTERNATIVES.md).

## Saiba mais

- [`../docs/rbac-mcp.md`](../docs/rbac-mcp.md) — RBAC por Team/User/Virtual Key, fluxo ponta-a-ponta, threat model, matriz completa de env e troubleshooting.
- [`ALTERNATIVES.md`](ALTERNATIVES.md) — por que o shim custom em vez de um gateway pronto.
