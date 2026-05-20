# RBAC por MCP, Team e Virtual Key no `llmops-mini-stack`

> Documento técnico em pt-BR descrevendo como o stack implementa controle de acesso baseado em papéis (RBAC) para servidores MCP, segmentado por **Team**, **User** e **Virtual Key** do LiteLLM, com identidade pessoal de usuário propagada via OAuth upstream (Linear).
>
> Fontes primárias:
> - `litellm/config.yaml`
> - `mcp-gateway/app.py`
> - `docker-compose.yaml`
> - `.env.example`

---

## Sumário

1. [Visão geral](#1-visão-geral)
2. [Camada 1 — Team e User no LiteLLM](#2-camada-1--team-e-user-no-litellm)
3. [Camada 2 — Virtual Key e allow-list de MCP](#3-camada-2--virtual-key-e-allow-list-de-mcp)
4. [Camada 3 — OAuth pessoal upstream (Linear)](#4-camada-3--oauth-pessoal-upstream-linear)
5. [O shim `mcp-gateway/app.py` componente por componente](#5-o-shim-mcp-gatewayapppy-componente-por-componente)
6. [Fluxo ponta-a-ponta](#6-fluxo-ponta-a-ponta)
7. [Camadas adicionais de policy](#7-camadas-adicionais-de-policy)
8. [Matriz de variáveis de ambiente](#8-matriz-de-variáveis-de-ambiente)
9. [Modelo de ameaça e mitigações](#9-modelo-de-ameaça-e-mitigações)
10. [Operação e troubleshooting](#10-operação-e-troubleshooting)
11. [Limites conhecidos](#11-limites-conhecidos)

---

## 1. Visão geral

O stack expõe ferramentas MCP (Model Context Protocol) a clientes externos através de **um único endpoint OAuth 2.1** — o serviço `mcp-gateway` (porta `:9100`). Internamente, o gateway compõe duas identidades distintas em um único bearer opaco:

- **Identidade da plataforma**: virtual key emitida pelo LiteLLM (`sk-...`). Define quais MCPs e quais modelos LLM o usuário tem direito de acessar.
- **Identidade pessoal**: token OAuth do provider upstream (ex.: Linear com `actor=user`). Permite que ações no upstream sejam executadas COMO O USUÁRIO humano que autorizou.

### MCP-client agnóstico

O conjunto `mcp-gateway` + `LiteLLM` + `Langfuse` não tem dependência de cliente específico. Qualquer aplicação que fale o protocolo MCP padrão (Streamable HTTP + OAuth 2.1 conforme [modelcontextprotocol.io](https://modelcontextprotocol.io)) consegue conectar:

- **Claude Desktop** e **claude.ai** (web/extensão) — testados no laboratório.
- **ChatGPT** (custom connectors / GPTs que suportam MCP).
- **Cursor**, **Windsurf**, **Zed**, **VS Code com extensão MCP** e demais IDEs com cliente MCP nativo.
- **Agentes** próprios construídos com `mcp` SDK (Python, TypeScript, Go) — basta apontar para o endpoint do gateway e seguir o fluxo Discovery → DCR → Authorize → Token descrito em §6.
- **Frameworks de orquestração** (LangChain, LlamaIndex, AutoGen, CrewAI, etc.) com adapter MCP.

O gateway só fala protocolo: `/.well-known/oauth-authorization-server` (RFC 8414), `/.well-known/oauth-protected-resource` (RFC 9728), `/register` (RFC 7591), authorize + PKCE S256 (RFC 7636), Bearer token. Tudo padrão. Trocar de cliente significa apontar o cliente novo para o mesmo `PUBLIC_BASE_URL` e refazer o consent. O Langfuse continua observando todas as chamadas (cada cliente vira um span com `trace.user_id` distinto via `bearer[:16]`).

### Diagrama

```
                    +--------------------------------+
                    |   Claude Desktop / claude.ai   |
                    |   (cliente MCP / OAuth 2.1)    |
                    +-----------------+--------------+
                                      |
                                      | Authorization: Bearer cmp_*
                                      | (token opaco emitido pelo shim)
                                      v
+-----------------------------------------------------------------+
|                  mcp-gateway   :9100                            |
|                                                                 |
|   /.well-known/oauth-authorization-server                       |
|   /.well-known/oauth-protected-resource[/path]                  |
|   /register             (Dynamic Client Registration RFC 7591)  |
|   /v1/mcp/oauth/authorize  (GET + POST com tela HTML pt-BR)     |
|   /v1/linear/callback   (recebe code do Linear)                 |
|   /v1/mcp/oauth/token   (PKCE S256, mint do bearer cmp_*)       |
|   /v1/mcp/oauth/revoke                                          |
|   /mcp{path}            (proxy autorizado)                      |
|                                                                 |
|   binding em Redis (DB 2):                                      |
|     mcp:bearer:cmp_* -> { api_key, linear_access,               |
|                            linear_refresh, linear_exp }         |
+----+---------------------------------------+--------------------+
     |                                       |
     | x-litellm-api-key: Bearer sk-...      | Authorization: Bearer <linear_access>
     | x-mcp-linear-authorization: ...       | (bypass direto - workaround #26700)
     v                                       v
+----+---------------------+         +-------+---------------------+
|   litellm   :4000        |         |   mcp.linear.app/mcp        |
|                          |         |   (servidor MCP do Linear)  |
|  - /v1/mcp/server        |         +-----------------------------+
|    (allow-list por key)  |
|  - /mcp/deepwiki         |         +-----------------------------+
|    -> deepwiki.com/mcp   +-------> |  mcp.deepwiki.com/mcp       |
|                          |         |  (servidor MCP do DeepWiki) |
+--------------------------+         +-----------------------------+
```

### As três camadas RBAC

| Camada | Identidade | Onde se define | O que controla |
|---|---|---|---|
| 1. Team / User | Conta LiteLLM | Admin UI `:4000` + `litellm/config.yaml` | Modelos LLM, budgets, rate limits, `allowed_routes`, MCPs (via `object_permission.mcp_servers`) |
| 2. Virtual Key | `sk-...` emitida pelo LiteLLM | Herdada do Team/User pai | Mesma allow-list de MCPs; é o que o usuário cola na tela de consent |
| 3. OAuth upstream | Token Linear `actor=user` | Aprovação interativa no `linear.app/oauth/authorize` | Identidade humana dentro do Linear (cria issues como você, não como bot) |

### Por que existe o shim

LiteLLM v1.85.0 fala MCP nativamente como gateway de servidor → servidor, mas **não é um Authorization Server OAuth para clientes externos**. Clientes MCP (Claude Desktop, claude.ai) esperam:

- Um único `issuer` OAuth 2.1.
- Um único `access_token` por servidor MCP.
- Discovery via `.well-known/oauth-protected-resource` (RFC 9728) e `.well-known/oauth-authorization-server` (RFC 8414).
- Dynamic Client Registration (RFC 7591) e PKCE S256 (RFC 7636).

O `mcp-gateway` implementa esse contrato. Internamente, ele:

1. Pede ao usuário a virtual key LiteLLM na tela de consent.
2. Identifica o MCP solicitado pelo parâmetro `resource` da URL de authorize (`https://<gateway>/mcp/<alias>`) e consulta o `MCP_AUTH_REGISTRY` (ver §5.2). Se `auth_type=oauth`, redireciona automaticamente ao provider configurado (ex.: Linear); se `auth_type=none`, emite o code direto sem segundo hop.
3. Cria um **compound bearer** (`cmp_*`) que amarra a virtual key ao token OAuth pessoal (quando houver).
4. A cada chamada `/mcp/*`, expande o bearer em headers que o LiteLLM (ou o servidor MCP upstream) entende, e emite um span Langfuse `<mcp_name>/<tool_ou_method>` por requisição.

---

## 2. Camada 1 — Team e User no LiteLLM

### 2.1 Onde se configura

A administração de Teams, Users e Keys é feita na **admin UI do LiteLLM** em `http://litellm:4000` (ou na rota pública conforme reverse proxy). Os dados persistem em Postgres porque `general_settings` do `litellm/config.yaml` declaram:

```yaml
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  database_url: os.environ/DATABASE_URL
  store_model_in_db: true
```

A flag `store_model_in_db: true` é obrigatória para que modelos, teams, users e keys editados pela UI sejam persistidos no banco — sem ela, a UI vira somente-leitura sobre o YAML.

### 2.2 Defaults aplicados a internal users

Quando um internal user é criado (via SSO ou via API com `user_role=internal_user`), o LiteLLM aplica os defaults declarados em `litellm/config.yaml` (linhas 29-36):

```yaml
litellm_settings:
  default_internal_user_params:
    user_role: "internal_user"
    max_budget: 10.0
    budget_duration: "30d"
    models: ["gemini-3-flash", "minimax-m2.5"]
    tpm_limit: 10000
    rpm_limit: 60
    allowed_routes: ["llm_api_routes", "mcp_routes"]
```

Os campos relevantes:

| Campo | Função |
|---|---|
| `user_role` | `internal_user` (não admin). Não pode editar Teams nem outras keys. |
| `max_budget` / `budget_duration` | Orçamento em USD por janela rolante. LiteLLM bloqueia chamadas após estouro. |
| `models` | Allow-list de modelos LLM. Modelos não listados retornam 403 mesmo se a key for válida. |
| `tpm_limit` / `rpm_limit` | Rate limits por minuto (tokens / requests). |
| `allowed_routes` | **Grupos de rotas** habilitadas para a key. `mcp_routes` é **obrigatório** para que o usuário consiga atravessar o shim — sem isto, qualquer chamada `/mcp/*` retorna 403 no LiteLLM mesmo antes de checar MCPs específicos. |

### 2.3 Upper bound de geração de keys

Internal users podem gerar suas próprias keys (via UI ou `POST /key/generate`). O `upperbound_key_generate_params` (linhas 38-44) define o teto absoluto que nenhuma key gerada por internal user pode ultrapassar:

```yaml
  upperbound_key_generate_params:
    max_budget: 10.0
    budget_duration: "30d"
    duration: "30d"
    models: ["gemini-3-flash", "minimax-m2.5"]
    tpm_limit: 10000
    rpm_limit: 60
```

Importante: o teto cobre `max_budget`, `tpm_limit`, `rpm_limit`, `duration` (validade da key) e a allow-list de `models`. Não cobre, no YAML, a allow-list de MCPs — esta vem do Team pai ou do `object_permission` explícito da key (ver §3.1).

### 2.4 Hierarquia de herança

```
Team
 └─> User (member do team)
      └─> Virtual Key (gerada pelo user, herda escopo)
```

Cada camada pode SOMENTE restringir a anterior. Uma key não pode ter mais modelos do que o User, e o User não pode ter mais modelos do que o Team. O mesmo vale para MCPs (`object_permission.mcp_servers`).

### 2.5 Como criar Team com MCPs específicos

Via UI (`:4000` → Teams → New):

1. Definir `team_alias` (ex: `eng-backend`).
2. Em **Models**: marcar os modelos LLM permitidos para o team.
3. Em **Allowed MCP Servers** (ou via `object_permission.mcp_servers`): marcar `deepwiki_mcp` e/ou `linear_mcp` (os mesmos nomes declarados em `mcp_servers:` do `config.yaml`).
4. Definir budget de team se desejado (limite agregado de todos os membros).
5. Salvar. Membros recebem convite por e-mail ou são adicionados via API.

Via API (admin):

```bash
curl -X POST http://litellm:4000/team/new \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "team_alias": "eng-backend",
    "models": ["gemini-3-flash", "minimax-m2.5"],
    "max_budget": 100.0,
    "budget_duration": "30d",
    "object_permission": {
      "mcp_servers": ["deepwiki_mcp", "linear_mcp"]
    }
  }'
```

A resposta inclui `team_id`. Para adicionar membros:

```bash
curl -X POST http://litellm:4000/team/member_add \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "team_id": "<team_id>",
    "member": [{"user_id": "user@example.com", "role": "user"}]
  }'
```

### 2.6 ATENÇÃO — Master key

`LITELLM_MASTER_KEY` (em `.env`) é a credencial root do LiteLLM. **Bypassa todo o RBAC** descrito acima: tem acesso a todos os modelos, todos os MCPs, sem rate limit e sem budget. Use-a APENAS:

- Para administração via API/UI.
- Em ambientes single-user de laboratório.

**Nunca** colar a master key na tela de consent do shim em produção compartilhada — qualquer user que pegar essa string assume controle total do gateway.

---

## 3. Camada 2 — Virtual Key e allow-list de MCP

### 3.1 O que é a virtual key

Uma virtual key é um identificador `sk-...` emitido pelo LiteLLM via:

- `POST /key/generate` (API).
- UI → Keys → Generate (ações do usuário ou do admin).

Ela herda do Team/User pai (i) a allow-list de modelos LLM, (ii) os budgets e rate limits, (iii) os `allowed_routes`, e (iv) a allow-list de MCPs (em `object_permission.mcp_servers`).

### 3.2 Endpoint canônico de autorização MCP

`GET /v1/mcp/server` com `Authorization: Bearer sk-...` retorna **apenas** os MCP servers permitidos para aquela key.

Exemplo:

```bash
curl -s http://litellm:4000/v1/mcp/server \
  -H "Authorization: Bearer sk-virtual-key-abc123"
```

Resposta típica (forma pode variar conforme a versão do LiteLLM — o shim trata as variações; ver §5.10):

```json
{
  "data": [
    {
      "server_name": "deepwiki_mcp",
      "url": "https://mcp.deepwiki.com/mcp",
      "alias": "deepwiki"
    }
  ]
}
```

Esta é a fonte de verdade que o shim consulta antes de proxar `/mcp/linear` (ver §5.9). É o ponto de enforcement do RBAC por MCP.

### 3.3 Declaração dos MCPs no YAML

`litellm/config.yaml` (linhas 50-55):

```yaml
mcp_servers:
  deepwiki_mcp:
    url: "https://mcp.deepwiki.com/mcp"
  linear_mcp:
    url: "https://mcp.linear.app/mcp"
    extra_headers: ["authorization"]
```

- `deepwiki_mcp` é público, não exige nenhuma credencial — o LiteLLM repassa a chamada sem header `authorization`.
- `linear_mcp` declara `extra_headers: ["authorization"]`. Isso diz ao LiteLLM: "se o cliente enviar um header `authorization`, repasse-o ao upstream do Linear como `authorization`". É como o token OAuth pessoal chega ao Linear quando a chamada passa pelo LiteLLM (cenário que, por enquanto, está bypassado pelo workaround do issue #26700 — ver §5.9 e §11).

### 3.4 Aliases

`litellm/config.yaml` (linhas 46-48):

```yaml
litellm_settings:
  mcp_aliases:
    "deepwiki": "deepwiki_mcp"
    "linear": "linear_mcp"
```

Aliases permitem que o cliente MCP use nomes amigáveis nas URLs path-routed: `/mcp/deepwiki` resolve para o servidor `deepwiki_mcp`. O shim, por seu lado, faz path matching com prefixo `/linear` (qualquer um de `/linear`, `/linear_mcp`, `/linear/`, `/linear_mcp/` casa — ver `is_linear_path` em `mcp-gateway/app.py:746`).

### 3.5 Exemplo: gerar virtual key com escopo MCP explícito

```bash
curl -X POST http://litellm:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice@example.com",
    "team_id": "<team_id>",
    "models": ["gemini-3-flash"],
    "max_budget": 5.0,
    "budget_duration": "30d",
    "duration": "30d",
    "allowed_routes": ["llm_api_routes", "mcp_routes"],
    "object_permission": {
      "mcp_servers": ["deepwiki_mcp"]
    }
  }'
```

Resposta inclui `key` (`sk-...`). Esta key:

- Pode chamar `gemini-3-flash` apenas.
- Pode passar pelo shim (`mcp_routes`).
- Pode usar `deepwiki_mcp` apenas. Tentar `/mcp/linear` → 403 (`_key_has_mcp` retorna `False`).
- Tem orçamento 5 USD em 30 dias.

---

## 4. Camada 3 — OAuth pessoal upstream

Esta camada se aplica a qualquer MCP marcado como `auth_type=oauth` no `MCP_AUTH_REGISTRY` (§5.2). Hoje, o único provider concretamente configurado é o Linear, e os exemplos abaixo usam Linear como caso ilustrativo. A mesma estrutura suporta Notion, Slack, GitHub, Jira, etc. — basta adicionar uma entrada em `OAUTH_PROVIDERS`, um alias em `MCP_AUTH_REGISTRY` e um handler de callback (ver §11.3 para o checklist).

### 4.1 Por que é necessário

O LiteLLM, sozinho, autentica a key da plataforma — mas não tem como saber qual usuário humano está por trás daquela key. Para MCPs onde ações geram efeitos rastreáveis no sistema upstream (criar issue no Linear, postar mensagem no Slack, editar página no Notion, abrir PR no GitHub, etc.), o sistema upstream precisa autorizar a operação **como o usuário**, não como um bot da organização.

Vários providers expõem essa semântica via parâmetros extras no authorize endpoint. Exemplos:

- **Linear**: `actor=user` (ações ficam "criado por Alice", não "criado por <App OAuth>"). Default no shim — declarado em `OAUTH_PROVIDERS["linear"]["extra_params"]`.
- **Slack**: distinção entre `user_scope` e `scope` no OAuth — `user_scope` produz tokens que agem como o usuário; `scope` produz tokens de bot.
- **Google / Microsoft**: `prompt=consent` força reconfirmação, e o token herda a identidade do usuário logado.

A flexibilidade vive em `provider["extra_params"]` — cada provider declara o que precisa para ações como-usuário.

### 4.2 Armazenamento

Após o callback OAuth (`/v1/linear/callback` no caso atual), o shim persiste o binding em Redis (DB 2, segregado do cache do LiteLLM que usa DB 0) sob a chave `mcp:bearer:cmp_<random>`:

```json
{
  "api_key": "sk-virtual-key-abc123",
  "linear_access": "lin_oauth_...",
  "linear_refresh": "lin_refresh_...",
  "linear_exp": 1716246000
}
```

- TTL Redis: `BEARER_TTL` (default 30 dias = 2592000s).
- A key Redis é o **valor opaco** que o cliente MCP recebe como `access_token`. O cliente nunca vê a virtual key nem o token do upstream.
- Para um futuro provider (ex.: Notion), espera-se acrescentar campos `notion_access`/`notion_refresh`/`notion_exp` ao mesmo JSON. A refatoração futura sugerida em §11.3 normaliza isso para `oauth.<provider>.{access,refresh,exp}`.

### 4.3 Auto-refresh

Providers OAuth emitem `access_token` com TTL curto (Linear: ~1h; Slack: indefinido com refresh opcional; Notion: ~1h). Para evitar 401s mid-call, o proxy `/mcp/*` verifica antes de cada request:

```python
if bind.get("linear_exp") and bind["linear_exp"] < time.time() + REFRESH_LEAD:
    bind = await _refresh_linear(bearer, bind)
```

`REFRESH_LEAD = 60s` (constante em `app.py`). Se faltam menos de 60s para expirar, o shim chama `POST {LINEAR_TOKEN_URL}` com `grant_type=refresh_token` e atualiza o binding no Redis **mantendo a mesma chave externa** `cmp_*`. O cliente nunca percebe a rotação interna.

Linear rotaciona o `refresh_token` a cada uso — `_refresh_linear` salva o novo `refresh_token` se vier, ou mantém o atual. Outros providers podem ou não rotacionar; cada `_refresh_<x>` precisa lidar com a política do upstream específico.

Se o refresh falhar (refresh_token revogado, etc.), o binding é deletado e o cliente recebe 401 — ele precisa refazer o fluxo OAuth completo.

---

## 5. O shim `mcp-gateway/app.py` componente por componente

Este capítulo descreve cada endpoint e função relevante. Números de linha referem `mcp-gateway/app.py`.

### 5.1 Metadata OAuth 2.1 (linhas 157-183)

```python
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
```

Pontos relevantes:

- **`"code_challenge_methods_supported": ["S256"]`** — PKCE obrigatório. O shim recusa `plain` ou ausência (`app.py:363`).
- **`"token_endpoint_auth_methods_supported": ["none"]`** — cliente público (sem `client_secret`). Apropriado para apps desktop/SPA que não conseguem guardar segredos.

`/.well-known/oauth-protected-resource[/path]` (RFC 9728) anuncia, por recurso `/mcp/*`, qual AS o cliente deve usar:

```python
return {
    "resource": resource,
    "authorization_servers": [PUBLIC_BASE],
    "bearer_methods_supported": ["header"],
    "scopes_supported": [],
}
```

### 5.2 Registry de auth por alias e providers OAuth

O dispatch automático introduzido em [`add-mcp-langfuse-traces`](#) repousa em duas tabelas declaradas próximas do bloco de env Linear em `mcp-gateway/app.py`:

```python
OAUTH_PROVIDERS: dict[str, dict[str, Any]] = {}
if LINEAR_ENABLED:
    OAUTH_PROVIDERS["linear"] = {
        "authorize_url": LINEAR_AUTHORIZE_URL,
        "client_id": LINEAR_CLIENT_ID,
        "redirect_uri": LINEAR_REDIRECT_URI,
        "scopes": LINEAR_SCOPES,
        "extra_params": {"actor": "user"},
    }

# Mirrors LiteLLM's mcp_servers em litellm/config.yaml.
MCP_AUTH_REGISTRY: dict[str, dict[str, str]] = {
    "linear_mcp":   {"auth_type": "oauth", "provider": "linear"},
    "deepwiki_mcp": {"auth_type": "none"},
}
```

Semântica:

- **`MCP_AUTH_REGISTRY`** — mapeia alias do MCP (mesmo nome usado em `litellm/config.yaml → mcp_servers`) para `auth_type`. Valor `"none"` significa "apenas virtual key basta"; `"oauth"` significa "redirecionar a um provider antes de emitir o code".
- **`OAUTH_PROVIDERS`** — mapeia `provider` (`"linear"`) para os parâmetros do authorize-endpoint upstream. Decoupla alias do provider, então um futuro `linear_admin_mcp` poderia reusar `provider="linear"` sem duplicar config.
- **Alias desconhecido OU `resource` ausente** → fallback `auth_type="none"` (sem segundo hop). Mantém compat com clientes legados que não enviam `resource` e evita quebrar se LiteLLM ganhar um novo MCP antes do registry ser atualizado.
- **`auth_type=oauth` com provider faltando** (`LINEAR_OAUTH_*` não definidos) → HTTP 400 `oauth_provider_unavailable: <provider>`. Falha alta para evitar consent mal-configurado.

Helper que extrai o alias:

```python
def _alias_from_resource(resource: str) -> str:
    """Pull the last path segment of resource=https://host/mcp/<alias>."""
    if not resource:
        return ""
    try:
        path = urlparse(resource).path
    except ValueError:
        return ""
    return path.rstrip("/").rsplit("/", 1)[-1] if path else ""
```

**Adicionar um novo MCP no-auth**: uma linha em `MCP_AUTH_REGISTRY`.
**Adicionar um novo MCP com OAuth pessoal**: uma linha em `OAUTH_PROVIDERS` + uma linha em `MCP_AUTH_REGISTRY` apontando para ele + handler de callback dedicado (hoje só existe `/v1/linear/callback`).

### 5.3 Dynamic Client Registration `/register` (linhas 186-211)

RFC 7591. Aceita um POST JSON com `redirect_uris` e `client_name`:

```python
@app.post("/register")
async def register(request: Request) -> JSONResponse:
    body = await request.json()
    cid = "mcp_" + secrets.token_urlsafe(16)
    now = int(time.time())
    redirect_uris = body.get("redirect_uris", [])
    for uri in redirect_uris:
        _validate_redirect_uri(uri)
    CLIENTS[cid] = { ... }
    return JSONResponse({...}, status_code=201)
```

- Cada `redirect_uri` é validado por `_validate_redirect_uri` (§9 Modelo de Ameaça).
- `CLIENTS` é um `dict` in-memory. Sobrevive somente até o restart do container. Mitigação: clientes legítimos (Claude Desktop) simplesmente refazem o registration na próxima sessão, custo zero para o usuário.

### 5.4 Authorize GET

```python
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
    resource = qp.get("resource", "")            # NEW

    # Validações: response_type=code, PKCE S256 obrigatório, redirect_uri validado.
    ...

    alias = _alias_from_resource(resource)
    mcp_label = alias or "MCP genérico"
    return HTMLResponse(_render_authorize(..., resource, mcp_label))
```

Mudanças em relação à versão original:

- **Lê `resource`** da query string. Claude.ai envia `resource=https://<gateway>/mcp/<alias>` em todo authorize. `_alias_from_resource` extrai o último segmento do path. Empty/garbage → string vazia → fallback `auth_type=none` no POST.
- **`mcp_label`** é exibido no consent para o usuário saber qual MCP está sendo autorizado.

A página HTML renderizada (`_AUTHORIZE_HTML`) pede apenas:

- Virtual key LiteLLM (`sk-...`).
- Um hidden field `resource` que o POST usará para dispatch.

**Não há mais checkbox "Conectar Linear"**. A decisão de redirecionar ao Linear (ou a qualquer outro provider OAuth) vem do `MCP_AUTH_REGISTRY` em função do alias — automática, não negociável pelo usuário.

Branding: "Arara Tech · Grupo Guanabara". Texto em pt-BR.

### 5.5 Authorize POST

O dispatch é dirigido pelo registry, não por checkbox:

```python
async def authorize_post(..., api_key: str = Form(...), resource: str = Form("")) -> Response:
    ...
    alias = _alias_from_resource(resource)
    entry = MCP_AUTH_REGISTRY.get(alias, {"auth_type": "none"})

    if entry["auth_type"] == "none":
        return await _mint_auth_code(...)        # caminho A

    provider_id = entry["provider"]
    provider = OAUTH_PROVIDERS.get(provider_id)
    if not provider:
        raise HTTPException(400, f"oauth_provider_unavailable: {provider_id}")

    session_id = secrets.token_urlsafe(32)
    await r.setex(K_SESSION + session_id, SESSION_TTL, json.dumps({
        ..., "api_key": api_key.strip(), "provider": provider_id,
    }))
    params = {
        "client_id": provider["client_id"],
        "redirect_uri": provider["redirect_uri"],
        "response_type": "code",
        "scope": provider["scopes"],
        "state": session_id,
        **provider.get("extra_params", {}),
    }
    return Response(status_code=302,
                    headers={"Location": f"{provider['authorize_url']}?{urlencode(params)}"})
```

Dois caminhos exclusivos, determinados pelo registry:

**A. `auth_type=none`** (alias desconhecido, `resource` ausente, ou MCP marcado como no-auth — ex.: `deepwiki_mcp`):

`_mint_auth_code` grava o code em Redis sob `mcp:code:<code>` (TTL 300s) e retorna `302 Location: <redirect_uri>?code=...&state=...`. Sem segundo hop.

**B. `auth_type=oauth`** (ex.: `linear_mcp` → provider `linear`):

- A sessão Redis (`mcp:session:<id>`, TTL `SESSION_TTL=600s`) guarda o contexto OAuth do cliente original **mais o `provider`** (campo novo). O callback usa esse campo para validar que está tratando o provider certo.
- O `state` enviado ao provider é o `session_id` — não confundir com o `state` original do cliente, que vai dentro do payload da sessão e será reanexado quando o code do shim for emitido.
- `provider["extra_params"]` carrega flags específicas. Para Linear, `{"actor": "user"}` força que ações no upstream sejam registradas como o usuário humano (não como app OAuth).

### 5.6 Callback Linear `/v1/linear/callback`

```python
@app.get("/v1/linear/callback")
async def linear_callback(code: str = "", state: str = "", ...):
    raw = await r.get(K_SESSION + state)
    if not raw:
        raise HTTPException(400, "session_expired")
    await r.delete(K_SESSION + state)
    sess = json.loads(raw)

    if sess.get("provider") != "linear":
        raise HTTPException(400, f"provider_mismatch: {sess.get('provider')!r}")

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
```

A sessão é deletada antes do mint (`r.delete(K_SESSION + state)`) — não há replay possível. O code resultante já carrega os tokens do Linear.

O check `sess["provider"] != "linear"` falha alto se o callback `/v1/linear/callback` for invocado com uma sessão originada de outro provider (cenário futuro quando o registry tiver mais entradas com `auth_type=oauth`). Hoje serve de sentinela para detectar erros de dispatch — quando um novo provider for adicionado, precisará de seu próprio handler de callback.

### 5.7 Token endpoint `/v1/mcp/oauth/token`

```python
@app.post("/v1/mcp/oauth/token")
async def token(grant_type, code, redirect_uri, code_verifier, client_id):
    if grant_type != "authorization_code":
        return ...invalid...
    raw = await r.get(K_CODE + code)
    if not raw:
        return ...invalid_grant...
    await r.delete(K_CODE + code)   # consume code (replay protection)
    rec = json.loads(raw)

    # checks:
    if redirect_uri and redirect_uri != rec["redirect_uri"]:
        return ...invalid_grant...
    if rec["client_id"] and client_id and client_id != rec["client_id"]:
        return ...invalid_grant...
    if not _verify_pkce(code_verifier, rec["code_challenge"]):
        return ...invalid_grant...

    bearer = "cmp_" + secrets.token_urlsafe(48)
    await r.setex(K_BEARER + bearer, BEARER_TTL, json.dumps({...}))
    return JSONResponse({
        "access_token": bearer,
        "token_type": "Bearer",
        "expires_in": BEARER_TTL,
        "scope": rec.get("scope", ""),
    }, headers=TOKEN_NO_CACHE)
```

`_verify_pkce` (`app.py:134-136`):

```python
def _verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == challenge
```

Implementa o método S256 exato do RFC 7636. O cliente armazena `code_verifier` localmente (não é enviado no authorize), e prova posse dele no token endpoint.

Bearer emitido: `cmp_<48 bytes urlsafe base64>` (`token_urlsafe(48)` → ~64 chars). O prefixo `cmp_` permite ao shim distinguir bearers próprios de outros bearers que porventura cheguem (uma master key, por exemplo, NÃO é aceita aqui — o shim só reconhece o que ele mesmo emitiu).

`TOKEN_NO_CACHE = {"Cache-Control": "no-store", "Pragma": "no-cache"}` previne caches intermediários de guardarem o bearer.

### 5.8 Revoke `/v1/mcp/oauth/revoke`

```python
@app.post("/v1/mcp/oauth/revoke")
async def revoke(token: str = Form(...)) -> Response:
    raw = await r.get(K_BEARER + token)
    if raw:
        bind = json.loads(raw)
        rt = bind.get("linear_refresh")
        if rt:
            try:
                await linear_client.post(LINEAR_REVOKE_URL, data={
                    "client_id": LINEAR_CLIENT_ID,
                    "client_secret": LINEAR_CLIENT_SECRET,
                    "token": rt,
                })
            except httpx.HTTPError:
                pass
        await r.delete(K_BEARER + token)
    return Response(status_code=200, headers=TOKEN_NO_CACHE)
```

- Best-effort: tenta revogar o `refresh_token` no Linear; se falhar, prossegue e apaga o binding local de qualquer forma.
- Sempre retorna 200 (não vaza se o bearer existia ou não — mitigação contra enumeration).

### 5.9 Proxy `/mcp{path}` — onde o RBAC acontece

Este é o núcleo do enforcement em runtime:

```python
@app.api_route(
    "/mcp{path:path}",
    methods=["GET", "POST", "OPTIONS", "DELETE", "PUT", "PATCH", "HEAD"],
)
async def mcp_proxy(path: str, request: Request) -> Response:
    upstream_url = f"/mcp{path}" if path else "/mcp/"
    bearer = _bearer_from_header(request.headers.get("authorization", ""))

    # 1. Lookup binding em Redis
    bind: dict[str, Any] | None = None
    if bearer.startswith("cmp_"):
        raw = await r.get(K_BEARER + bearer)
        if raw:
            bind = json.loads(raw)
            # 2. Refresh just-in-time se Linear próximo do expiry
            if bind.get("linear_exp") and bind["linear_exp"] < time.time() + REFRESH_LEAD:
                bind = await _refresh_linear(bearer, bind)

    if not bind:
        return _unauth_response(path)
```

`_unauth_response` retorna 401 com `WWW-Authenticate` apontando para o `oauth-protected-resource` metadata — o cliente MCP usa isso para descobrir o AS e reiniciar o fluxo automaticamente.

#### Branch A — path `/linear*` (bypass direto)

```python
is_linear_path = path.startswith("/linear")
if is_linear_path:
    if not bind.get("linear_access"):
        return _unauth_response(path)
    if not await _key_has_mcp(bind["api_key"], "linear_mcp"):
        return Response(
            content=json.dumps({"error": "forbidden",
                                "error_description": "linear_mcp not permitted for this key"}),
            status_code=403,
            media_type="application/json",
        )
    return await _proxy_to_linear_direct(request, bind)
```

**Por que bypass?** Comentário em `app.py:98-100`:

> Direct Linear MCP proxy. Bypasses LiteLLM because v1.85.0 cannot proxy streamable-http MCP servers (BerriAI/litellm#26700 — AnyIO cancel-scope bug in upstream MCP Python SDK). Streams SSE; no read timeout.

Sequência:

1. **Confirma que o usuário fez OAuth Linear** (`bind["linear_access"]` presente).
2. **Confirma RBAC** via `_key_has_mcp(api_key, "linear_mcp")` — pergunta ao LiteLLM se a virtual key tem `linear_mcp` em `object_permission.mcp_servers`. Cache 30s (`MCP_PERM_TTL`).
3. Se OK: chama `_proxy_to_linear_direct(request, bind)` (linhas 682-721), que faz request para `LINEAR_MCP_URL` (`mcp.linear.app/mcp`) substituindo o header `authorization` pelo `Bearer <linear_access>`.
4. Streamea SSE de volta ao cliente com `aiter_raw()` + `BackgroundTask(upstream.aclose)`.

Importante: nesse branch, o **LiteLLM não é consultado** para a chamada em si — o tráfego MCP vai direto cliente → shim → Linear. O LiteLLM é consultado apenas para a decisão de autorização (`_key_has_mcp`).

#### Branch B — demais paths (via LiteLLM)

```python
headers = {
    k: v
    for k, v in request.headers.items()
    if k.lower() not in HOP_BY_HOP and k.lower() != "authorization"
}
headers["x-litellm-api-key"] = f"Bearer {bind['api_key']}"
if bind.get("linear_access"):
    headers["x-mcp-linear-authorization"] = f"Bearer {bind['linear_access']}"
    headers["x-mcp-linear_mcp-authorization"] = f"Bearer {bind['linear_access']}"

req = mcp_client.build_request(request.method, upstream_url,
                               headers=headers,
                               params=request.query_params,
                               content=body)
upstream = await mcp_client.send(req, stream=True)
```

- **`x-litellm-api-key: Bearer sk-...`** — o LiteLLM usa esse header como a credencial real da chamada. Ele aplica todo o seu RBAC nativo: allow-list de MCPs em `object_permission`, budgets, rate limits, `allowed_routes`. Se a key não tem `deepwiki_mcp` no escopo, o LiteLLM retorna 403 antes mesmo de tocar no upstream.
- **`x-mcp-linear-authorization`** e **`x-mcp-linear_mcp-authorization`** — se houver `linear_access`, são enviados como "passagem opcional" para MCPs que declararem `extra_headers: ["authorization"]`. São prefixados pelo nome do MCP no LiteLLM (`linear_mcp`), permitindo que o LiteLLM associe o header ao servidor certo. Hoje, nenhum dos branches efetivamente exercita esse caminho para o Linear (o bypass do Branch A o evita), mas a infraestrutura está pronta para quando o issue #26700 for resolvido.

Headers `HOP_BY_HOP` — `connection`, `keep-alive`, `transfer-encoding`, `content-length`, `host`, etc. — são removidos antes de repassar, conforme RFC 7230.

#### Tracing Langfuse

Cada chamada `/mcp/*` (em ambos os branches) gera um span Langfuse via `_start_mcp_span`. O nome do span segue o formato `<mcp_name>/<tool_ou_method>`:

| Cenário JSON-RPC | Nome do span |
|---|---|
| `method=tools/call`, `params.name=read_wiki_structure` | `deepwiki_mcp/read_wiki_structure` |
| `method=tools/list` | `deepwiki_mcp/tools/list` |
| `method=initialize` | `deepwiki_mcp/initialize` |
| Body não-JSON ou sem `method` | `deepwiki_mcp/request` |

Outros atributos do span:

- `trace.user_id` = `bearer[:16]` (16 caracteres do compound bearer, pseudo-anônimo).
- `trace.session_id` = `sha256(virtual_key)[:12]` (hash truncado, agrupa sessões da mesma key).
- `metadata.mcp.server`, `metadata.mcp.method`, `metadata.mcp.tool_name`, `metadata.mcp.jsonrpc_id`, `path`, `http_method`, `status_code`.
- `input.body` e `output` carregam o payload bruto da request e a resposta (incluindo SSE quando streaming).

`LANGFUSE_ENABLED` é `True` somente com `LANGFUSE_PUBLIC_KEY` + `LANGFUSE_SECRET_KEY` + SDK instalado. Sem isso, `_start_mcp_span` é no-op.

### 5.10 `_key_has_mcp()` em detalhe

```python
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
```

Pontos relevantes:

- **Defensivo contra mudanças de schema**: aceita `server_name | alias | name | mcp_server_name`. Versões diferentes do LiteLLM nomeiam o campo de forma diferente; o shim coleta todos.
- **Resposta lista OU `{data: [...]}`**: também tolera as duas formas conhecidas.
- **Cache 30s** (`MCP_PERM_TTL`): evita martelar o LiteLLM em sessões com muitas chamadas curtas. O preço é uma janela máxima de 30s entre revogar a permissão no LiteLLM e o shim deixar de aceitar a key — aceitável para a maioria dos cenários, ajustável via env var.
- **Falha → deny**: qualquer exceção ou 4xx vira `allowed = False`. Fail-closed.

---

## 6. Fluxo ponta-a-ponta

Cenário: Alice (membro do team `eng-backend`, com `linear_mcp` e `deepwiki_mcp` no escopo) conecta o Claude Desktop ao gateway pela primeira vez.

### Sequência

1. **Discovery** — Claude Desktop fetch `GET https://<gateway>/.well-known/oauth-authorization-server`. Recebe metadata indicando `authorization_endpoint`, `token_endpoint`, etc.

2. **Registration** — Claude Desktop `POST /register` com `redirect_uris=["claude.ai/oauth/callback"]`. Shim valida o prefixo, gera `client_id=mcp_xxxxx`, armazena em `CLIENTS`, retorna 201.

3. **Authorize (GET)** — Claude Desktop abre browser em:
   ```
   GET /v1/mcp/oauth/authorize
       ?client_id=mcp_xxxxx
       &redirect_uri=https://claude.ai/oauth/callback
       &response_type=code
       &code_challenge=<base64url(sha256(verifier))>
       &code_challenge_method=S256
       &state=<rand>
       &scope=
       &resource=https://<gateway>/mcp/linear_mcp
   ```
   Shim valida tudo, extrai `alias=linear_mcp` de `resource`, renderiza tela HTML pt-BR exibindo o MCP solicitado.

4. **Consent** — Alice cola `sk-virtual-key-abc123` (sua virtual key LiteLLM) e clica "Autorizar". **Não há checkbox** — o shim já sabe que `linear_mcp` exige OAuth pessoal porque `MCP_AUTH_REGISTRY["linear_mcp"]["auth_type"] == "oauth"`.

5. **Authorize (POST) — dispatch automático para o provider** — Shim consulta `MCP_AUTH_REGISTRY["linear_mcp"]` → `provider="linear"` → `OAUTH_PROVIDERS["linear"]`. Cria session Redis `mcp:session:<id>` com `api_key="sk-virtual-key-abc123"`, code_challenge, state original e `provider="linear"`. Responde 302 para:
   ```
   https://linear.app/oauth/authorize
       ?client_id=<LINEAR_CLIENT_ID>
       &redirect_uri=https://<gateway>/v1/linear/callback
       &response_type=code
       &scope=read,write,issues:create,comments:create
       &state=<session_id>
       &actor=user
   ```
   (Para um MCP com `auth_type=none` — ex.: `deepwiki_mcp` — este passo seria substituído por um 302 direto para `claude.ai/oauth/callback?code=...&state=...`, pulando os passos 6-7.)

6. **Aprovação no Linear** — Alice faz login no Linear (se ainda não estava), aprova as permissões. Linear redireciona para:
   ```
   GET /v1/linear/callback?code=lin_code_xxx&state=<session_id>
   ```

7. **Token exchange Linear** — Shim recupera session pelo `state`, valida `sess["provider"] == "linear"` (sentinela contra cross-provider), deleta da Redis, troca `code=lin_code_xxx` por tokens no `LINEAR_TOKEN_URL`. Recebe `{access_token, refresh_token, expires_in}`.

8. **Mint shim auth code** — Shim chama `_mint_auth_code(api_key="sk-...", linear_access=..., linear_refresh=..., linear_exp=...)`. Armazena em Redis `mcp:code:<code>` TTL 300s. Retorna 302 para `https://claude.ai/oauth/callback?code=<shim_code>&state=<state_original>`.

9. **Token exchange shim** — Claude Desktop intercepta o redirect, faz `POST /v1/mcp/oauth/token`:
   ```
   grant_type=authorization_code
   code=<shim_code>
   redirect_uri=https://claude.ai/oauth/callback
   code_verifier=<verifier>
   client_id=mcp_xxxxx
   ```
   Shim consome o code, verifica PKCE (`BASE64URL(SHA256(verifier)) == challenge`), confere `client_id` e `redirect_uri`. Mint `bearer=cmp_<rand>`, armazena binding em Redis `mcp:bearer:cmp_<rand>` TTL 30 dias. Retorna:
   ```json
   {
     "access_token": "cmp_<rand>",
     "token_type": "Bearer",
     "expires_in": 2592000,
     "scope": ""
   }
   ```

10. **Chamada MCP Linear** — Claude Desktop `POST /mcp/linear` com `Authorization: Bearer cmp_<rand>` e payload JSON-RPC (`tools/list`, `tools/call`, etc.):
    - Shim lookup binding (`mcp:bearer:cmp_<rand>`).
    - Se `linear_exp < now + 60s`, chama `_refresh_linear`.
    - `path.startswith("/linear")` → True.
    - `_key_has_mcp("sk-virtual-key-abc123", "linear_mcp")`:
      - Cache `mcp:perm:sk-...:linear_mcp` miss.
      - `GET http://litellm:4000/v1/mcp/server` com `Authorization: Bearer sk-virtual-key-abc123`.
      - LiteLLM responde `{data: [{server_name: "linear_mcp"}, {server_name: "deepwiki_mcp"}]}`.
      - Set names = `{"linear_mcp", "deepwiki_mcp"}`. `"linear_mcp" in names` → True.
      - Cache `1` por 30s.
    - Proxy direto para `https://mcp.linear.app/mcp` com `Authorization: Bearer <linear_access>`.
    - Span Langfuse emitido com nome `linear_mcp/<tool>` (ex.: `linear_mcp/save_issue`).
    - Streamea SSE de resposta.

11. **Chamada MCP DeepWiki** — Claude Desktop `POST /mcp/deepwiki`:
    - Shim lookup binding OK.
    - `path.startswith("/linear")` → False. Branch B.
    - Headers: remove original `authorization`, adiciona `x-litellm-api-key: Bearer sk-virtual-key-abc123` + headers Linear (mesmo que não usados aqui).
    - Proxy para `http://litellm:4000/mcp/deepwiki`.
    - LiteLLM autentica a key, verifica que `deepwiki_mcp` está no escopo, repassa para `https://mcp.deepwiki.com/mcp`.
    - Span Langfuse emitido com nome `deepwiki_mcp/<tool>`.
    - Resposta streamea de volta.

12. **24h depois** — Token Linear expirou. Próxima chamada `/mcp/linear`:
    - `bind.linear_exp - now < 60s` → True.
    - `_refresh_linear(bearer, bind)`: POST `LINEAR_TOKEN_URL` com `grant_type=refresh_token`. Recebe novo `access_token` + (possivelmente) novo `refresh_token`. Atualiza binding em Redis com mesmo `cmp_<rand>`, TTL refrescado para 30d.
    - Claude Desktop **não percebe nada** — o `access_token` externo que ele guarda continua sendo o mesmo `cmp_<rand>`.

13. **Revogação** — Alice clica "Disconnect" no Claude Desktop. Cliente faz `POST /v1/mcp/oauth/revoke` com `token=cmp_<rand>`:
    - Shim tenta revogar `linear_refresh` no Linear (best-effort).
    - Deleta `mcp:bearer:cmp_<rand>` no Redis.
    - Próxima `/mcp/*` com esse bearer → 401.

---

## 7. Camadas adicionais de policy

Além do RBAC por MCP, o stack aplica outras camadas ortogonais:

### 7.1 Budgets

`max_budget` (USD) em janela `budget_duration` (default `30d`). Aplicado por user, por team e por key — o menor vence. LiteLLM retorna 429 ou 403 quando estoura.

### 7.2 Rate limits

`tpm_limit` (tokens por minuto) e `rpm_limit` (requests por minuto). Aplicados na mesma hierarquia. Implementados no LiteLLM via contadores Redis.

### 7.3 `allowed_routes`

Limita quais **grupos de rotas** do LiteLLM a key consegue chamar. Valores conhecidos:

- `llm_api_routes` — `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, etc.
- `mcp_routes` — `/v1/mcp/*` e `/mcp/*`. **Necessário para atravessar o shim**, pois o shim faz `GET /v1/mcp/server` e `POST /mcp/*` no LiteLLM em nome da key.
- `management_routes` — administração; tipicamente reservado a admin keys.
- `info_routes` — info read-only.

Sem `mcp_routes`, o `_key_has_mcp` retorna `False` (LiteLLM responde 403) e mesmo `deepwiki_mcp` no `object_permission` não adianta.

### 7.4 Guardrails Presidio (PII)

`litellm/config.yaml` linhas 57-83 declaram um guardrail `presidio-pii`:

```yaml
guardrails:
  - guardrail_name: "presidio-pii"
    litellm_params:
      guardrail: presidio
      mode: "pre_call"
      default_on: true
      ...
      pii_entities_config:
        PERSON: "MASK"
        CREDIT_CARD: "MASK"
        EMAIL_ADDRESS: "MASK"
        ...
```

Aplica-se a chamadas LLM (`pre_call` mascara PII antes de enviar ao modelo, `output_parse_pii` mascara na resposta). **Não se aplica a chamadas `/mcp/*`** — é uma camada ortogonal à autorização de MCP, focada em proteção de dados na rota LLM.

### 7.5 Cache Redis das respostas LLM

```yaml
cache: true
cache_params:
  type: redis
  host: redis
  port: 6379
  password: os.environ/REDIS_AUTH
```

Cacheia respostas de modelos por hash do prompt+params. Reduz custo. Não afeta MCP (cada chamada MCP é stateful por sessão).

---

## 8. Matriz de variáveis de ambiente

### 8.1 Gateway

| Variável | Origem | Default | Função |
|---|---|---|---|
| `LITELLM_BASE_URL` | `docker-compose.yaml` | `http://litellm:4000` | Endpoint interno do LiteLLM (rede `llmops`). |
| `PUBLIC_BASE_URL` | `.env` (via `MCP_GATEWAY_PUBLIC_URL`) | — | Issuer do AS exibido nos metadata. Deve ser HTTPS público acessível pelo cliente. |
| `REDIS_URL` | compose | `redis://:<REDIS_AUTH>@redis:6379/2` | DB 2, segregado do cache LiteLLM (DB 0). |
| `MCP_BEARER_TTL` | `.env` | 2592000 (30d) | TTL do compound bearer `cmp_*`. |
| `MCP_PERM_TTL` | env | 30 | TTL cache de `_key_has_mcp`. |
| `ALLOWED_REDIRECT_PREFIXES` | `.env` (via `MCP_ALLOWED_REDIRECT_PREFIXES`) | `https://claude.ai/,https://claude.com/,http://localhost,http://127.0.0.1` | Anti open-redirect. CSV. |

### 8.2 Linear OAuth

| Variável | Origem | Função |
|---|---|---|
| `LINEAR_OAUTH_CLIENT_ID` | `.env` | App OAuth registrado em `linear.app → Settings → API → OAuth Applications`. |
| `LINEAR_OAUTH_CLIENT_SECRET` | `.env` | Secret do mesmo app. |
| `LINEAR_REDIRECT_URI` | `.env` | DEVE bater **exatamente** com o cadastrado no app Linear. Ex: `https://<gateway>/v1/linear/callback`. |
| `LINEAR_OAUTH_SCOPES` | `.env` | Default `read,write,issues:create,comments:create`. |
| `LINEAR_AUTHORIZE_URL` | env | Default `https://linear.app/oauth/authorize`. |
| `LINEAR_TOKEN_URL` | env | Default `https://api.linear.app/oauth/token`. |
| `LINEAR_REVOKE_URL` | env | Default `https://api.linear.app/oauth/revoke`. |
| `LINEAR_MCP_URL` | env | Default `https://mcp.linear.app/mcp`. Endpoint para o bypass direto. |

`LINEAR_ENABLED` (booleano interno) é `True` somente se `CLIENT_ID`, `CLIENT_SECRET` e `REDIRECT_URI` estiverem todos preenchidos. Quando falso, `OAUTH_PROVIDERS["linear"]` não é registrado, e qualquer authorize para `linear_mcp` falha com `400 oauth_provider_unavailable: linear`.

### 8.3 LiteLLM

| Variável | Origem | Função |
|---|---|---|
| `LITELLM_MASTER_KEY` | `.env` | Root da admin UI e da API admin. **Bypassa RBAC.** |
| `LITELLM_SALT_KEY` | `.env` | Salt para hash de keys em Postgres. |
| `DATABASE_URL` | compose | `postgresql://...@postgres:5432/<LANGFUSE_DB|POSTGRES_DB>`. |
| `GEMINI_API_KEY` / `OPENROUTER_API_KEY` | `.env` | Credenciais dos provedores LLM. |
| `REDIS_AUTH` | `.env` | Senha do Redis (compartilhada). |
| `PRESIDIO_ANALYZER_API_BASE` / `PRESIDIO_ANONYMIZER_API_BASE` | compose | Endpoints do guardrail PII. |
| `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` / `LANGFUSE_HOST` | `.env` | Observabilidade. Habilitam o tracing por span `<mcp_name>/<tool>` em cada chamada `/mcp/*`. Sem essas variáveis, o gateway opera normalmente — só não envia spans. **Atenção**: variáveis de shell exportadas (ex.: `export LANGFUSE_PUBLIC_KEY=...` no `.zshrc`) sobrepõem o `.env` no `docker compose`. Se o gateway loga `Failed to export span batch code: 401`, conferir `docker compose config | grep LANGFUSE_PUBLIC_KEY` contra o `.env` e desexportar do shell se divergir. |

---

## 9. Modelo de ameaça e mitigações

### 9.1 Open redirect

**Ameaça**: atacante registra um cliente com `redirect_uris=["https://evil.com/"]` e induz vítima a autorizar; recebe o code em domínio controlado.

**Mitigação**: `_validate_redirect_uri` (linhas 119-131):

```python
def _validate_redirect_uri(redirect_uri: str) -> None:
    parsed = urlparse(redirect_uri)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "invalid_redirect_uri")
    if parsed.fragment:
        raise HTTPException(400, "invalid_redirect_uri")
    for prefix in ALLOWED_REDIRECT_PREFIXES:
        if redirect_uri.startswith(prefix):
            return
    raise HTTPException(400, f"redirect_uri not allowed: {redirect_uri}")
```

Só prefixos da allow-list passam. Aplicado tanto em `/register` quanto em `/v1/mcp/oauth/authorize` (GET e POST).

### 9.2 PKCE downgrade

**Ameaça**: cliente malicioso ou intermediário força `code_challenge_method=plain` ou ausência, para que um vazamento do code seja suficiente para trocar por token.

**Mitigação**: o metadata anuncia somente `S256`, e `authorize_get` recusa qualquer outra coisa (`app.py:363`):

```python
if code_challenge_method != "S256":
    raise HTTPException(400, "code_challenge_required (S256)")
if not code_challenge:
    raise HTTPException(400, "code_challenge_required")
```

### 9.3 Vazamento da virtual key

**Ameaça**: virtual key roubada permite usar todos os MCPs e modelos no escopo da key, contornando o consent.

**Mitigação**:

- A virtual key fica **server-side** no binding Redis. O cliente nunca a recebe — só vê o bearer `cmp_*` opaco.
- Revogação da key na admin do LiteLLM derruba imediatamente o `_key_has_mcp` (após no máximo 30s de cache) e quebra `x-litellm-api-key` no Branch B (LiteLLM retorna 401).
- Recomenda-se rotacionar virtual keys periodicamente e/ou usar keys de curta duração (`duration: "7d"`).

### 9.4 Replay de authorization code

**Ameaça**: um `code` interceptado é trocado por token mais de uma vez.

**Mitigação**:

- `r.delete(K_CODE + code)` é chamado antes do mint do bearer, removendo o code do Redis. TTL adicional de 300s.
- A binding entre o code e seu `code_challenge` impede que outro cliente troque o code (precisa do `code_verifier` correto).

### 9.5 Reuso cross-client / token theft

**Ameaça**: bearer `cmp_*` exfiltrado de uma máquina pode ser usado por outro cliente.

**Mitigação**: bearer não é proof-of-possession (não há mTLS nem DPoP nesta versão). A proteção é:

- TTL de 30 dias (configurável em `MCP_BEARER_TTL`).
- Endpoint `/v1/mcp/oauth/revoke`.
- Recomenda-se diminuir `MCP_BEARER_TTL` em ambientes com modelo de ameaça mais alto.

### 9.6 MCP allow-list bypass via cache stale

**Ameaça**: admin revoga `linear_mcp` da key no LiteLLM; janela de 30s do `MCP_PERM_TTL` ainda permite chamadas.

**Mitigação**:

- Cache TTL de 30s é configurável. Para revogação instantânea, definir `MCP_PERM_TTL=0` (cada chamada `/mcp/linear` faz round-trip ao LiteLLM).
- Em emergência: `redis-cli -a $REDIS_AUTH -n 2 DEL mcp:perm:<key>:<server>` força refresh.
- Para revogação imediata mesmo em Branch B, deletar `mcp:bearer:<bearer>` invalida o bearer todo.

### 9.7 Fixation de session (Linear)

**Ameaça**: atacante força vítima a usar um `session_id` previsível para sequestrar o callback Linear.

**Mitigação**: `session_id = secrets.token_urlsafe(32)` (256 bits de entropia) e deletado após uso (`r.delete(K_SESSION + state)`).

### 9.8 Vazamento de logs

**Ameaça**: virtual key ou tokens Linear em stdout/stderr do container.

**Mitigação**: o shim não loga nem `bind`, nem `api_key`, nem `linear_access`. Exceções HTTP retornam status + mensagem sem ecoar a credencial. Recomenda-se verificar configuração de logs adicionais (uvicorn access logs filtrar `authorization` header — não é gerado por padrão).

---

## 10. Operação e troubleshooting

### 10.1 Subir o stack

```bash
cp .env.example .env
# editar .env com segredos reais (LITELLM_MASTER_KEY, POSTGRES_PASSWORD, etc.)
docker compose up -d
# aguardar healthchecks:
docker compose ps
```

Health do gateway:

```bash
curl -s https://<gateway>/health
# {"ok":true,"linear":true}   se Linear configurado
# {"ok":true,"linear":false}  se sem credenciais Linear
```

Metadata OAuth:

```bash
curl -s https://<gateway>/.well-known/oauth-authorization-server | jq
```

### 10.2 Criar Team via API

```bash
curl -X POST http://localhost:4000/team/new \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "team_alias": "eng-backend",
    "models": ["gemini-3-flash", "minimax-m2.5"],
    "max_budget": 100.0,
    "budget_duration": "30d",
    "object_permission": {
      "mcp_servers": ["deepwiki_mcp", "linear_mcp"]
    }
  }'
```

### 10.3 Criar internal user

```bash
curl -X POST http://localhost:4000/user/new \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "alice@example.com",
    "user_role": "internal_user",
    "teams": ["<team_id>"]
  }'
```

### 10.4 Gerar virtual key com MCP scope explícito

```bash
curl -X POST http://localhost:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice@example.com",
    "team_id": "<team_id>",
    "models": ["gemini-3-flash"],
    "max_budget": 5.0,
    "budget_duration": "30d",
    "duration": "30d",
    "allowed_routes": ["llm_api_routes", "mcp_routes"],
    "object_permission": {
      "mcp_servers": ["deepwiki_mcp"]
    }
  }'
```

A resposta inclui `key`. Entregar à Alice (canal seguro).

### 10.5 Inspecionar bindings no Redis

```bash
docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 KEYS 'mcp:bearer:*'
docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 GET 'mcp:bearer:cmp_xxx'
docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 TTL 'mcp:bearer:cmp_xxx'
```

Cache de permissões:

```bash
docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 KEYS 'mcp:perm:*'
```

Sessions OAuth em progresso:

```bash
docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 KEYS 'mcp:session:*'
```

### 10.6 Revogar manualmente

```bash
# Revoga um bearer específico:
docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 DEL 'mcp:bearer:cmp_xxx'

# Limpa todo o cache de permissões (força re-check em todas chamadas):
docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 --scan --pattern 'mcp:perm:*' | xargs -r docker compose exec redis redis-cli -a $REDIS_AUTH -n 2 DEL
```

Para revogar a virtual key inteira no LiteLLM (efeito mais amplo):

```bash
curl -X POST http://localhost:4000/key/delete \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -d '{"keys": ["sk-virtual-key-abc123"]}'
```

### 10.7 Sintomas comuns

| Sintoma | Causa provável | Diagnóstico |
|---|---|---|
| `401 unauthorized` em `/mcp/*` com `WWW-Authenticate` | Bearer expirado, ou refresh Linear falhou | `redis-cli ... GET mcp:bearer:<bearer>` retorna `(nil)` |
| `403 forbidden linear_mcp not permitted for this key` | Virtual key não tem `linear_mcp` no `object_permission` do Team/User/Key | `curl /v1/mcp/server` com a key — `linear_mcp` ausente da resposta |
| `400 invalid_grant` em `/v1/mcp/oauth/token` | PKCE não bate, code já foi consumido, ou TTL de 300s expirou | Cliente provavelmente regenerou o `code_verifier` entre authorize e token |
| `400 invalid_redirect_uri` | `redirect_uri` fora da allow-list `ALLOWED_REDIRECT_PREFIXES` | Editar `.env` e reiniciar gateway |
| Tela de consent mostra `MCP genérico` em vez do alias | Cliente não enviou `resource` na URL, ou alias não está em `MCP_AUTH_REGISTRY` | Inspecionar URL do authorize: deve conter `&resource=https://<gateway>/mcp/<alias>` |
| `400 oauth_provider_unavailable: linear` | `auth_type=oauth` no registry mas env do provider faltando | Conferir `LINEAR_OAUTH_CLIENT_ID`/`_SECRET`/`REDIRECT_URI` no `.env`; reiniciar gateway |
| `400 provider_mismatch: 'X'` no `/v1/linear/callback` | Sessão Redis foi criada para outro provider, mas Claude bateu no callback Linear | Bug interno: cliente forjando state, ou novo provider sem callback dedicado |
| `400 session_expired` no callback OAuth | Demorou mais de 600s no authorize do provider; ou container reiniciou | Aumentar `SESSION_TTL` no código, ou refazer o fluxo |
| Linear retorna `invalid_redirect_uri` | `LINEAR_REDIRECT_URI` no `.env` ≠ valor cadastrado no app Linear | Conferir caractere por caractere, inclusive trailing slash |
| 403 do LiteLLM em `/mcp/deepwiki` | `allowed_routes` não inclui `mcp_routes`, ou `deepwiki_mcp` fora do `object_permission` | Conferir Team/User/Key no admin UI |

### 10.8 Logs

```bash
docker compose logs -f mcp-gateway
docker compose logs -f litellm
```

LiteLLM tem opção de tracing detalhado via `LITELLM_DEBUG=1` na variável de ambiente (cuidado: logs verbosos).

---

## 11. Limites conhecidos

### 11.1 `CLIENTS` in-memory

`mcp-gateway/app.py:109` define `CLIENTS: dict[str, dict[str, Any]] = {}`. Restart do container apaga registros. Mitigação: clientes legítimos (Claude Desktop) detectam que o `client_id` ficou inválido e refazem o registration automaticamente — custo zero para o usuário.

**Para tornar persistente** (futuro): mover `CLIENTS` para Redis com TTL longo ou para Postgres.

### 11.2 BerriAI/litellm#26700 — bypass do Linear

Linear MCP usa transporte `streamable-http` (SSE chunked). LiteLLM v1.85.0 tem bug de cancelamento de scope AnyIO no SDK MCP Python que faz o proxy travar. Workaround atual: branch `is_linear_path` em `mcp_proxy` desvia o tráfego para `LINEAR_MCP_URL` diretamente, sem passar pelo LiteLLM. Decisão de autorização (`_key_has_mcp`) continua sendo feita via LiteLLM — apenas o tráfego de payload é bypassado.

Quando o upstream corrigir:

- Remover o branch `is_linear_path` em `mcp-gateway/app.py:746`.
- Remover `_proxy_to_linear_direct` e o `linear_mcp_client`.
- `linear_mcp` em `config.yaml` já tem `extra_headers: ["authorization"]` configurado — o LiteLLM passará a propagar o token Linear automaticamente.
- Branch B já envia os headers `x-mcp-linear-authorization` e `x-mcp-linear_mcp-authorization`, prontos para esse cenário.

### 11.3 OAuth pessoal — generalização parcial concluída

O dispatch (authorize POST → provider authorize URL) **já é genérico** desde a introdução de `MCP_AUTH_REGISTRY` + `OAUTH_PROVIDERS` (§5.2). O que ainda é Linear-específico:

- **Handler de callback**: existe apenas `/v1/linear/callback`. Cada provider precisa do seu próprio porque o token exchange tem formato proprietário (corpo, headers, parsing da resposta).
- **Refresh**: `_refresh_linear` é hardcoded. Linear rotaciona `refresh_token`; Notion não; Slack tem regras próprias. Não dá pra unificar sem abstração.
- **Campos do binding**: `linear_access`/`linear_refresh`/`linear_exp` no JSON do `mcp:bearer:*`. Para múltiplos providers simultâneos, precisa migrar para `oauth.<provider>.{access,refresh,exp}`.
- **Header de propagação no Branch B**: `x-mcp-linear-authorization` e `x-mcp-linear_mcp-authorization` são hardcoded. Para Notion/Slack/etc., seria `x-mcp-<alias>-authorization` derivado do alias do MCP.
- **Branch A (bypass)**: `is_linear_path` e `_proxy_to_linear_direct` existem por causa do bug #26700. Se outro provider sofrer o mesmo problema, precisa replicar.

Checklist para adicionar **Notion** (exemplo concreto):

1. Adicionar variáveis `NOTION_OAUTH_CLIENT_ID/_SECRET/_REDIRECT_URI/_SCOPES` em `.env` e propagar via `docker-compose.yaml`.
2. Acrescentar bloco `if NOTION_ENABLED: OAUTH_PROVIDERS["notion"] = {...}` em `app.py`.
3. Acrescentar `"notion_mcp": {"auth_type": "oauth", "provider": "notion"}` em `MCP_AUTH_REGISTRY` (assumindo que o LiteLLM expõe `notion_mcp` em `mcp_servers`).
4. Implementar `@app.get("/v1/notion/callback")` espelhando `linear_callback`, com o assert `sess.get("provider") != "notion"` para falhar alto se chegar payload errado.
5. Adicionar campos `notion_access`/`notion_refresh`/`notion_exp` ao `_mint_auth_code` e ao binding Redis.
6. Implementar `_refresh_notion(bearer, bind)`.
7. No proxy, se Notion sofrer um bug equivalente ao #26700, adicionar `is_notion_path` e `_proxy_to_notion_direct`. Caso contrário, basta o Branch B com `extra_headers: ["authorization"]` em `notion_mcp` no `config.yaml` do LiteLLM.

Refatoração futura recomendada: extrair "upstream provider" como abstração (`UpstreamOAuthProvider`), parametrizando token endpoint, callback handler e refresh — eliminando o trabalho repetitivo dos itens 4-6 acima. Isso transformaria o checklist em "adicione uma linha em `OAUTH_PROVIDERS`".

### 11.4 Sem rotação de bearer

Bearer `cmp_*` é emitido com TTL fixo (30d default) e não rotaciona durante a vida. Não há suporte a `refresh_token` no token endpoint do shim (apenas `authorization_code`). Implicações:

- Após `BEARER_TTL`, o cliente precisa refazer o fluxo OAuth completo (com nova tela de consent).
- Não há revogação automática se a virtual key for revogada — depende do `_key_has_mcp` falhar (com até 30s de delay) e o LiteLLM rejeitar `x-litellm-api-key` no Branch B.

Mitigação se isso virar problema: adicionar suporte a `refresh_token` no `/v1/mcp/oauth/token` para rotacionar o `cmp_*` periodicamente; ou diminuir `BEARER_TTL` para horas.

### 11.5 Cache `mcp:perm:` indexado por virtual key bruta

A chave de cache `mcp:perm:<api_key>:<server>` inclui a virtual key em claro. Isso significa que quem ler o Redis (já protegido por `REDIS_AUTH`, isolado em network bridge) consegue enumerar keys em uso.

Mitigação futura: usar hash da key (`sha256(api_key)[:32]`) como índice do cache.

---

## Apêndice — Mapa rápido de arquivos

| Arquivo | Responsabilidade |
|---|---|
| `litellm/config.yaml` | Modelos LLM, defaults de internal user, MCP servers, aliases, guardrails Presidio, cache Redis. |
| `mcp-gateway/app.py` | Shim OAuth 2.1 completo: metadata, registration, authorize, callback Linear, token, revoke, proxy `/mcp/*`. |
| `mcp-gateway/Dockerfile` | Python 3.12-slim + uvicorn em `:9100`. |
| `mcp-gateway/requirements.txt` | `fastapi`, `uvicorn[standard]`, `httpx`, `python-multipart`, `redis`. |
| `docker-compose.yaml` | Orquestração: postgres, redis, clickhouse, minio, presidio, langfuse, litellm, mcp-gateway. |
| `.env.example` | Template de credenciais e configurações de runtime. |
