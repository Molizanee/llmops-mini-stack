# MCP Gateway — Alternativas Prontas

**Data**: 2026-05-20
**Contexto**: avaliação de gateways open source que poderiam substituir total ou parcialmente o shim FastAPI customizado em `mcp-gateway/app.py`.

---

## 1. O que o shim atual faz

Antes de comparar, fixar o escopo exato do `mcp-gateway/app.py` (≈1000 LoC):

| Capacidade | Detalhe |
|---|---|
| OAuth 2.1 Authorization Server | `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/register` (DCR), `/v1/mcp/oauth/authorize` (GET form + POST), `/v1/mcp/oauth/token`, `/v1/mcp/oauth/revoke` |
| PKCE S256 | verifica `code_challenge` contra `code_verifier` |
| Compound bearer | bearer opaco `cmp_…` ligando chave virtual LiteLLM + tokens OAuth Linear por usuário |
| Form de consentimento | HTML pt-BR pedindo chave virtual + checkbox Linear |
| Upstream OAuth (Linear) | troca authorization_code, armazena refresh_token, auto-refresh em janela de 60s antes do expiry (Linear TTL 24h) |
| Persistência | Redis (`mcp:session:*`, `mcp:code:*`, `mcp:bearer:*`) |
| Proxy `/mcp/*` | injeta `x-litellm-api-key` + `x-mcp-linear-authorization`, streaming bidirecional |
| Bypass especial Linear | `/mcp/linear/*` vai direto pro `mcp.linear.app` (LiteLLM 1.85.0 quebra streamable-http — BerriAI/litellm#26700) |
| Cache de permissão | `mcp:perm:*` TTL 30s consulta `/v1/mcp/server` no LiteLLM por chave virtual |
| Validação redirect_uri | allowlist de prefixos (claude.ai, claude.com, localhost) |
| Tracing | spans Langfuse por request com `mcp.server`, `mcp.method`, `mcp.tool_name`, `mcp.jsonrpc_id`, status_code, user_id, session_id |

Funções 1-a-1 que precisam estar no substituto.

---

## 2. Matriz de alternativas

| Gateway | Licença | OAuth 2.1 AS | PKCE | DCR | Compound tokens / upstream OAuth | Langfuse | Auto-refresh upstream | Custom consent UI | Substitui LiteLLM? |
|---|---|---|---|---|---|---|---|---|---|
| **LiteLLM nativo (v1.77.5+)** | MIT | sim | sim (1.85+ via PR #15720) | sim | upstream-delegated (cliente faz PKCE direto com upstream) | via callback | depende do upstream | não | já é |
| **IBM ContextForge** (`IBM/mcp-context-forge`) | Apache 2.0 | sim | sim (RFC 7636) | sim (RFC 7591) | tokens upstream por usuário + `X-Upstream-Authorization` | sim (oficial) | sim | parcial (config) | não, federa |
| **Docker MCP Gateway** | Apache 2.0 | DCR helpers library | sim | sim | OAuth por servidor, secrets injection em containers | OTel | sim | não | não |
| **Kong AI Gateway + plugins AI MCP Proxy / OAuth2** | mixed (Kong Gateway OSS / Enterprise) | sim | sim | parcial | introspection + JWKS, token validation by audience | OTel | depende plugin | sim (developer portal) | parcial (AI Proxy) |
| **Solo agentgateway** | Apache 2.0 | sim | sim | parcial | OAuth2 proxy integration (Keycloak), MCP authn | sim (oficial, integração Langfuse documentada) | sim | depende IdP | não |
| **Lunar MCPX** | open core (core Apache 2.0) | sim (control plane) | sim | sim | identity-aligned attribution, credential isolation | OTel | sim | sim | não |
| **Bifrost (Maxim)** | Apache 2.0 | sim | sim | sim | OAuth com PKCE + auto-refresh, tool filtering por virtual key | OTel + nativo | sim | parcial | é AI gateway (concorre com LiteLLM) |
| **Lasso MCP Gateway** | Apache 2.0 | não (foco em segurança) | n/a | n/a | plugin Presidio PII, guardrails | logs | n/a | não | não |
| **Microsoft MCP Gateway (AKS)** | MIT | Entra ID | via Entra | n/a | Entra ID OIDC + RBAC | Azure Monitor | sim | não (Entra) | não |
| **Obot** | Apache 2.0 | sim | sim | sim | Okta/Entra/GitHub/Google, token exchange | logs | sim | sim | não |
| **atrawog/mcp-oauth-gateway** | MIT | sim | sim | sim | GitHub IdP, adiciona OAuth a qualquer MCP sem modificar | básico | sim | parcial | não |
| **akshay5995/mcp-oauth-gateway** | MIT | sim | sim | sim | transparente | básico | sim | parcial | não |

---

## 3. Análise das opções mais relevantes

### 3.1 LiteLLM nativo (upstream-delegated auth)

Desde v1.77.5 (out/2025) e fix de PKCE em PR #15720, LiteLLM aceita `auth_type: oauth2` + `delegate_auth_to_upstream: true` por servidor MCP. Cliente faz PKCE direto com o upstream (Linear, GitHub, etc.); LiteLLM repassa o `Authorization: Bearer` sem inspecionar.

**Prós**:
- zero código próprio
- já está no stack
- mantém streaming

**Contras** (porque foi feito o shim):
- spend tracking + per-key rate limits + guardrails que dependem de `user_api_key_auth.user_id` **não rodam** quando bypass está ativo — auditoria precisa vir do upstream
- não dá pra combinar "chave virtual LiteLLM" + "OAuth Linear pessoal" num único bearer pro cliente
- não suporta o caso "Claude Desktop vê UM issuer só" — força o cliente a discoverr o issuer upstream
- LiteLLM 1.85.0 tem bug streamable-http no proxy MCP (BerriAI/litellm#26700), que é exatamente a razão do bypass `_proxy_to_linear_direct`

Veredito: **não cobre o requisito de compound token + atribuição por usuário no LiteLLM**.

### 3.2 IBM ContextForge (mcp-context-forge)

Apache 2.0, 3.5k+ stars, federa MCP/A2A/REST/gRPC. Implementa DCR (RFC 7591) + PKCE (RFC 7636). Tokens OAuth armazenados por gateway+usuário, expostos via `X-Upstream-Authorization`. Suporta GitHub, Google, IBM Security Verify, Keycloak, Entra ID, Auth0, Authentik, Okta. Integração Langfuse oficial documentada.

**Prós**:
- cobre 90% do que o shim faz, em produto mantido
- Langfuse first-class
- multi-IdP sem código

**Contras**:
- form de consentimento próprio (pt-BR Arara Tech) não trivial de portar
- não é "shim em frente do LiteLLM" — substitui o role de gateway, então duplica funções (registry, federation) que LiteLLM já faz
- adiciona Postgres + componentes adicionais

Veredito: **opção mais próxima funcionalmente**, mas exige decidir se ContextForge **substitui** LiteLLM como gateway MCP ou roda **na frente** dele.

### 3.3 Solo agentgateway

Apache 2.0, escrito em Rust. OAuth 2.0 + JWT + API keys, RBAC com CEL, OpenTelemetry (logs/metrics/traces) nativo. Post oficial Solo + post oficial agentgateway descrevem integração Langfuse — emite spans MCP (tool discovery, execution, backend latency).

**Prós**:
- performance (Rust)
- Langfuse documentado
- Gateway API K8s

**Contras**:
- compound token (chave LiteLLM + token upstream no mesmo bearer) não é o modelo dele — modelo é IdP único (Keycloak)
- requer IdP externo
- curva de aprendizado CEL

Veredito: **bom se aceitar Keycloak como IdP único** e migrar Linear OAuth para "external IdP federado".

### 3.4 Kong AI Gateway + AI MCP OAuth2 / AI MCP Proxy

Kong Gateway 3.12+ adiciona plugins `ai-mcp-proxy` e `ai-mcp-oauth2`. OAuth2 valida que o `access_token` foi emitido para o MCP server alvo (audience binding). Suporta introspection ou JWKS.

**Prós**:
- maturidade de API gateway industrial
- governance robusto
- portal developer

**Contras**:
- pesado pro escopo (Kong + Postgres/declarative + plugin licenses para alguns recursos)
- compound token customizado não é nativo — precisaria plugin Lua próprio
- maioria dos recursos MCP avançados em Kong Enterprise

Veredito: **overkill** pra escopo atual; vale só se Kong já estiver na infra Arara Tech.

### 3.5 Docker MCP Gateway

Apache 2.0. Lifecycle de containers MCP, DCR helpers em lib separada (`docker/mcp-gateway-oauth-helpers`), secrets injection.

**Prós**:
- isolamento por container (signed images)
- OAuth flow embutido no Docker Desktop

**Contras**:
- modelo é "rodar MCP servers locais" — não casa com mix "LiteLLM-hosted + remote MCP (mcp.linear.app)"
- sem Langfuse nativo

Veredito: **escopo diferente** (devbox / desktop integration).

### 3.6 Bifrost (Maxim)

Go, Apache 2.0. 11µs overhead @ 5k rps. OAuth com PKCE + auto-refresh, tool filtering por virtual key, semantic cache, code mode.

**Prós**:
- performance
- OAuth + virtual key são primeiros classes no design
- substitui parcialmente LiteLLM (multi-provider routing)

**Contras**:
- substitui LiteLLM em vez de ficar na frente — decisão maior
- ecossistema menor que LiteLLM

Veredito: **avaliar se um dia substituir LiteLLM** virar opção.

### 3.7 Mini-gateways focados em OAuth shim

- `atrawog/mcp-oauth-gateway`: OAuth 2.1 AS com GitHub IdP
- `akshay5995/mcp-oauth-gateway`: idem, transparente

**Prós**: escopo idêntico ao shim atual (adiciona OAuth na frente de MCP)
**Contras**: IdP único (geralmente GitHub), sem compound token, sem Langfuse, comunidade pequena

Veredito: **interessantes como referência** pra simplificar o shim, mas não cobrem compound token.

---

## 4. Recomendação

| Cenário | Opção |
|---|---|
| Manter LiteLLM como gateway central e querer **zero código próprio** | **LiteLLM upstream-delegated** + aceitar perda de spend tracking e atribuição por usuário |
| Substituir o shim por produto mantido com **paridade funcional** | **IBM ContextForge** — porta a tela pt-BR + decide se federa LiteLLM atrás ou substitui |
| Padronizar em K8s + Gateway API + Keycloak | **Solo agentgateway** + Keycloak federando Linear |
| Empresa já usa Kong | **Kong AI Gateway 3.12** + plugin AI MCP OAuth2 |
| Manter shim atual mas **encolher** | usar `mcp-context-forge` como dep e enxergar nele só o módulo OAuth AS, mantendo o form de consentimento próprio |

**Recomendação principal**: o shim atual é justificado **porque combina compound token + form pt-BR + bypass Linear (LiteLLM bug)**. Nenhuma opção pronta cobre os três simultaneamente. A migração faz sentido só se:

1. LiteLLM corrigir `#26700` (remove bypass Linear) **e**
2. Aceitar perder compound token a favor de `delegate_auth_to_upstream` **ou** migrar IdP único pra Keycloak

Antes disso, o shim de ≈1000 LoC é o caminho mais barato pro requisito.

---

## 5. Fontes

- [Best Open Source MCP Gateways 2026 — Lunar](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026)
- [10 Best MCP Gateways — Composio](https://composio.dev/content/best-mcp-gateway-for-developers)
- [13 Best MCP Gateways for Enterprise Teams — Obot](https://obot.ai/blog/the-13-best-mcp-gateways-for-enterprise-teams/)
- [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
- [docker/mcp-gateway-oauth-helpers](https://github.com/docker/mcp-gateway-oauth-helpers)
- [Connect to Remote MCP Servers with OAuth — Docker](https://www.docker.com/blog/connect-to-remote-mcp-servers-with-oauth/)
- [IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge)
- [ContextForge OAuth 2.0 Integration](https://ibm.github.io/mcp-context-forge/manage/oauth/)
- [ContextForge Langfuse Integration](https://ibm.github.io/mcp-context-forge/manage/observability/langfuse/)
- [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway)
- [Lasso Launches Open Source MCP Security Gateway](https://www.lasso.security/resources/lasso-releases-first-open-source-security-gateway-for-mcp)
- [Kong AI MCP OAuth2 plugin](https://developer.konghq.com/plugins/ai-mcp-oauth2/)
- [Kong AI MCP Proxy plugin](https://developer.konghq.com/plugins/ai-proxy/)
- [Kong AI/MCP Gateway technical breakdown](https://medium.com/@claudioacquaviva/kong-ai-mcp-gateway-and-kong-mcp-server-technical-breakdown-13420f610ee6)
- [LiteLLM MCP OAuth](https://docs.litellm.ai/docs/mcp_oauth)
- [LiteLLM v1.77.5 — MCP OAuth 2.0 Support](https://docs.litellm.ai/release_notes/v1-77-5)
- [LiteLLM PR #15720 — PKCE fix](https://github.com/BerriAI/litellm/pull/15720)
- [agentgateway/agentgateway](https://github.com/agentgateway/agentgateway)
- [agentgateway OAuth2 proxy integration](https://agentgateway.dev/docs/standalone/main/tutorials/oauth2-proxy/)
- [agentgateway Langfuse integration](https://agentgateway.dev/blog/2026-02-17-agentgateway-langfuse-integration/)
- [Open Source LLM Observability — agentgateway + Langfuse](https://www.solo.io/blog/llm-observability-agentgateway-langfuse)
- [Lunar MCPX product page](https://www.lunar.dev/product/mcp)
- [atrawog/mcp-oauth-gateway](https://github.com/atrawog/mcp-oauth-gateway)
- [akshay5995/mcp-oauth-gateway](https://github.com/akshay5995/mcp-oauth-gateway)
- [Langfuse MCP Tracing docs](https://langfuse.com/docs/observability/features/mcp-tracing)
