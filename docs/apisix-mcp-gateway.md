# APISIX na borda + `mcp-gateway` como BFF/Authorization Server

> Documento técnico em pt-BR que responde se dá para colapsar a proteção do stack MCP num único componente. A conclusão é objetiva: **não dá**. APISIX (borda) e `mcp-gateway` :9100 (BFF + OAuth 2.1 Authorization Server) resolvem problemas de camadas diferentes; nenhum dos dois sozinho atende a todos os requisitos. A arquitetura recomendada combina os dois — APISIX cuidando das preocupações transversais de perímetro e `mcp-gateway` cuidando da lógica app-aware de MCP/OAuth — com o LiteLLM :4000 permanecendo como fonte da verdade do RBAC.

---

## Sumário

1. [Contexto](#1-contexto)
2. [Papéis dos dois componentes (+ LiteLLM)](#2-papéis-dos-dois-componentes--litellm)
3. [Por que NÃO usar só APISIX](#3-por-que-não-usar-só-apisix)
4. [Por que NÃO usar só o `mcp-gateway`](#4-por-que-não-usar-só-o-mcp-gateway)
5. [Por que combinar (a recomendação)](#5-por-que-combinar-a-recomendação)
6. [Arquitetura alvo](#6-arquitetura-alvo)
7. [Integração APISIX (config)](#7-integração-apisix-config)
8. [O que NÃO muda ao colocar APISIX na frente](#8-o-que-não-muda-ao-colocar-apisix-na-frente)
9. [Limitações / riscos](#9-limitações--riscos)
10. [Referências](#10-referências)

---

# 1. Contexto

Este documento responde a uma pergunta concreta de engenharia: *"dá pra dropar o `mcp-gateway` e usar só APISIX na frente do LiteLLM, conectando os custom connectors do Claude Desktop direto aos endpoints MCP do LiteLLM, mantendo RBAC mcp/team e traces por usuário?"*

A motivação é legítima: reduzir o número de componentes da stack, evitar manter um serviço FastAPI de ~1000 LoC e usar um gateway de borda maduro (APISIX) como única camada de proteção na frente do LiteLLM. A hipótese era que APISIX, sendo um API gateway completo, pudesse absorver o papel do `mcp-gateway`.

A conclusão é que **não dá para colapsar num componente só** — APISIX e `mcp-gateway` resolvem problemas diferentes e nenhum dos dois sozinho atende a todos os requisitos:

- **APISIX não é um OAuth 2.1 Authorization Server.** Seu plugin `openid-connect` é *relying party* (validador de token que delega a um IdP externo). APISIX não expõe `/authorize`, `/token`, `/register`, não faz Dynamic Client Registration (RFC 7591) e não publica `.well-known/oauth-authorization-server` nem `.well-known/oauth-protected-resource`. O conector remoto do Claude Desktop exige exatamente esse conjunto de endpoints (ver §3 e a Spec MCP).
- **LiteLLM não consegue ser exposto direto** para tráfego MCP streamable-http (bug #26700, ver `docs/rbac-mcp.md` §11), e não emite os spans MCP-aware com resolução de e-mail/sessão que o `mcp-gateway` produz.
- **O RBAC mcp/team continua vivendo no LiteLLM** (`object_permission.mcp_servers`), mas precisa de um BFF que o ecoe ao conector e materialize o consent OAuth.

A arquitetura-alvo (§6) **combina os dois**: APISIX na borda (preocupações transversais) e `mcp-gateway` :9100 como BFF + Authorization Server (lógica app-aware), seguindo o padrão de defesa em camadas / Backends for Frontends.

# 2. Papéis dos dois componentes (+ LiteLLM)

Cada componente ocupa uma camada distinta. **APISIX** é o gateway de borda: cuida das preocupações transversais a *toda* requisição (TLS, rate-limit, WAF, IP allow/deny, quotas, observabilidade de tráfego, CORS). **`mcp-gateway` :9100** é o BFF + OAuth 2.1 Authorization Server: cuida da lógica específica do conector MCP (DCR, PKCE S256, `.well-known`, consent, bearer composto `cmp_*`, echo de RBAC, spans MCP-aware). **LiteLLM :4000** é a fonte da verdade de RBAC (`object_permission.mcp_servers`) e o roteador de modelo/MCP.

| Componente | Camada | Responsabilidades | NÃO faz |
|---|---|---|---|
| **APISIX** | Borda / edge | Terminação TLS; rate-limit (`limit-count`/`limit-req`, distribuído via Redis); WAF (`coraza-waf`/`chaitin-waf`); IP allow/deny (`ip-restriction`, CIDR); CORS; `proxy-rewrite`; observabilidade de tráfego (`opentelemetry`/`prometheus`); validação de token como *relying party* (`openid-connect`, delega a IdP externo) | Não é OAuth 2.1 AS: não expõe `/authorize`/`/token`/`/register`, não faz DCR (RFC 7591), não publica `.well-known/oauth-authorization-server` nem `.well-known/oauth-protected-resource`, não emite tokens (só valida). Não conhece RBAC per-MCP nem emite spans MCP-aware |
| **`mcp-gateway` :9100** | BFF / app-aware gateway | OAuth 2.1 Authorization Server (DCR RFC 7591, `client_id` `mcp_*`; PKCE S256; `.well-known` RFC 8414/9728; consent pt-BR; emite bearer composto `cmp_*` TTL 30d); refresh in-place do token upstream (ex. Linear); echo do RBAC do LiteLLM via `_key_has_mcp()`; spans MCP-aware no Langfuse (1 span/chamada, `user_id`=e-mail do dono da key, `session_id`=sessão Claude) | Não é a fonte da verdade de RBAC (só ecoa o LiteLLM). Não termina TLS de borda, não aplica WAF/rate-limit transversal nem IP allow/deny |
| **LiteLLM :4000** | Plano de controle / dados | Fonte da verdade de RBAC: `object_permission.mcp_servers` com herança Team → User → Virtual Key (só restringe, ver `docs/rbac-mcp.md` §1–3); roteamento de modelo e de MCP; `success_callback:["langfuse"]` focado em completions LLM | Não consegue proxy de MCP streamable-http (bug #26700, ver `docs/rbac-mcp.md` §11) — daí o Branch A. Não faz DCR/consent OAuth nem spans MCP-aware com resolução de e-mail/sessão |

# 3. Por que NÃO usar só APISIX

A tentação inicial é colocar o APISIX (Apache) na borda e deixar que ele resolva tudo: auth, rate-limit, roteamento e segurança em um único componente. Para o caso de MCP isso **não funciona**, por uma razão estrutural: o protocolo MCP exige que o servidor seja um **OAuth 2.1 Authorization Server completo**, e o APISIX não é — nem pode ser configurado para ser.

## 3.1 APISIX não é um Authorization Server

O APISIX oferece plugins de autenticação (`key-auth`, `jwt-auth`, `openid-connect`, `hmac-auth`), mas todos atuam como **validadores** de credenciais, não como emissores. Em particular, o plugin `openid-connect` é um **relying party** (cliente OIDC): ele delega o fluxo de autenticação a um IdP externo (Keycloak, Auth0, Okta) e apenas valida o token devolvido. O APISIX, em qualquer configuração:

- NÃO expõe `/authorize`, `/token`, `/introspect` nem `/register`;
- NÃO publica `.well-known/oauth-authorization-server` (RFC 8414);
- NÃO publica `.well-known/oauth-protected-resource` (RFC 9728);
- NÃO faz Dynamic Client Registration (RFC 7591);
- NÃO emite tokens nem participa do PKCE (RFC 7636) — só valida o que o IdP emitiu.

Ou seja: o APISIX é **edge gateway**, não **Authorization Server**. Quem precisa do AS é o servidor MCP, e esse papel cabe ao `mcp-gateway` (descrição componente a componente em `docs/rbac-mcp.md` §5).

## 3.2 O cliente MCP exige AS + DCR + PKCE do servidor

Pela spec de autorização do MCP, um cliente remoto (Claude Desktop, claude.ai, Cursor) só consegue se conectar a um servidor protegido se o servidor cumprir um contrato OAuth 2.1 específico:

1. responder `401` com `WWW-Authenticate: resource_metadata="..."` quando não autenticado;
2. publicar `.well-known/oauth-protected-resource` (RFC 9728) apontando para o Authorization Server;
3. publicar `.well-known/oauth-authorization-server` (RFC 8414) no AS;
4. oferecer Authorization Code flow (`GET /authorize` com `code_challenge` + `POST /token`);
5. exigir **PKCE S256** (cliente público);
6. validar `redirect_uri` contra whitelist estrita;
7. idealmente, suportar **Dynamic Client Registration** (RFC 7591) — o Claude registra o cliente dinamicamente.

O Claude obtém o token **fora** da chamada (durante o fluxo OAuth) e depois envia o `Bearer` em cada request, deixando o refresh a cargo da plataforma. Se o servidor não publica esses metadados e não oferece DCR + PKCE, **o Claude Desktop nem inicia a conexão** — falha já no discovery, antes de qualquer chamada de tool.

O APISIX não entrega nenhum dos itens 2 a 7. Logo, um setup "só APISIX" para na primeira etapa do handshake MCP.

## 3.3 APISIX não é MCP-aware (RBAC e traces)

Mesmo que o problema de OAuth fosse resolvido externamente, o APISIX continuaria cego ao domínio MCP:

- **RBAC por MCP** — o APISIX não conhece o conceito de `object_permission.mcp_servers` nem a herança Team → User → Virtual Key do LiteLLM. Não sabe consultar `GET /v1/mcp/server` para decidir se uma key pode acessar `linear_mcp` e devolver a resposta restrita `{tools: []}` em vez de derrubar a conexão. O modelo de três camadas é descrito em `docs/rbac-mcp.md` §1–3.
- **Traces por tool/usuário** — o APISIX propaga contexto de trace (`opentelemetry`, `zipkin`, `prometheus`), mas só enxerga HTTP. Ele não nomeia o span como `<server>/<tool>` (ex.: `linear_mcp/create_issue`), não resolve o `user_id` para o **e-mail** do dono da virtual key (os 2 hops `/key/info` → `/user/info`), nem deriva o `session_id` da sessão Claude. Esse enriquecimento é feito pelo `mcp-gateway` — modelo de tracing em `docs/rbac-mcp.md` §5.9.

## 3.4 O que o MCP exige × o que o APISIX entrega

| Exigência da spec MCP / domínio | APISIX (edge gateway) | Quem entrega |
|---|---|---|
| `.well-known/oauth-authorization-server` (RFC 8414) | Não | `mcp-gateway` |
| `.well-known/oauth-protected-resource` (RFC 9728) | Não | `mcp-gateway` |
| `401` + `WWW-Authenticate: resource_metadata=...` | Não | `mcp-gateway` |
| Dynamic Client Registration `/register` (RFC 7591) | Não | `mcp-gateway` |
| `GET /authorize` + tela de consent | Não | `mcp-gateway` |
| `POST /token` + verificação PKCE S256 (RFC 7636) | Não (só valida token de IdP) | `mcp-gateway` |
| Emissão e refresh de token (bearer composto `cmp_*`) | Não | `mcp-gateway` |
| RBAC por MCP (`mcp_servers`, herança Team→User→Key) | Não | LiteLLM (echo no `mcp-gateway`) |
| Span `<server>/<tool>` + e-mail do dono + `session_id` | Não (só trace HTTP) | `mcp-gateway` |
| Validação de Bearer já emitido (relying party OIDC) | Sim (`openid-connect`) | APISIX |
| Rate-limit, WAF, CORS, IP allow/deny, TLS na borda | Sim | APISIX |

A última linha mostra que o APISIX é necessário — mas para os concerns de borda, não para o papel de servidor MCP. Conclusão: APISIX sozinho não atende; é peça complementar, não substituta (ver §5).

# 4. Por que NÃO usar só o `mcp-gateway`

O inverso também não se sustenta. O `mcp-gateway` (`:9100`) é **lógica de aplicação** — um Authorization Server OAuth 2.1 combinado com um BFF (Backend for Frontend) específico de MCP. Ele resolve DCR, consent, emissão e refresh do bearer composto `cmp_*`, echo de RBAC e tracing enriquecido. O que ele **não** faz, e nem deveria fazer, é **blindagem de perímetro**.

## 4.1 O gateway é app-aware, não edge

O `mcp-gateway` é um processo FastAPI (~1035 LoC, `app.py`) focado no domínio MCP/OAuth. Ele não foi desenhado para absorver tráfego hostil de internet aberta. Faltam-lhe, por design, todas as preocupações transversais de borda:

- **TLS termination** — terminação e gestão de certificados na borda;
- **Rate-limit / quota** por IP e por consumer (janela fixa/deslizante, contagem distribuída) — o gateway não tem `limit-count`/`limit-req`;
- **WAF** — inspeção de payload contra OWASP (Coraza, port do ModSecurity; ou Chaitin) — inexistente no gateway;
- **IP allow/deny** por CIDR (`ip-restriction`);
- **Proteção contra bots e flood** na camada de borda;
- **Limites de tamanho de request e timeouts de borda** padronizados para todas as rotas.

## 4.2 Expor o FastAPI direto na internet é frágil

```text
   INTERNET (tráfego hostil, não filtrado)
        |
        |  sem TLS gerenciado, sem rate-limit,
        |  sem WAF, sem IP allow/deny
        v
   +---------------------------+
   |  mcp-gateway :9100        |   <- AS + BFF, app-aware
   |  (FastAPI, ~1035 LoC)     |      NÃO é blindagem de perímetro
   +---------------------------+
```

Sem uma camada de borda na frente, um único processo de aplicação fica exposto a abuso de volume (sem rate-limit distribuído), a payloads maliciosos (sem WAF) e a varredura indiscriminada de origem (sem IP allow/deny). Sobrecarregar o BFF com essas responsabilidades degrada a eficiência operacional e a escalabilidade do componente que deveria estar concentrado em lógica de MCP/OAuth.

Conclusão: o `mcp-gateway` é insubstituível para o papel de Authorization Server MCP, mas precisa de uma borda à sua frente. Essa borda é o APISIX (ver §5).

# 5. Por que combinar (a recomendação)

A recomendação é executar **APISIX na borda + `mcp-gateway` como AS/BFF + LiteLLM como plano de controle de permissão e modelos**. Isso aplica dois princípios consolidados: **defesa em camadas** e **separação de responsabilidades**, este último materializado no padrão arquitetural **Backends for Frontends (BFF)** descrito pela Microsoft Azure Architecture Center.

## 5.1 Cada camada faz o que sabe fazer

- **APISIX (edge / borda)** — concerns **transversais a todas as requests**: TLS, validação de auth de borda, rate-limit/quota, WAF, CORS, IP allow/deny, transformação básica de path/header e observabilidade de tráfego (propagação de contexto de trace). É o ponto único de entrada hostil-facing.
- **`mcp-gateway` (BFF / app-aware)** — lógica **específica do cliente MCP**: DCR (RFC 7591), tela de consent pt-BR, emissão/refresh do bearer composto `cmp_*`, echo de RBAC por MCP (`_key_has_mcp` via `GET /v1/mcp/server`) e spans Langfuse nomeados `<server>/<tool>` com e-mail e sessão resolvidos. Ver `docs/rbac-mcp.md` §5.
- **LiteLLM (plano de controle)** — **fonte da verdade do RBAC** (`object_permission.mcp_servers`, herança Team → User → Virtual Key) e roteamento de modelos. O gateway apenas **ecoa** essa decisão; ele não inventa permissão. Ver `docs/rbac-mcp.md` §1–3 e §2.4.1.

## 5.2 Topologia recomendada

```text
   Cliente MCP (Claude Desktop / claude.ai / Cursor)
        |  OAuth 2.1 + PKCE S256, Authorization: Bearer cmp_*
        v
   +------------------------------------------------------+
   |  APISIX  (edge)                                      |
   |  TLS · rate-limit · WAF · CORS · IP allow/deny       |
   |  validação de auth de borda · trace HTTP            |
   +-----------------------------+------------------------+
                                 |  (proxy reverso)
                                 v
   +------------------------------------------------------+
   |  mcp-gateway  :9100  (AS + BFF, app-aware)          |
   |  .well-known/* · /register · /authorize · /token     |
   |  bearer cmp_* (Redis DB 2) · echo RBAC · spans       |
   +------+----------------------------------+------------+
          | x-litellm-api-key: Bearer sk-... | Branch A: Bearer <linear_access>
          v                                  v  (bypass #26700)
   +------+-----------------+        +-------+------------------+
   |  LiteLLM  :4000        |        |  mcp.linear.app/mcp      |
   |  RBAC (fonte da verdade)|       +--------------------------+
   |  /v1/mcp/server         |
   |  Branch B: deepwiki ----+----->  mcp.deepwiki.com/mcp
   +-------------------------+
```

A checagem de permissão (`_key_has_mcp`) **sempre** passa pelo LiteLLM, mesmo no Branch A (bypass direto para `mcp.linear.app` por causa da limitação BerriAI/litellm#26700, em que o LiteLLM v1.85.0 não consegue fazer proxy de MCP streamable-http). Só o tráfego de **payload** desvia; a **autorização** não. Detalhe em `mcp-gateway/README.md` (Limitações) e `docs/rbac-mcp.md` §11.

## 5.3 Por que não colapsar tudo em um só componente

| Critério | Manter as camadas separadas |
|---|---|
| **Eficiência operacional** | O BFF não é sobrecarregado com WAF/rate-limit/TLS; concentra-se em MCP/OAuth. |
| **Escalabilidade** | Borda e BFF escalam de forma independente conforme o perfil de carga. |
| **Segurança (defesa em camadas)** | Se uma camada falha, a outra ainda verifica: borda filtra tráfego hostil antes de chegar ao AS; o AS faz a autorização fina mesmo que a borda deixe passar. |
| **Confiabilidade** | Falha ou deploy de uma camada não derruba a responsabilidade da outra; superfícies de mudança ficam isoladas. |

## 5.4 Concern × camada

| Concern | APISIX (borda) | `mcp-gateway` (AS/BFF) | LiteLLM (controle) |
|---|---|---|---|
| TLS termination | ✓ | — | — |
| Rate-limit / quota (IP, consumer) | ✓ | — | parcial (budgets/limits por key) |
| WAF (Coraza / Chaitin) | ✓ | — | — |
| CORS, IP allow/deny | ✓ | — | — |
| Validação de Bearer já emitido (OIDC RP) | ✓ | — | — |
| Observabilidade de **tráfego HTTP** | ✓ (otel/zipkin/prom) | — | — |
| `.well-known/*` OAuth (RFC 8414 / 9728) | — | ✓ | — |
| DCR `/register` (RFC 7591) | — | ✓ | — |
| `/authorize` + consent + `/token` + PKCE S256 | — | ✓ | — |
| Emissão/refresh do bearer composto `cmp_*` | — | ✓ | — |
| OAuth pessoal upstream (ex.: Linear `actor=user`) | — | ✓ | — |
| Echo de RBAC por MCP (`_key_has_mcp`) | — | ✓ | ✓ (fonte da verdade) |
| RBAC `mcp_servers` + herança Team→User→Key | — | — | ✓ |
| Roteamento de modelos / MCPs upstream | — | parcial (Branch A) | ✓ |
| Span `<server>/<tool>` + e-mail + `session_id` | — | ✓ | parcial (raso, sem resolução de e-mail) |

> Observação sobre tracing: o LiteLLM também tem `success_callback: ["langfuse"]` em `litellm/config.yaml`, mas focado em completions LLM. O tracing de chamada MCP por tool no LiteLLM é mais raso, dependente de versão e **sem** resolução de e-mail/sessão. O enriquecimento por tool/usuário descrito em §3.3 é responsabilidade do `mcp-gateway` (ver `docs/rbac-mcp.md` §5.9).

**Resumo:** APISIX e `mcp-gateway` não competem — são camadas complementares. O APISIX protege o perímetro; o `mcp-gateway` é o servidor MCP que o cliente exige (AS + DCR + PKCE); o LiteLLM é a fonte da verdade do RBAC e dos modelos. Remover qualquer uma das três deixa uma lacuna que as outras não cobrem.

# 6. Arquitetura alvo

O fluxo combina os três componentes em camadas. O AI Client (Claude Desktop/Code) faz o handshake OAuth com o `mcp-gateway` (que é o Authorization Server), recebe o bearer composto `cmp_*` e passa esse bearer nas chamadas MCP. Todo o tráfego entra pela borda (APISIX) antes de chegar ao BFF.

```text
                          handshake OAuth 2.1
                   (.well-known, /register, /authorize,
                     /token — PKCE S256, consent pt-BR)
                  ┌──────────────────────────────────────┐
                  │                                       │
                  ▼                                       │
┌─────────────────────────┐     TLS, rate-limit,    ┌─────┴───────────────────────┐
│       AI Client         │     WAF, IP allow/deny, │           APISIX            │
│ (Claude Desktop / Code) │────▶ CORS, obs. tráfego  │        (borda / edge)       │
│  Bearer: cmp_*          │                          └─────────────┬───────────────┘
└─────────────────────────┘                                        │
                                                                    ▼
                                            ┌───────────────────────────────────────┐
                                            │          mcp-gateway  :9100             │
                                            │     OAuth 2.1 AS + BFF (FastAPI)        │
                                            │  • verifica cmp_* (Redis DB 2)          │
                                            │  • echo RBAC: _key_has_mcp() ──────┐    │
                                            │  • 1 span MCP-aware / chamada       │   │
                                            │    (user_id=e-mail, session=Claude) │   │
                                            └───────┬─────────────────────┬───────┼───┘
                                                    │ Branch B            │ Branch A (#26700)
                                                    ▼                     │ bypass direto
                                       ┌───────────────────────┐         │
                                       │    LiteLLM  :4000      │         │
                                       │  RBAC (fonte da verdade)│        │
                                       │  object_permission     │◀────────┘ (só checa
                                       │   .mcp_servers          │           permissão via
                                       │  roteamento modelo/MCP  │           _key_has_mcp)
                                       └───────────┬─────────────┘
                                                   │                       │
                                                   ▼                       ▼
                                       ┌───────────────────────┐  ┌────────────────────┐
                                       │  MCPs upstream         │  │   mcp.linear.app   │
                                       │  (deepwiki etc.)       │  │  (Linear, direto)  │
                                       └───────────────────────┘  └────────────────────┘
```

> **Branch A (bypass Linear):** por causa do bug #26700 (LiteLLM v1.85.0 não faz proxy de MCP streamable-http), o `mcp-gateway` envia o *payload* da chamada Linear direto para `mcp.linear.app`. A checagem de permissão (`_key_has_mcp()`) ainda passa pelo LiteLLM; só o tráfego de payload desvia. Detalhe em `mcp-gateway/README.md` (Limitações) e `docs/rbac-mcp.md` §11.

## 6.1 Mapa de responsabilidades por hop

| Hop | O que faz | O que NÃO faz |
|---|---|---|
| **AI Client** (Claude Desktop/Code) | Faz o fluxo OAuth fora da chamada (DCR + Authorization Code + PKCE S256), guarda e renova o bearer `cmp_*`, envia-o no header `Authorization` de cada chamada MCP | Não conhece RBAC nem virtual keys; não decide quais MCPs/tools pode ver (recebe `{tools: []}` quando restrito) |
| **APISIX** (borda) | Termina TLS; aplica rate-limit/quota, WAF, IP allow/deny, CORS; observabilidade de tráfego; encaminha ao `:9100` | Não emite/valida tokens OAuth como AS; não publica `.well-known`; não faz DCR; não conhece RBAC per-MCP nem traces MCP-aware |
| **`mcp-gateway` :9100** (OAuth AS + BFF) | Publica `.well-known` (RFC 8414/9728); DCR (RFC 7591); consent pt-BR; PKCE S256; emite bearer composto `cmp_*`; verifica permissão via `_key_has_mcp()` (cache 30s) e devolve `{tools: []}` se o MCP não for permitido; abre 1 span Langfuse por chamada (`user_id`=e-mail, `session_id`=sessão Claude) | Não é a fonte da verdade de RBAC (ecoa o LiteLLM); RBAC é per-SERVER, **não** per-tool; não termina TLS de borda nem aplica WAF |
| **LiteLLM :4000** (RBAC + roteamento) | Fonte da verdade do RBAC (`object_permission.mcp_servers`, herança Team→User→Key); roteamento de modelo/MCP; responde `GET /v1/mcp/server` ao gateway | Não faz proxy de MCP streamable-http (#26700) → Branch A; não faz consent/DCR; não emite spans MCP-aware com e-mail/sessão |
| **MCPs upstream / Linear** | Executam as tools (Branch B via LiteLLM; Branch A direto em `mcp.linear.app`) | Não conhecem o RBAC da plataforma nem a identidade resolvida nos traces |

# 7. Integração APISIX (config)

Colocar o APISIX na frente do `mcp-gateway` (`:9100`) adiciona uma camada de borda (edge) com preocupações transversais — auth de borda, rate-limit, observabilidade, WAF, IP — sem reescrever a lógica de aplicação. O ponto sensível é que o gateway é um **OAuth 2.1 Authorization Server + BFF**: várias rotas precisam passar **intactas**, ou o fluxo OAuth do cliente MCP (Claude Desktop / claude.ai) quebra.

```text
                Internet (HTTPS, host público)
                            |
                            v
        +-----------------------------------------+
        |              APISIX  (edge)             |
        |  - limit-count / limit-req              |
        |  - ip-restriction                       |
        |  - coraza-waf                           |
        |  - opentelemetry / prometheus           |
        |  - proxy-rewrite (X-Forwarded-*)        |
        |  - proxy-buffering off (SSE)            |
        |                                         |
        |  NÃO faz: emissão/validação de cmp_*,   |
        |  RBAC de MCP, resolução de email/sessão |
        +--------------------+--------------------+
                             | preserva Authorization,
                             | traceparent, baggage
                             v
                  mcp-gateway:9100 (upstream)
```

> **Premissa de capacidade.** O APISIX entra como **relying party / proxy de borda**, não como Authorization Server. Ele **não** expõe `/authorize`, `/token`, `/register` nem `.well-known/oauth-authorization-server` próprios — essas rotas pertencem ao `mcp-gateway` e são apenas repassadas. Detalhe do porquê dessa separação em §3 e §8 e no modelo de camadas (Edge Gateway × BFF).

## 7.1 (a) Passthrough intacto das rotas OAuth

As rotas abaixo **não** podem receber auth de borda nem reescrita de path. O cliente MCP descobre o issuer via `.well-known/*`, registra-se via `/register` (DCR) e troca tokens em `/token`; qualquer interferência (401 da borda, path reescrito, header de auth injetado) quebra o handshake antes mesmo do gateway ser alcançado.

Rotas a preservar: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/register`, `/v1/mcp/oauth/authorize`, `/v1/mcp/oauth/token`, `/v1/linear/callback`.

```yaml
# Route dedicada para o fluxo OAuth do gateway — SEM auth, SEM rewrite de path.
- uri: /.well-known/*
  name: gateway-oauth-wellknown
  upstream_id: mcp-gateway
  plugins:
    proxy-rewrite:
      headers:
        set:
          X-Forwarded-Host: "$http_host"
          X-Forwarded-Proto: "https"
    # nenhum key-auth / jwt-auth / openid-connect aqui

- uris:
    - /register
    - /v1/mcp/oauth/authorize
    - /v1/mcp/oauth/token
    - /v1/linear/callback
  name: gateway-oauth-flow
  upstream_id: mcp-gateway
  plugins:
    proxy-rewrite:
      headers:
        set:
          X-Forwarded-Host: "$http_host"
          X-Forwarded-Proto: "https"
    cors:
      allow_origins: "https://claude.ai,https://claude.com"
      allow_methods: "GET,POST,OPTIONS"
      allow_headers: "Authorization,Content-Type,Mcp-Session-Id,traceparent,baggage"
```

> **Não use `regex_uri`/`proxy-rewrite` para mexer no path dessas rotas.** O `redirect_uri` validado pelo gateway (whitelist estrita, RFC 7636/spec MCP) e o callback do Linear (`/v1/linear/callback`) dependem do path exato. Reescrever path = `redirect_uri` mismatch = OAuth quebrado.

## 7.2 (b) `proxy-rewrite` e o problema do host externo

O gateway precisa emitir `issuer`, `authorization_endpoint`, `token_endpoint`, `redirect_uri` e o parâmetro `resource` apontando para o **host público externo** (ex.: `https://mcp.exemplo.com`), **nunca** para `mcp-gateway:9100` (nome interno do Compose). Se o gateway emitir o host interno, o cliente MCP recebe um `issuer` que não bate com o host onde ele realmente fala → mismatch de issuer → o fluxo quebra.

Como o APISIX termina o TLS e troca o host, ele deve repassar o host externo via `X-Forwarded-Host` / `X-Forwarded-Proto`, e o **gateway** deve ser configurado para construir suas URLs a partir desses headers (não a partir de `request.url.host`).

```yaml
plugins:
  proxy-rewrite:
    headers:
      set:
        X-Forwarded-Host: "$http_host"   # host público que o cliente usou
        X-Forwarded-Proto: "https"
        X-Forwarded-For: "$remote_addr"
```

> **Checklist de host.** (1) APISIX seta `X-Forwarded-Host`/`X-Forwarded-Proto`. (2) Gateway lê esses headers para montar `issuer`/endpoints/`resource`. (3) Validar com `GET /.well-known/oauth-authorization-server` através da borda: todos os campos de URL devem conter o host público, não `:9100`.

## 7.3 (c) Não sobrescrever `Authorization: Bearer cmp_*`

O gateway depende do header `Authorization: Bearer cmp_*` em toda chamada a `/mcp{path}` — é dele que sai o binding `mcp:bearer:cmp_*` no Redis (virtual key `sk-...` + token OAuth upstream). Se a borda **substituir** esse header (ex.: ao aplicar seu próprio `key-auth`/`jwt-auth` que escreve em `Authorization`, ou um `proxy-rewrite` que faz `set` em `Authorization`), o gateway perde o bearer e a request falha.

```yaml
# Route da superfície MCP autenticada (/mcp...). PRESERVA o Authorization do cliente.
- uri: /mcp*
  name: gateway-mcp-proxy
  upstream_id: mcp-gateway
  plugins:
    proxy-rewrite:
      headers:
        set:
          X-Forwarded-Host: "$http_host"
          X-Forwarded-Proto: "https"
        # NÃO incluir 'Authorization' em set/add/remove
    # NÃO habilitar key-auth/jwt-auth nesta route (evitar double-auth/clobber)
```

> **Double-auth na borda.** O bearer `cmp_*` é opaco e validado **só** pelo gateway. Não há como o APISIX validá-lo (ele não conhece o Redis DB 2 nem o esquema do binding). Tentar autenticá-lo na borda com `jwt-auth`/`openid-connect` → 401 indevido. A borda, se quiser auth adicional, deve usar um **header próprio** (ex.: `key-auth` com `X-Edge-Key`), nunca tocar `Authorization`.

## 7.4 (d) SSE / streamable-http

O transporte MCP streamable-http usa SSE (Server-Sent Events). Por padrão o APISIX bufferiza a resposta upstream — o que **trava** o streaming. É preciso desligar o buffering e elevar timeouts na route do proxy MCP.

```yaml
- uri: /mcp*
  name: gateway-mcp-proxy
  upstream_id: mcp-gateway
  plugins:
    proxy-buffering:
      disable: true          # via header X-Accel-Buffering: no
    proxy-rewrite:
      headers:
        set:
          X-Forwarded-Host: "$http_host"
          X-Forwarded-Proto: "https"
```

E na config de Nginx/route do APISIX (proxy do upstream), garantir:

```text
proxy_buffering            off
proxy_read_timeout         86400s      # SSE longo-prazo
chunked_transfer_encoding  on
```

> **AVISO — bug #12665.** No APISIX 3.9.1+ o SSE **sobre HTTPS** é bufferizado indevidamente (o tráfego SSE só flui corretamente sobre HTTP simples). Como a borda termina TLS, esse cenário é exatamente o afetado. **Testar SSE ponta-a-ponta sobre HTTPS antes de produção.** O plugin SSE (PR #12498, APISIX 3.9+) e `proxy-buffering` (controle via `X-Accel-Buffering`) são os mecanismos disponíveis; nenhum garante o caso HTTPS antes da correção do #12665. Se o stream travar, o sintoma é o cliente MCP conectando mas não recebendo eventos.

## 7.5 (e) Repasse de `traceparent` e `baggage` (W3C)

O nesting distribuído de traces no Langfuse depende do gateway receber os headers W3C `traceparent` e `baggage` do cliente (e do `Mcp-Session-Id`, usado na precedência de `session_id`). O APISIX **não** pode descartá-los — se descartar, o span do gateway abre como root isolado e o nesting (trace pai → span MCP) se perde.

O APISIX preserva headers de request por padrão; o cuidado é **não** removê-los acidentalmente em `proxy-rewrite` e configurar o `opentelemetry` da borda para **propagar** o contexto W3C (não reescrever `traceparent` com um novo trace que descole do cliente).

```yaml
plugins:
  opentelemetry:
    sampler:
      name: always_on
    # propaga contexto W3C; não substituir o traceparent do cliente
  proxy-rewrite:
    headers:
      # garantir que NÃO há 'traceparent'/'baggage'/'Mcp-Session-Id'
      # em headers.remove — eles devem fluir intactos
      set:
        X-Forwarded-Host: "$http_host"
        X-Forwarded-Proto: "https"
```

> O detalhamento de como o gateway usa esses headers (precedência de `session_id`, abertura de span com `trace_context`, repasse de `baggage`) está em `docs/rbac-mcp.md` §5.9 — não duplicado aqui.

## 7.6 Config de borda (cross-cutting)

Plugins de borda aplicados na route do proxy MCP (e/ou globalmente), todos reais no APISIX:

```yaml
- uri: /mcp*
  name: gateway-mcp-proxy
  upstream_id: mcp-gateway
  plugins:
    # Rate-limit distribuído (contagem via Redis)
    limit-count:
      count: 600
      time_window: 60
      rejected_code: 429
      key_type: "var"
      key: "remote_addr"
      policy: "redis"
      redis_host: "redis"
      redis_port: 6379
      redis_database: 3          # NÃO usar DB 2 (reservado ao gateway)
    # Suavização de rajada (leaky bucket)
    limit-req:
      rate: 20
      burst: 40
      rejected_code: 429
    # Allow/deny por CIDR
    ip-restriction:
      whitelist:
        - 10.0.0.0/8
        - 192.168.0.0/16
    # WAF (port do OWASP ModSecurity via Proxy-WASM)
    coraza-waf:
      directives: |
        SecRuleEngine On
        Include @owasp_crs/*.conf
```

```yaml
# Observabilidade global (prometheus para scrape; opentelemetry para trace de borda)
plugins:
  prometheus: {}
```

> **Rate-limit e o bypass do Linear.** O `limit-count`/`limit-req` da borda contam **todas** as requests, inclusive as do Branch A (bypass direto para `mcp.linear.app`, workaround do #26700). Calibrar limites considerando que parte do tráfego MCP não passa pelo LiteLLM — mas **passa** pela borda. Ver §9 e `docs/rbac-mcp.md` §11.

# 8. O que NÃO muda ao colocar APISIX na frente

APISIX é **aditivo**: ele acrescenta uma camada de borda, mas **não substitui** nenhuma das duas funções centrais do stack. Duas responsabilidades permanecem exatamente onde estavam.

| Função | Onde vive (continua) | Papel do APISIX |
|---|---|---|
| **RBAC de MCP** (allow-list per-server) | LiteLLM (`object_permission.mcp_servers`, herança Team → User → Key); gateway só ecoa via `_key_has_mcp()` | **Nenhum.** APISIX não conhece virtual keys, `allowed_routes`, nem `mcp_servers`. Não assume RBAC. |
| **Traces por chamada MCP** (1 span/request, email, sessão) | `mcp-gateway` (resolve email via 2 hops, `session_id`, nesting W3C) | **Só repassa** `traceparent`/`baggage`/`Mcp-Session-Id`. Não emite o span de tool nem resolve identidade. |

## 8.1 RBAC continua 100% no LiteLLM

A fonte da verdade do RBAC é o LiteLLM. A allow-list per-server (`object_permission.mcp_servers`) e a herança Team → User → Virtual Key (que só **restringe**, nunca expande) são avaliadas pelo LiteLLM; o gateway apenas consulta `GET /v1/mcp/server` e ecoa o resultado (respondendo `{tools: []}` para MCP fora de escopo, em vez de 403). O requisito de `allowed_routes` incluir `mcp_routes` para chegar em `/v1/mcp/server` está detalhado em `docs/rbac-mcp.md` §2.4.1.

O APISIX **não** participa disso. Ele não tem como inspecionar o `cmp_*` (opaco) para descobrir qual virtual key ele carrega, nem consultar `/v1/mcp/server`. Configurar "RBAC na borda" seria duplicar — e divergir — da fonte da verdade. Modelo de 3 camadas: `docs/rbac-mcp.md` §1–3.

## 8.2 Traces continuam no gateway

O gateway emite **1 span por request MCP**, com `trace.user_id` = email do dono da virtual key (resolvido via `/key/info` → `/user/info`, cache Redis 3600s), `session_id` por precedência (`Mcp-Session-Id` → baggage → `traceparent` → hash do bearer) e nesting distribuído quando há `traceparent`. Esse modelo — incluindo tags e metadata — está em `docs/rbac-mcp.md` §5.9.

O APISIX **só repassa** `traceparent`/`baggage` (§7.5). Seu próprio `opentelemetry`/`prometheus` cobre métricas e trace **de borda** (latência, status HTTP, throughput), o que é complementar — não substitui o tracing semântico por tool/usuário/sessão do gateway. O `success_callback: ["langfuse"]` do LiteLLM (`litellm/config.yaml`) continua focado em completions LLM, mais raso para MCP e sem resolução de email/sessão.

> **Resumo.** APISIX adiciona defesa de borda (auth de borda opcional, rate-limit, WAF, IP, observabilidade de infra). RBAC de MCP e tracing semântico por tool permanecem responsabilidade do LiteLLM e do `mcp-gateway`, respectivamente. Colapsar tudo num componente só removeria a defesa em camadas (ver justificativa de separação Edge Gateway × BFF no padrão "Backends for Frontends", §5).

# 9. Limitações / riscos

A introdução do APISIX e as limitações herdadas do stack trazem riscos concretos. Nenhum invalida a arquitetura, mas todos exigem mitigação explícita e teste antes de produção.

| # | Risco | Impacto | Mitigação |
|---|---|---|---|
| R1 | **SSE sobre HTTPS bufferizado** (APISIX #12665, 3.9.1+) | Transporte streamable-http trava na borda; cliente conecta mas não recebe eventos | `proxy-buffering` off + `X-Accel-Buffering: no` + `proxy_read_timeout 86400s` + `chunked` (§7.4). **Testar SSE/HTTPS ponta-a-ponta antes de produção.** Avaliar plugin SSE (PR #12498). Fixar versão do APISIX e acompanhar correção do #12665. |
| R2 | **LiteLLM #26700** — proxy MCP streamable-http falha (AnyIO cancel-scope) | LiteLLM v1.85.0 não faz proxy de `mcp.linear.app`; necessário Branch A (bypass direto) | Bypass já implementado no gateway: payload vai direto para `mcp.linear.app`, mas a checagem de permissão (`_key_has_mcp`) ainda passa pelo LiteLLM. Detalhe em `docs/rbac-mcp.md` §11 / `mcp-gateway/README.md` (Limitações). Rate-limit de borda continua cobrindo o tráfego do Branch A (§7.6). |
| R3 | **Double-auth / clobber do bearer na borda** | APISIX sobrescreve `Authorization: Bearer cmp_*` → gateway perde o binding → request falha (ou 401 indevido se a borda tenta validar o opaco) | Nenhum `key-auth`/`jwt-auth`/`openid-connect` na route `/mcp*`; nunca incluir `Authorization` em `proxy-rewrite` set/add/remove (§7.3). Auth adicional de borda só via header próprio (ex.: `X-Edge-Key`). |
| R4 | **`CLIENTS` de DCR in-memory no gateway** | `CLIENTS` (registro RFC 7591, `client_id` `mcp_*`) é in-memory; perde-se no restart do `mcp-gateway` | Mitigado pelo re-registro automático: o cliente MCP re-executa o DCR ao falhar. Documentado em `docs/rbac-mcp.md` §11.1 e `mcp-gateway/README.md` (Limitações). Para persistência durável, mover `CLIENTS` para Redis/Postgres (fora do escopo atual). |
| R5 | **Mismatch de issuer / host externo** | Gateway emite `issuer`/`redirect_uri`/`resource` com host interno (`mcp-gateway:9100`) → OAuth do cliente quebra | APISIX seta `X-Forwarded-Host`/`X-Forwarded-Proto`; gateway monta URLs a partir desses headers; validar `.well-known/*` através da borda (§7.2). |
| R6 | **Quebra de nesting de traces** | APISIX descarta ou reescreve `traceparent`/`baggage`/`Mcp-Session-Id` → span do gateway vira root isolado no Langfuse | Não remover esses headers em `proxy-rewrite`; `opentelemetry` da borda configurado para **propagar** (não substituir) o contexto W3C (§7.5; modelo em `docs/rbac-mcp.md` §5.9). |
| R7 | **Quebra do passthrough OAuth** | Auth de borda ou reescrita de path em `/.well-known/*`, `/register`, `/v1/mcp/oauth/*`, `/v1/linear/callback` → handshake OAuth falha antes do gateway | Routes dedicadas sem auth e sem rewrite de path para essas rotas (§7.1). Não usar `regex_uri` no fluxo OAuth. |
| R8 | **Colisão de Redis DB** | `limit-count` da borda configurado com `redis_database: 2` colide com o binding `mcp:bearer:cmp_*` do gateway | Usar DB distinto (ex.: DB 3) no `limit-count` (§7.6). Gateway reserva o DB 2. |

> **Threat model de aplicação** (open redirect, PKCE downgrade, replay de authorization code, vazamento de virtual key, allow-list bypass via cache stale, etc.): não duplicado aqui — ver `docs/rbac-mcp.md` §9. Esta seção cobre apenas os riscos **introduzidos ou amplificados** pela camada de borda APISIX e pelas limitações duras do stack.

# 10. Referências

## APISIX

- Plugin `openid-connect`: https://apisix.apache.org/docs/apisix/plugins/openid-connect/
- API Gateway Authentication: https://apisix.apache.org/learning-center/api-gateway-authentication/
- API Gateway Rate Limiting: https://apisix.apache.org/learning-center/api-gateway-rate-limiting/
- API Gateway Security: https://apisix.apache.org/learning-center/api-gateway-security/
- Issue #12665 (SSE sobre HTTPS bufferizado): https://github.com/apache/apisix/issues/12665
- PR #12498 (plugin SSE): https://github.com/apache/apisix/pull/12498
- `proxy-buffering` (API7 Hub): https://docs.api7.ai/hub/proxy-buffering

## MCP / RFCs

- MCP — Authorization spec: https://modelcontextprotocol.io/specification/draft/basic/authorization
- Claude — MCP connector: https://platform.claude.com/docs/en/agents-and-tools/mcp-connector
- RFC 8414 (OAuth 2.0 Authorization Server Metadata): https://datatracker.ietf.org/doc/html/rfc8414
- RFC 7591 (OAuth 2.0 Dynamic Client Registration): https://datatracker.ietf.org/doc/html/rfc7591
- RFC 9728 (OAuth 2.0 Protected Resource Metadata): https://datatracker.ietf.org/doc/html/rfc9728

## Padrão BFF

- Backends for Frontends (Microsoft Azure Architecture Center): https://learn.microsoft.com/en-us/azure/architecture/patterns/backends-for-frontends

## Interno

- `docs/rbac-mcp.md` — RBAC por MCP/Team/Virtual Key (§1–3 camadas RBAC, §2.4.1 herança de MCP e `allowed_routes`, §5.9 proxy `/mcp{path}` e tracing Langfuse, §9 modelo de ameaça, §11 limites conhecidos)
- `mcp-gateway/README.md` — operação do BFF/AS (seção Limitações: `CLIENTS` in-memory, bypass do Linear #26700)
- `mcp-gateway/ALTERNATIVES.md` — alternativas de arquitetura avaliadas
