# Criando virtual keys: UI vs API

Guia curto das diferenças entre gerar uma virtual key (`sk-...`) pela **UI** do LiteLLM
(`:4000` → Keys → Create) e pela **API** (`POST /key/generate`). Foco no que muda para
acesso a MCP e para postura de segurança. Para o RBAC completo, ver
[`rbac-mcp.md`](./rbac-mcp.md) (em especial §2.4.1).

## TL;DR

- **UI** é prático, mas só expõe 3 *key types* pré-definidos e **não** tem campo de
  `allowed_routes`. Para MCP funcionar, é preciso escolher **"Full Access"** — que deixa a
  key irrestrita por rota.
- **API** permite definir `allowed_routes` exato. É o **único** jeito de gerar uma key
  least-privilege que acessa MCP (`["llm_api_routes","mcp_routes"]`) sem abrir todas as
  rotas.
- O que controla acesso a MCP é o `allowed_routes` da key (precisa alcançar
  `/v1/mcp/server`) + os MCPs no `object_permission.mcp_servers` do **Team** (a key herda
  quando não tem lista própria).

## Comparação

| Dimensão | UI (Create Key) | API (`POST /key/generate`) |
|---|---|---|
| Controle de `allowed_routes` | Não — derivado do *key type* | Sim — campo explícito |
| `key_type` disponíveis | AI APIs / Management / Full Access | qualquer; ou omite e passa `allowed_routes` |
| `allowed_routes` default | `["llm_api_routes"]` (key type "AI APIs") | `[]` se omitido |
| Acessa MCP por default? | **Não** (precisa "Full Access") | Sim se omitir `allowed_routes`, ou setar `mcp_routes` |
| Least-privilege LLM+MCP | **Impossível** (sem campo de rotas) | **Sim**: `["llm_api_routes","mcp_routes"]` |
| Herda MCPs do Team | Sim (deixar "Allowed MCP Servers" em branco) | Sim (omitir `object_permission`) |
| Quem pode gerar | Admin ou o próprio internal_user (self-serve) | Admin (master key) ou quem tiver rota `/key/generate` |
| Automação / scripting | Manual, clique a clique | Sim (cURL/script) |

## Os 3 key types da UI

| Label (UI) | `key_type` | `allowed_routes` | Alcança `/v1/mcp/server`? |
|---|---|---|---|
| **AI APIs** (default) | `llm_api` | `["llm_api_routes"]` | **Não** — `llm_api_routes` cobre `/mcp/*` mas não `/v1/mcp/server` |
| **Management** | `management` | rotas de management | Não — sem `/mcp/*` de inference |
| **Full Access** | `default` | `[]` (irrestrito) | **Sim** |

Por isso a key padrão da UI ("AI APIs") não enxerga MCP: o shim consulta `/v1/mcp/server`
em `_key_has_mcp` (`mcp-gateway/app.py:649`) e a rota retorna `403`.

## Receitas

### UI (prático, irrestrito por rota)

1. Keys → Create New Key.
2. **Team**: selecionar o time (fonte dos MCPs).
3. **Key Type**: **Full Access**.
4. **Allowed MCP Servers**: **deixar em branco** (em branco = herda a lista inteira do Team).
5. Create.

Herda os MCPs do Team automaticamente. Trade-off: irrestrita por rota (ver Segurança).

### API (least-privilege + MCP, recomendado)

```bash
curl -X POST http://localhost:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "<user_id>",
    "team_id": "<team_id>",
    "allowed_routes": ["llm_api_routes", "mcp_routes"]
  }'
```

- Sem `object_permission` na key → herda os MCPs do Team.
- `mcp_routes` garante acesso a `/v1/mcp/server` (discovery) e `/mcp/*` (tools).
- `llm_api_routes` cobre as rotas de LLM. Juntas, **não** liberam management nem
  `/key/generate`.

## Segurança: por que API > UI para keys de MCP

Uma key **Full Access** (`allowed_routes: []`) de um `internal_user`:

- **Bloqueado por role** (ok): reads cross-team (`/team/list`), e writes de admin
  (`/user/new`, `/team/*`, keys de terceiros) → `401`.
- **Permitido** (risco): `POST /key/generate` → a key consegue **emitir outras keys**
  (limitadas pelo `upperbound_key_generate_params`). Uma key vazada se auto-replica →
  revogação/auditoria mais difícil.
- Info própria (`/user/info`) e listagem de MCP (`/v1/mcp/server`) retornam `200`, mas URLs
  de MCP vêm **redigidas** (`url: null`) para virtual keys — sem vazamento de credencial.

A key da API com `["llm_api_routes","mcp_routes"]` bloqueia `/key/generate` e todo o
management, mantendo LLM + MCP. Budgets, rate limits, allow-list de modelos, RBAC de MCP e
guardrail de PII se aplicam nos dois casos.

## Pré-requisito (vale para UI e API)

O Team precisa ter os MCPs em `object_permission.mcp_servers`, setados **por nome** (não por
ID — IDs de servidores de config mudam e viram referências mortas):

```bash
curl -X POST http://localhost:4000/team/update \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"team_id":"<team_id>","object_permission":{"mcp_servers":["deepwiki_mcp","linear_mcp"]}}'
```

Sem isso, nenhuma key (UI ou API) herda MCP. Ver [`rbac-mcp.md`](./rbac-mcp.md) §2.4.1.
