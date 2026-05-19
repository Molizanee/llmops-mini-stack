# LLMOps Stack

> [Read in English](README.md)

Uma stack self-hosted de operacoes LLM. Converse com qualquer modelo LLM por uma interface unificada, com controle de orcamento, gestao de usuarios, logs de requisicoes, tracing e mascaramento de dados sensiveis -- tudo rodando na sua propria infraestrutura.

## Por que

Usar LLMs por plataformas de terceiros significa abrir mao do controle sobre custos, acesso de usuarios e privacidade de dados. Essa stack coloca tudo isso sob seu controle com um unico `docker compose up`:

- **Orcamento e gestao de usuarios** -- O LiteLLM Proxy funciona como gateway para qualquer provedor de LLM, rastreando gastos por usuario e por modelo.
- **Observabilidade** -- Cada requisicao (sucesso ou falha) e rastreada no Langfuse, com logs completos de entradas, saidas, latencia e uso de tokens.
- **Mascaramento de PII** -- O Presidio analisa todas as mensagens antes de chegarem ao LLM e mascara dados sensiveis (nomes, cartoes de credito, emails, CPFs, etc.).
- **Sem vendor lock-in** -- Troque modelos e provedores editando um arquivo de configuracao. A interface de chat e o tracing continuam os mesmos.

## Arquitetura

```
Usuario -> LiteLLM Proxy (:4000) -> Provedores LLM (Gemini, OpenRouter, etc.)
                                       |
                                 Presidio (mascaramento PII)
                                       |
                                 Langfuse (tracing)
```

| Servico              | Porta | Finalidade                        |
|----------------------|-------|-----------------------------------|
| LiteLLM Proxy        | 4000  | Gateway LLM, orcamento, roteamento|
| Langfuse Web         | 3000  | UI e API de observabilidade       |
| Langfuse Worker      | 3030  | Processamento assincrono de traces|
| Presidio Analyzer    | 5002  | Deteccao de PII                   |
| Presidio Anonymizer  | 5001  | Mascaramento de PII               |
| PostgreSQL           | 5432  | Banco de dados (LiteLLM + Langfuse)|
| ClickHouse           | 8123  | Analytics (Langfuse OLAP)         |
| Redis                | 6379  | Cache e fila                      |
| MinIO                | 9000  | Armazenamento blob compativel S3  |
| MinIO Console        | 9090  | UI de admin do MinIO              |

## Pre-requisitos

- **Python 3** (para rodar o script de setup)
- **Docker** e **Docker Compose** (v2)

## Setup

### 1. Clonar o repositorio

```bash
git clone https://github.com/Molizanee/llmops-stack.git
cd llmops-stack
```

### 2. Gerar o arquivo de ambiente

```bash
python setup_env.py
```

O script vai pedir:
- Sua chave de API do **Google AI Studio (Gemini)**
- Sua chave de API do **OpenRouter**
- Credenciais de admin do Langfuse (email, nome, senha)

Todos os outros segredos (senhas de banco, chaves de criptografia, tokens de API) sao gerados automaticamente. O resultado e um arquivo `.env` com permissoes definidas como `600`.

### 3. Subir todos os servicos

```bash
docker compose up -d
```

Aguarde cerca de 60 segundos para todos os servicos inicializarem e passarem nos health checks.

### 4. Acessar os servicos

- **LiteLLM Proxy** (admin): http://localhost:4000/ui
- **Langfuse** (tracing): http://localhost:3000

Para o Langfuse, use as credenciais que voce informou durante o `setup_env.py`.

### Tracing

O tracing funciona automaticamente. O script de setup gera as chaves de API do Langfuse e configura tanto o Langfuse (via inicializacao headless) quanto o LiteLLM para usar o mesmo par de chaves. Toda requisicao ao LLM e enviada como trace para o Langfuse automaticamente.

## Configuracao

### Modelos LLM

Os modelos sao definidos em `litellm/config.yaml` na secao `model_list`:

```yaml
model_list:
  - model_name: gemini-3-flash          # nome exibido na interface de chat
    litellm_params:
      model: gemini/gemini-3-flash-preview  # identificador provedor/modelo
      api_key: os.environ/GEMINI_API_KEY
  - model_name: minimax-m2.5
    litellm_params:
      model: openrouter/minimax/minimax-m2.5
      api_key: os.environ/OPENROUTER_API_KEY
```

Para adicionar um novo modelo:

1. Adicione uma nova entrada no array `model_list`.
2. Defina `model_name` com o nome que voce quer exibir na interface.
3. Defina `model` com o identificador do modelo no LiteLLM (veja [provedores suportados pelo LiteLLM](https://docs.litellm.ai/docs/providers)).
4. Defina a chave de API, inline ou via variavel de ambiente.
5. Se adicionou uma nova variavel de ambiente, inclua no `.env` e no servico `litellm` no `docker-compose.yaml`.
6. Reinicie o LiteLLM: `docker compose restart litellm`

A configuracao tambem tem `store_model_in_db: true`, o que permite adicionar modelos em tempo de execucao pela interface admin do LiteLLM em http://localhost:4000/ui sem editar o arquivo de configuracao.

### Mascaramento de PII (Presidio)

O mascaramento de PII e configurado em `litellm/config.yaml` na secao `guardrails`:

```yaml
guardrails:
  - guardrail_name: "presidio-pii"
    litellm_params:
      guardrail: presidio
      mode: "pre_call"
      default_on: true
      output_parse_pii: true
      presidio_language: "en"
      presidio_filter_scope: both
      presidio_score_thresholds:
        ALL: 0.7
      pii_entities_config:
        PERSON: "MASK"
        CREDIT_CARD: "MASK"
        EMAIL_ADDRESS: "MASK"
        PHONE_NUMBER: "MASK"
        US_SSN: "MASK"
        # ... outras entidades
```

O que voce pode alterar:

- **Adicionar ou remover tipos de entidade** -- Adicione qualquer [entidade suportada pelo Presidio](https://microsoft.github.io/presidio/supported_entities/) em `pii_entities_config`, ou remova as que nao precisa.
- **Mudar a acao** -- Substitua `"MASK"` por `"REDACT"` para remover o dado completamente em vez de substituir por um placeholder.
- **Ajustar o limiar de confianca** -- Diminua `presidio_score_thresholds.ALL` (ex: `0.5`) para capturar mais PII potencial ao custo de mais falsos positivos, ou aumente (ex: `0.9`) para menos falsos positivos.
- **Desativar o mascaramento** -- Defina `default_on: false` para desligar o mascaramento de PII por padrao.

Apos fazer alteracoes, reinicie o LiteLLM: `docker compose restart litellm`

### Entidades PII Configuradas Atualmente

| Entidade           | Descricao                             |
|--------------------|---------------------------------------|
| PERSON             | Nomes de pessoas                      |
| CREDIT_CARD        | Numeros de cartao de credito          |
| CRYPTO             | Enderecos de carteiras de criptomoeda |
| EMAIL_ADDRESS      | Enderecos de email                    |
| IBAN_CODE          | Numeros de conta bancaria internacional|
| IP_ADDRESS         | Enderecos IP                          |
| LOCATION           | Localizacoes fisicas                  |
| MEDICAL_LICENSE    | Numeros de licenca medica             |
| PHONE_NUMBER       | Numeros de telefone                   |
| URL                | URLs                                  |
| US_BANK_NUMBER     | Numeros de conta bancaria dos EUA     |
| US_DRIVER_LICENSE  | Numeros de carteira de motorista dos EUA|
| US_ITIN            | Numeros de contribuinte individual dos EUA|
| US_PASSPORT        | Numeros de passaporte dos EUA         |
| US_SSN             | Numeros de seguro social dos EUA      |

## Parando os servicos

Parar todos os servicos:

```bash
docker compose down
```

Parar e remover todos os dados (volumes):

```bash
docker compose down -v
```

## Licenca

Este projeto e disponibilizado como esta para fins de self-hosting.
