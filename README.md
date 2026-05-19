# LLMOps Stack

> [Leia em Portugues](README.pt-br.md)

A self-hosted LLM operations stack. Chat with any LLM model through a unified interface, with budget control, user management, request logging, tracing, and PII masking -- all running on your own infrastructure.

## Why

Running LLMs through third-party platforms means giving up control over costs, user access, and data privacy. This stack puts all of that under your control with a single `docker compose up`:

- **Budget and user management** -- LiteLLM Proxy acts as a gateway to any LLM provider, tracking spend per user and per model.
- **Observability** -- Every request (successful or failed) is traced in Langfuse, giving you full logs of inputs, outputs, latency, and token usage.
- **PII masking** -- Presidio scans all messages before they reach the LLM and masks sensitive data (names, credit cards, emails, SSNs, etc.).
- **No vendor lock-in** -- Swap models and providers by editing a config file. The chat UI and tracing remain the same.

## Architecture

```
User -> LiteLLM Proxy (:4000) -> LLM Providers (Gemini, OpenRouter, etc.)
                                    |
                              Presidio (PII masking)
                                    |
                              Langfuse (tracing)
```

| Service              | Port  | Purpose                          |
|----------------------|-------|----------------------------------|
| LiteLLM Proxy        | 4000  | LLM gateway, budget, routing     |
| Langfuse Web         | 3000  | Observability UI and API         |
| Langfuse Worker      | 3030  | Async trace processing           |
| Presidio Analyzer    | 5002  | PII detection                    |
| Presidio Anonymizer  | 5001  | PII masking                      |
| PostgreSQL           | 5432  | Database (LiteLLM + Langfuse)    |
| ClickHouse           | 8123  | Analytics (Langfuse OLAP)        |
| Redis                | 6379  | Cache and queue                  |
| MinIO                | 9000  | S3-compatible blob storage       |
| MinIO Console        | 9090  | MinIO admin UI                   |

## Prerequisites

- **Python 3** (to run the setup script)
- **Docker** and **Docker Compose** (v2)

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/Molizanee/llmops-stack.git
cd llmops-stack
```

### 2. Generate the environment file

```bash
python setup_env.py
```

The script will prompt you for:
- Your **Google AI Studio (Gemini)** API key
- Your **OpenRouter** API key
- Langfuse admin credentials (email, name, password)

All other secrets (database passwords, encryption keys, API tokens) are generated automatically. The output is a `.env` file with permissions set to `600`.

### 3. Start all services

```bash
docker compose up -d
```

Wait about 60 seconds for all services to initialize and pass their health checks.

### 4. Access the services

- **LiteLLM Proxy** (admin): http://localhost:4000/ui
- **Langfuse** (tracing): http://localhost:3000

For Langfuse, use the credentials you provided during `setup_env.py`.

### Tracing

Tracing works out of the box. The setup script generates Langfuse API keys and configures both Langfuse (via headless initialization) and LiteLLM to use the same key pair. Every LLM request is sent as a trace to Langfuse automatically.

## Configuration

### LLM Models

Models are defined in `litellm/config.yaml` under `model_list`:

```yaml
model_list:
  - model_name: gemini-3-flash          # name shown in the chat UI
    litellm_params:
      model: gemini/gemini-3-flash-preview  # provider/model identifier
      api_key: os.environ/GEMINI_API_KEY
  - model_name: minimax-m2.5
    litellm_params:
      model: openrouter/minimax/minimax-m2.5
      api_key: os.environ/OPENROUTER_API_KEY
```

To add a new model:

1. Add a new entry to the `model_list` array.
2. Set `model_name` to whatever label you want in the UI.
3. Set `model` to the LiteLLM model identifier (see [LiteLLM supported providers](https://docs.litellm.ai/docs/providers)).
4. Set the API key, either inline or via environment variable.
5. If you added a new environment variable, add it to `.env` and to the `litellm` service in `docker-compose.yaml`.
6. Restart LiteLLM: `docker compose restart litellm`

The config also has `store_model_in_db: true`, which means you can add models at runtime through the LiteLLM admin UI at http://localhost:4000/ui without editing the config file.

### PII Masking (Presidio)

PII masking is configured in `litellm/config.yaml` under `guardrails`:

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
        # ... other entities
```

What you can change:

- **Add or remove entity types** -- Add any [Presidio supported entity](https://microsoft.github.io/presidio/supported_entities/) to `pii_entities_config`, or remove ones you do not need.
- **Change the action** -- Replace `"MASK"` with `"REDACT"` to fully remove the data instead of replacing it with a placeholder.
- **Adjust the confidence threshold** -- Lower `presidio_score_thresholds.ALL` (e.g., `0.5`) to catch more potential PII at the cost of more false positives, or raise it (e.g., `0.9`) for fewer false positives.
- **Disable masking** -- Set `default_on: false` to turn off PII masking by default.

After making changes, restart LiteLLM: `docker compose restart litellm`

### Currently Configured PII Entities

| Entity             | Description                          |
|--------------------|--------------------------------------|
| PERSON             | Person names                         |
| CREDIT_CARD        | Credit card numbers                  |
| CRYPTO             | Cryptocurrency wallet addresses      |
| EMAIL_ADDRESS      | Email addresses                      |
| IBAN_CODE          | International bank account numbers   |
| IP_ADDRESS         | IP addresses                         |
| LOCATION           | Physical locations                   |
| MEDICAL_LICENSE    | Medical license numbers              |
| PHONE_NUMBER       | Phone numbers                        |
| URL                | URLs                                 |
| US_BANK_NUMBER     | US bank account numbers              |
| US_DRIVER_LICENSE  | US driver's license numbers          |
| US_ITIN            | US Individual Taxpayer ID numbers    |
| US_PASSPORT        | US passport numbers                  |
| US_SSN             | US Social Security numbers           |

## Stopping

Stop all services:

```bash
docker compose down
```

Stop and remove all data (volumes):

```bash
docker compose down -v
```

## License

This project is provided as-is for self-hosting purposes.
