# SafeNestT SENTRA — Agentic Investigation Intelligence

SafeNestT's proprietary agentic investigation intelligence engine for fraud, OSINT, cybersecurity, digital intelligence, evidence analysis, and investigative reporting.

**SENTRA** is the customer-facing name of the AI engine formerly referred to internally as Hermes.

## Architecture

- **SENTRA Orchestrator**: coordinates the investigation
- **SENTRA OSINT Investigator**
- **SENTRA Security Intelligence Investigator**
- **SENTRA Crypto Intelligence Investigator**
- **SENTRA Evidence Investigator**
- **SENTRA Fraud Investigator**
- **SENTRA Intelligence Report Generator**
- **Orchestrator**: Multi-agent investigation pipeline
- **API**: FastAPI REST endpoints
- **Persistence**: PostgreSQL with Row-Level Security (RLS)
- **Security**: Column-level encryption, hash-chain audit log, per-tenant rate limiting

## Quick Start

### Docker Compose (recommended)

```bash
# Generate SSL certs for PostgreSQL
./scripts/generate-ssl.sh

# Start full stack
docker-compose up -d

# Check health
curl http://localhost:8000/v1/health
```

### Local Development

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Start API (requires PostgreSQL running)
uvicorn safenestt.api.app:app --reload
```

## Security

- **Encryption at rest**: Fernet column-level encryption for sensitive fields
- **Encryption in transit**: HTTPS redirect, PostgreSQL SSL
- **Tenant isolation**: RLS policies + non-owner DB role
- **Audit log**: Tamper-evident hash-chain integrity
- **Rate limiting**: Per-tenant throttling
- **Secrets**: Env-based with KMS upgrade path (AWS SSM, GCP Secret Manager)

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `MODE` | development/production | development |
| `DB_HOST` | PostgreSQL host | 172.19.0.11 |
| `DB_SSL_MODE` | SSL mode (prefer/require/verify-full) | prefer |
| `SAFENESTT_ENCRYPTION_KEY` | Fernet encryption key | (generate) |
| `OPENROUTER_API_KEY` | OpenRouter API key | (required) |
| `RATE_LIMIT_INVESTIGATIONS_PER_MINUTE` | Per-tenant limit | 10 |

## License

Proprietary — SafeNestT
