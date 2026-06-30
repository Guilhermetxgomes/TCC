# TCC — Sistema de Monitoramento de Tráfego Resistente à Vigilância em Massa

[![CI](https://github.com/Guilhermetxgomes/TCC/actions/workflows/ci.yml/badge.svg)](https://github.com/Guilhermetxgomes/TCC/actions/workflows/ci.yml)

Trabalho de Conclusão de Curso — Engenharia da Computação, Escola Politécnica da USP.

Sistema ALPR (Automatic License Plate Recognition) que coleta dados de tráfego garantindo que **nenhum acesso em massa seja possível sem autorização judicial e custo computacional deliberado**, e que o **acesso excepcional exija quórum institucional**.

---

## Arquitetura

```
+---------------+  captura cifrada   +------------------+
|   Coletor     | -----------------> |  Servidor de     |
|  (camera)     |  POST /records     |  Custodia        |<-- investigador
+---------------+                    |  (banco cego)    |    (com token)
       |                             +------------------+
       | BOLO match                         |
       v                             decode_log escrito
+---------------+                   +------------------+
|  Servidor     |                   |   Banco BOLO     |
|    BOLO       |                   |  (fisicamente    |
|  (separado)   |                   |   separado)      |
+---------------+                   +------------------+
       ^
       |
+---------------+
|  Governanca   |  emite tokens, fragmenta SK mensal
|  (juiz)       |  GET /keys/monthly-pk (publica)
+---------------+  GET /keys/kgov (so cameras)
                   POST /tokens (investigadores)
                   POST /keys/split   (emergencia)
                   POST /keys/reconstruct (quorum)
```

### Cinco componentes

| Componente | Diretório | Descrição |
|---|---|---|
| Coletor | `cmd/coletor` | Câmera ALPR — cifra registros na borda antes de enviar |
| Servidor | `cmd/servidor` | Custódia cega — armazena blobs cifrados, nunca vê plaintext |
| BOLO | `cmd/bolo` | Servidor exclusivo para registros de placas em lista negra |
| Governança | `cmd/governanca` | Juiz emite tokens; gerencia chaves mensais |
| Cliente | `cmd/cliente` | Investigador — resolve puzzles e decifra registros autorizados |

### Três níveis de acesso

#### Busca Aberta
- Recupera todos os registros de uma câmera em um período
- Protegida por: token judicial + puzzle Argon2id (>=14 bits de entropia)
- Custo por registro: ~16ms (memory-hard, impede varredura em massa)

#### Busca Fechada
- Recupera registros por placa (via `HMAC(placa, K_gov)`)
- Protegida por: token judicial + puzzle Argon2id
- A placa nunca é armazenada em claro no banco

#### Busca Total (Acesso Excepcional)
- Recupera o plaintext completo sem puzzle, mas exige quórum institucional
- Protegida por: SK mensal X25519 fragmentada com Shamir's Secret Sharing (t=3, n=5)
- Nenhuma instituição isolada pode decifrar — é necessária coalizão de >=3

### Proteções anti-vigilância em massa

| Proteção | Onde | Como |
|---|---|---|
| Placa nunca em claro | Servidor | `HMAC(placa, K_gov)` como índice |
| Puzzle Argon2id | Cada registro | ~16ms por decifração (8MB RAM, memory-hard) |
| BOLO via lista negra | Coletor | Hash diário — servidor BOLO nunca conhece as placas "quentes" |
| Acesso excepcional com quórum | Governança | Shamir's Secret Sharing (t=3, n=5) em GF(2^8) |
| Log de auditoria imutável | Servidor | `decode_logs` — toda decifração é registrada |

---

## Pré-requisitos

- **Go 1.22+**
- **Docker** e **Docker Compose** (para `make up`)
- `make` (GNU make ou compatível)

Verificação:

```bash
go version      # go1.22.x ou superior
docker version  # 20.x ou superior
```

---

## Setup rápido

```bash
git clone https://github.com/Guilhermetxgomes/TCC.git
cd TCC

# Gera todas as chaves criptograficas e um .env funcional
make setup
# vai pedir uma passphrase para cifrar a chave mensal X25519

# Edite .env e defina uma DB_PASSWORD segura (ja ha uma aleatorea)
nano .env

# Sobe todos os servicos (migrations automaticas incluidas)
make up
```

Após `make up`, os seguintes endereços estarão disponíveis:

| Serviço | URL |
|---|---|
| Servidor de custódia | http://localhost:8080 |
| Servidor BOLO | http://localhost:8081 |
| Governança | http://localhost:8090 |

---

## Operação

### Verificar saúde dos serviços

```bash
curl http://localhost:8080/health   # {"status":"ok"}
curl http://localhost:8090/health   # {"status":"ok"}
```

### Obter chave pública mensal

```bash
curl http://localhost:8090/keys/monthly-pk
# {"key_month":"2026-06","monthly_pk_hex":"..."}
```

### Emitir token de busca aberta

```bash
curl -X POST http://localhost:8090/tokens \
  -H "X-Investigator-Key: $INVESTIGATOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "search_type": "open",
    "camera_id": "CAM-SIM-001",
    "start": "2026-06-01T00:00:00Z",
    "end": "2026-06-30T23:59:59Z",
    "decoded_by": "delegado-joao",
    "ttl_minutes": 60
  }'
```

### Fluxo de acesso excepcional (quórum Shamir)

```bash
# 1. Governanca divide a SK mensal em 5 fragmentos
curl -X POST http://localhost:8090/keys/split \
  -H "X-Investigator-Key: $INVESTIGATOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"shares": 5, "threshold": 3}'

# 2. Cada fragmento e entregue a uma instituicao diferente
# 3. Tres instituicoes convergem e submetem seus fragmentos:
curl -X POST http://localhost:8090/keys/reconstruct \
  -H "X-Investigator-Key: $INVESTIGATOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key_month":"2026-06","shares":["<hex1>","<hex2>","<hex3>"]}'
# -> {"key_month":"2026-06","sk_hex":"<monthly_sk_reconstruida>"}
```

---

## Desenvolvimento

```bash
make test                # testes unitarios com race detector
make test-integration    # testes de integracao (requer Docker)
make build               # compila todos os binarios
make lint                # golangci-lint
```

### Migrações manuais

```bash
# Requer: psql, DB acessivel e DB_PASSWORD no ambiente
make migrate BANCO=all          # aplica migrations em ambos os bancos
make migrate BANCO=principal    # so banco principal
./scripts/migrate.sh bolo down  # rollback no banco BOLO
```

---

## Estrutura do repositório

```
cmd/
  coletor/     # camera ALPR
  servidor/    # servidor de custodia
  bolo/        # servidor exclusivo BOLO
  governanca/  # governanca (juiz + chaves)
  cliente/     # investigador
  genkeys/     # gerador de chaves (setup)
internal/
  alpr/        # tipos, builder, busca total
  bolo/        # blacklist, builder BOLO
  collector/   # pipeline de captura
  crypto/
    crumpling/ # k_0 -> Argon2id -> AES-256-GCM (puzzle prefix)
    ecc/       # X25519 + AES-256-GCM (busca total)
    shamir/    # Shamir's Secret Sharing em GF(2^8) puro
    signing/   # ECDSA P-256 (assinaturas de camera e token)
  governance/  # keygen, store, SplitSK/CombineSK
    govserver/ # servidor HTTP de governanca
  server/      # servidor de custodia (handlers HTTP)
  storage/     # queries PostgreSQL
  token/       # AuthToken (emissao, verificacao, middleware)
migrations/
  principal/   # schema do banco principal
  bolo/        # schema do banco BOLO
docs/
  adrs/        # Architecture Decision Records
  gitflow.md   # convencoes de branch e commit
scripts/       # setup.sh, migrate.sh
docker/        # Dockerfile compartilhado
```

---

## Decisões de arquitetura

| ADR | Decisão |
|---|---|
| [ADR-001](docs/adrs/ADR-001-linguagem-go.md) | Go como linguagem principal |
| [ADR-002](docs/adrs/ADR-002-modelo-dados-alpr.md) | Modelo de dados do registro ALPR |
| [ADR-003](docs/adrs/ADR-003-proof-of-work-argon2id.md) | Argon2id como proof-of-work |
| [ADR-004](docs/adrs/ADR-004-shamir-acesso-excepcional.md) | Acesso excepcional via Shamir + X25519 |

---

## Segurança

- **Nunca comite** `.env`, `secrets/`, arquivos `*.pem` ou `*.key`
- As chaves reais de produção nunca devem aparecer no código-fonte
- `K_GOV_HEX` e `MONTHLY_PK_HEX` são derivados em runtime do servidor de governança
- Rotacione a `monthly_sk` mensalmente via `POST /keys/split` com novos fragmentos

---

## Convenções de contribuição

Ver [`docs/gitflow.md`](docs/gitflow.md).
