# TCC — Sistema de Monitoramento de Tráfego Resistente à Vigilância em Massa

Trabalho de Conclusão de Curso — Engenharia da Computação, Escola Politécnica da USP.

Sistema ALPR (Automatic License Plate Recognition) que coleta dados de tráfego garantindo que nenhum acesso em massa seja possível sem autorização judicial e custo computacional deliberado.

## Arquitetura

O sistema é composto por cinco componentes independentes:

| Componente | Diretório | Descrição |
|---|---|---|
| Coletor | `cmd/coletor` | Câmera ALPR — cifra registros na borda antes de enviar |
| Servidor | `cmd/servidor` | Custódia cega — armazena blobs cifrados, nunca vê conteúdo |
| BOLO | `cmd/bolo` | Servidor exclusivo para registros de placas na lista negra |
| Governança | `cmd/governanca` | Juiz emite tokens; auditor fiscaliza logs |
| Cliente | `cmd/cliente` | Investigador — resolve puzzles e decifra registros autorizados |

### Três níveis de acesso

- **Busca Aberta** — por câmera + data, autorizada pelo juiz
- **Busca Fechada** — por placa (via HMAC), autorizada pelo juiz
- **Busca Total** — acesso excepcional via quórum do Comitê de Emergência (Shamir's Secret Sharing)

### Proteções anti-vigilância em massa

- Nenhuma placa armazenada em claro — só `HMAC(placa, K_gov)`
- Puzzle Argon2id (memory-hard) torna decifração em massa inviável
- BOLO via lista negra diária enviada pela Central de Investigações
- Acesso excepcional exige quórum institucional (representantes dos 3 poderes)

## Estrutura do repositório

```
cmd/          # entry points de cada componente
internal/
  alpr/       # tipos e schema do registro ALPR
  crypto/
    crumpling/ # mecanismo de crumpling (Argon2id + AES-256-GCM)
    ecc/       # encapsulamento de chave com X25519
    signing/   # assinaturas ECDSA
    shamir/    # fragmentação de chaves (Shamir's Secret Sharing)
  puzzle/      # geração e resolução de puzzles
  storage/     # abstrações de banco de dados
docs/
  adrs/        # Architecture Decision Records
  gitflow.md   # convenções de branch e commit
scripts/       # utilitários de setup e geração de chaves
docker/        # Dockerfiles por componente
```

## Como rodar localmente

### Pré-requisitos

- Go 1.22+
- Docker e Docker Compose

### Setup

```bash
git clone https://github.com/Guilhermetxgomes/TCC.git
cd TCC
go mod tidy
go build ./...
```

### Com Docker

```bash
docker compose up
```

## Decisões de arquitetura

Ver [`docs/adrs/`](docs/adrs/) para os Architecture Decision Records completos:

- [ADR-001](docs/adrs/ADR-001-linguagem-go.md) — Escolha de Go como linguagem principal
- [ADR-002](docs/adrs/ADR-002-modelo-dados-alpr.md) — Modelo de dados do registro ALPR
- [ADR-003](docs/adrs/ADR-003-proof-of-work-argon2id.md) — Argon2id como proof-of-work

## Convenções de contribuição

Ver [`docs/gitflow.md`](docs/gitflow.md).
