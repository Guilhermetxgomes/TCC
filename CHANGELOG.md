# Changelog

Todas as mudanças notáveis deste projeto são documentadas aqui.

---

## [v1.0.0] — 2026-06-30

Entrega do Trabalho de Conclusão de Curso para o orientador.
Sistema ALPR resistente à vigilância em massa — Escola Politécnica da USP.

---

### Marco 1 — Infraestrutura base e decisões de stack

- Módulo Go `github.com/Guilhermetxgomes/TCC` inicializado
- PostgreSQL como banco de dados (duas instâncias: principal + BOLO)
- Migrations SQL idempotentes (`migrations/principal/`, `migrations/bolo/`)
- Dockerfile compartilhado (multi-stage, imagem distroless ~10MB)
- `docker-compose.yml` com todos os serviços
- GitHub Actions CI: build, gofmt, go vet, golangci-lint, testes unitários e de integração
- Architecture Decision Records (ADR-001, ADR-002, ADR-003)
- Convenções de gitflow documentadas em `docs/gitflow.md`

---

### Marco 2 — Coletor e crumpling na borda

- **Crumpling** (`internal/crypto/crumpling`): `k_0` → `Argon2id(k_0, AD)` → `AES-256-GCM` com puzzle prefix
  - `DefaultEntropyBits = 14`: ~16ms por decifração (8MB RAM, inviável em massa)
  - Três payloads independentes por registro: Open, Closed, Total
- **`internal/alpr`**: tipos `ALPRRecord`, `ALPRPlaintext`, `BuildConfig`; builder que constrói os três payloads em paralelo
- **ECDSA P-256** (`internal/crypto/signing`): assinatura de câmera em cada registro
- **BOLO** (`internal/bolo`): `Blacklist` (JSON com `plate_hmacs` + `valid_until`), `Build` para construir `BOLORecord`
- **Coletor** (`internal/collector`): `Collector.Process` — Build → POST /records → se BOLO match → POST /bolo/records
- **`cmd/coletor`**: recarrega blacklist BOLO a cada 6h; loop com ticker e signal handling

---

### Marco 3 — Servidor cego e proof-of-work

- **`internal/storage`**: `InsertRecord`, `FindByCamera`, `FindByPlateHMAC`, `LogDecode`, `InsertBOLORecord`, `FindBOLOByPlateHMAC`
- **`internal/server`**: servidor HTTP de custódia com cinco endpoints:
  - `POST /records` — ingere `ALPRRecord` (sem autenticação)
  - `POST /bolo/records` — ingere `BOLORecord`
  - `GET /records` — busca aberta (token + puzzle PoW)
  - `GET /records/closed` — busca fechada (token + puzzle PoW)
  - `GET /bolo/records` — busca BOLO (token)
- **`internal/token`**: `AuthToken` (ECDSA P-256), `Issue`, `Verify`, middleware `RequireToken`
- **Testes de integração** (`internal/server/integration_test.go`): testcontainers PostgreSQL

---

### Marco 4 — Governança, tokens e modalidades de busca

- **`internal/governance`**: `GenerateMonthlyKeyPair` (X25519), `GenerateKgov`, `SaveMonthlyKey`/`LoadMonthlyKey` (AES-256-GCM com passphrase)
- **`internal/governance/govserver`**: servidor HTTP de governança:
  - `GET /keys/monthly-pk` — PK mensal pública
  - `GET /keys/kgov` — K_gov (autenticado por API key de câmera)
  - `POST /tokens` — emite `AuthToken` assinado pelo juiz
- **`internal/storage/tokens`**: persistência de tokens (`authorization_tokens`)
- **`cmd/governanca`**: carrega chaves do filesystem; auto-gera mensal + K_gov se não encontrar
- **`cmd/servidor`**: carrega `JUDGE_PK_PATH` PEM para validar tokens

---

### Marco 5 — Acesso excepcional e Shamir Secret Sharing

- **`internal/crypto/shamir`**: SSS em GF(2⁸) puro, sem dependências externas
  - Avaliação via esquema de Horner; reconstrução via interpolação de Lagrange em x=0
  - Multiplicação GF(2⁸) com polinômio irredutível 0x11b (FIPS 197)
- **`internal/crypto/ecc`**: `SealKey`/`OpenKey` — X25519 + AES-256-GCM; nonce embutido no blob
- **`internal/alpr/total_search`**: `DecryptTotal` — decifra `TotalPayload` usando SK mensal reconstruída
- **`internal/governance/shamir_dist`**: `SplitSK`/`CombineSK` com validação de PK derivada
- **`govserver`**: `POST /keys/split` e `POST /keys/reconstruct`
- **ADR-004**: documenta o protocolo de quórum institucional
- **`TestEmergencyAccessE2E`**: teste E2E completo sem banco (split → build → reconstruct → DecryptTotal)

---

### Marco 6 — Integração, testes e entrega ao orientador

- **`cmd/genkeys`**: gerador automático de chaves (ECDSA P-256 + X25519 + K_gov + .env)
- **`scripts/setup.sh`**: orquestra geração de chaves e verificação de build
- **`docker-compose.yml`**: migrations automáticas via services `migrate-principal` e `migrate-bolo`
- **`scripts/migrate.sh`**: suporte a `banco=all` e rollback
- **Teste de integração E2E** (`internal/collector/integration_e2e_test.go`): dois PostgreSQL reais, collector.Process → busca aberta + fechada + decode_logs
- **`Makefile`**: alvos `setup`, `up`, `down`, `test`, `test-integration`, `migrate`, `build`, `lint`
- **README** reescrito: diagrama ASCII, três níveis de acesso, guia de operação completo
- **ADR-004**: acesso excepcional via Shamir + X25519

---

[v1.0.0]: https://github.com/Guilhermetxgomes/TCC/releases/tag/v1.0.0
