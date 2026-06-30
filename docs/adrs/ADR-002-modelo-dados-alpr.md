# ADR-002 — Modelo de dados do registro ALPR

**Status:** Aceito
**Data:** 2026-06-29

## Contexto

Necessidade de um contrato de dados entre o coletor (Marco 2) e o servidor de custódia (Marco 3) que suporte três níveis de acesso sem expor dados sensíveis ao servidor.

## Decisão

Cada captura ALPR gera um `ALPRRecord` com três payloads cifrados independentes e um `BOLORecord` armazenado em servidor separado quando a placa está na lista negra.

## Parâmetros definidos

| Parâmetro | Valor |
|---|---|
| `entropy_bits` | 14 bits (2¹⁴ ≈ 16.384 tentativas) |
| Argon2id memory | 8MB |
| Argon2id time | 1 |
| `K_gov` | Gerada pela governança, distribuída às câmeras com a PK mensal |
| EphemeralPK | Por registro (não por sessão) |
| Banco BOLO | Servidor físico separado |

## Schema normativo

Ver `internal/alpr/record.go`.

## Consequências

- Servidor de custódia nunca vê conteúdo em claro
- Busca fechada indexada por `HMAC(placa, K_gov)` — placa nunca em claro
- Separação física dos bancos principal e BOLO
