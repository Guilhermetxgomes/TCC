# ADR-003 — Estratégia de Proof-of-Work: Argon2id

**Status:** Aceito
**Data:** 2026-06-29

## Contexto

O mecanismo de crumpling requer uma função de derivação `k_0 → k_ccz` que torne o brute-force do sufixo de `k_0` caro o suficiente para inviabilizar vigilância em massa, mas viável para investigação direcionada.

## Decisão

**Argon2id** como função de derivação, substituindo SHA-256 simples.

## Justificativa

SHA-256 é acelerável por GPU (10B ops/s em RTX 3090), tornando 2^20 tentativas triviais (~0,1ms). Argon2id é memory-hard: cada tentativa requer acesso sequencial a blocos de RAM, neutralizando a vantagem de GPU/ASIC.

## Parâmetros

```go
argon2.IDKey(k0, salt, time=1, memory=8*1024, threads=1, keyLen=32)
```

Com `entropy_bits=14` (2¹⁴ ≈ 16.384 tentativas):
- Investigador (8 núcleos): ~4 segundos por registro
- Atacante com GPU: ~4 segundos por registro (memória limita paralelismo)
- 1M registros (atacante): ~46 dias

## Consequências

- Decifração de um registro leva ~4s para o investigador — aceitável para investigações pontuais
- Parâmetros calibráveis pelo Conselho de Governança sem mudança de protocolo
- `golang.org/x/crypto/argon2` já é dependência do projeto (via T1.4)
