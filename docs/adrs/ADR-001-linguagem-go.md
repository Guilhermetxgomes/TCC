# ADR-001 — Escolha da linguagem e stack principal

**Status:** Aceito
**Data:** 2026-06-29

## Contexto

O projeto requer primitivas criptográficas avançadas (AES-GCM, Curve25519, ECDSA, Shamir), servidor HTTP com autenticação, banco de dados e deploy via Docker.

## Decisão

**Go** como linguagem principal do projeto.

## Justificativa

- Biblioteca criptográfica madura (`crypto/*` + `golang.org/x/crypto`)
- Binário estático: imagens Docker ~10MB, viável para edge no futuro
- Concorrência nativa via goroutines
- Curva de aprendizado baixa vs Rust/C — compatível com prazo do TCC
- Mesmo código serve para TCC e produção futura

## Primitivas e pacotes

| Primitiva | Pacote |
|---|---|
| AES-256-GCM | `crypto/aes` + `crypto/cipher` |
| SHA-256 | `crypto/sha256` |
| ECDSA | `crypto/ecdsa` |
| X25519 | `crypto/ecdh` |
| Argon2id (PoW) | `golang.org/x/crypto/argon2` |
| Shamir's Secret Sharing | `github.com/hashicorp/vault/shamir` |

## Consequências

- Coletor implementado em Go; portável para C/Rust se o hardware exigir
- Time dedica ~2 semanas para nivelamento em Go antes dos Marcos 2 e 3
