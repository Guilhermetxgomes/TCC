# ADR-004 — Acesso Excepcional via Shamir's Secret Sharing e Busca Total

**Status:** Aceito
**Data:** 2026-06-30

## Contexto

O sistema ALPR precisa de um mecanismo de acesso excepcional que satisfaça três requisitos simultâneos:

1. **Sem acesso unilateral:** nenhuma entidade isolada — nem a câmera, nem o servidor, nem o juiz — pode decifrar um registro sem cooperação institucional.
2. **Quórum obrigatório:** o acesso deve exigir a participação de representantes de múltiplas instituições (e.g., Executivo, Judiciário, Ministério Público).
3. **Sem comprometer as buscas ordinárias:** as modalidades Aberta e Fechada (Marcos 2 e 3) não podem ser afetadas pelo mecanismo de emergência.

A busca total é o terceiro nível de acesso do sistema. Diferente das buscas ordinária (por câmera/período) e fechada (por HMAC de placa), ela recupera o plaintext sem nenhum puzzle Argon2id — ela é custosa a nível institucional, não computacional.

## Decisão

**Protocolo de duas camadas:**

### Camada 1 — Cifração total do registro (X25519 + AES-256-GCM)

Ao construir cada `ALPRRecord`, a câmera:

1. Gera uma chave efêmera `k` (32 bytes aleatórios)
2. Cifra o `ALPRPlaintext` com AES-256-GCM usando `k` → `TotalPayload.{Ciphertext, Nonce}`
3. Encapsula `k` com a PK mensal X25519 do servidor de governança:
   - Gera par efêmero X25519 `(eph_sk, eph_pk)`
   - Computa `shared = X25519(eph_sk, monthly_pk)` → deriva `aes_key = SHA-256(shared)`
   - Cifra: `TotalPayload.EncryptedKey = nonce_12 || AES-GCM(aes_key, k)`
   - Armazena `TotalPayload.EphemeralPK = eph_pk`

A `monthly_pk` é pública e obtida do servidor de governança na inicialização do coletor. Para decifrar, é necessária a `monthly_sk` correspondente.

### Camada 2 — Fragmentação da SK mensal (Shamir's Secret Sharing)

A `monthly_sk` X25519 (32 bytes) é dividida em `n` fragmentos com threshold `t`, usando SSS em GF(2⁸):

- Parâmetros recomendados: `n = 5`, `t = 3` (representantes dos 3 poderes + margem)
- Cada fragmento é entregue a uma instituição diferente
- Qualquer coalizão de ≥ t instituições pode reconstruir a SK
- Qualquer coalizão de < t instituições não obtém nenhuma informação sobre a SK

O endpoint `POST /keys/split` do servidor de governança realiza a divisão.
O endpoint `POST /keys/reconstruct` aceita ≥ t fragmentos e retorna a SK reconstruída, validando que a PK derivada bate com a PK pública registrada.

### Fluxo de acesso excepcional

```
1. [Governança] monthly_sk → SplitSK(n=5, t=3) → 5 fragmentos distribuídos
2. [Câmera]     ALPRRecord.TotalPayload ← SealKey(k, monthly_pk)
3. [Comitê]     3 instituições enviam fragmentos → POST /keys/reconstruct
4. [Investigador] monthly_sk reconstruída + DecryptTotal → ALPRPlaintext
```

## Implementação GF(2⁸) sem dependências externas

A implementação SSS utiliza aritmética no corpo de Galois GF(2⁸) com polinômio irredutível `x⁸ + x⁴ + x³ + x + 1` (0x11b), conforme AES FIPS 197:

- **Split:** para cada byte do segredo, gera um polinômio aleatório de grau `t-1` com o byte como termo constante; avalia em `x = 1..n`
- **Combine:** interpolação de Lagrange em `x = 0`; multiplicação em GF(2⁸) via deslocamento de bits com redução por 0x11b; inversão via `a^254` (teorema de Fermat em GF(2⁸))
- **Formato do fragmento:** `[x || f(x)[0] || ... || f(x)[len-1]]` — um byte de índice seguido de um byte por posição do segredo

A decisão de não usar `hashicorp/vault/shamir` evita dependência transitiva de ~8MB de código de infraestrutura de cloud em um binário de ~5MB.

## Alternativas consideradas

| Alternativa | Descartada por |
|---|---|
| `hashicorp/vault/shamir` | Dependência pesada incompatível com módulo Go minimal |
| Threshold ECDSA (t-of-n assinaturas) | Complexidade de protocolo muito maior; não resolve o problema de decifração |
| Custódia HSM centralizada | Ponto único de falha institucional; contradiz o modelo de quórum |
| Replicar monthly_sk para todas as partes | Elimina a propriedade de quórum mínimo |

## Consequências

**Positivas:**
- Sem ponto único de comprometimento da SK mensal
- A PK mensal é pública — câmeras não precisam de segredos para cifrar
- Rotação mensal da SK limita a janela de exposição em caso de comprometimento
- Implementação auditável em ~100 linhas de Go puro

**Negativas:**
- O servidor de governança deve manter a SK em memória durante o período mensal
- A reconstrução exige que todas as t instituições estejam disponíveis simultaneamente
- Não há recuperação automática se < t fragmentos forem perdidos

## Referências

- `internal/crypto/shamir/shamir.go` — implementação GF(2⁸) (T5.1)
- `internal/governance/shamir_dist.go` — SplitSK / CombineSK (T5.2/T5.3)
- `internal/crypto/ecc/ecc.go` — SealKey / OpenKey X25519 (T5.4)
- `internal/alpr/total_search.go` — DecryptTotal (T5.4)
- `internal/alpr/total_search_test.go` — TestEmergencyAccessE2E (T5.5)
- Adi Shamir, "How to Share a Secret", *Communications of the ACM*, 1979
- FIPS 197 — Advanced Encryption Standard (campo GF(2⁸))
