# Gitflow — Convenções de trabalho

## Branches

| Branch | Propósito |
|---|---|
| `main` | Código estável — merge apenas via PR aprovado |
| `feature/<nome>` | Desenvolvimento de features |
| `fix/<nome>` | Correção de bugs |
| `chore/<nome>` | Tarefas de infraestrutura, configuração |

Exemplos:
```
feature/T2.1-coletor-crumpling
fix/T3.2-indexacao-plate-hmac
chore/T1.8-docker-compose
```

## Commits

Padrão [Conventional Commits](https://www.conventionalcommits.org/):

```
<tipo>(<escopo>): <descrição curta>

feat(coletor): implementa crumpling com Argon2id
fix(servidor): corrige indexação por plate_hmac
docs(adrs): adiciona ADR-003 sobre proof-of-work
chore(docker): adiciona docker-compose para desenvolvimento
test(crypto): adiciona testes de integração do crumpling
```

Tipos válidos: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`

## Pull Requests

- Todo merge em `main` exige PR
- Mínimo **1 aprovação** antes de mergear
- PR deve referenciar a issue: `Closes #7`
- Branch deve estar atualizada com `main` antes do merge

## Critério de "done"

Uma task está concluída quando:
1. Código mergeado em `main` via PR aprovado
2. Issue fechada no GitHub
3. Card movido para "Done" no board
