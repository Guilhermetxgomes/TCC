.PHONY: setup up down test test-integration migrate build lint

# Gera todas as chaves criptográficas e um .env funcional
setup:
	@./scripts/setup.sh

# Sobe todos os serviços (migrations automáticas incluídas)
up:
	docker compose up --build

# Sobe em background
up-d:
	docker compose up --build -d

# Encerra e remove containers e volumes
down:
	docker compose down -v

# Testes unitários com detector de race conditions
test:
	go test -race ./...

# Testes de integração (requer Docker)
test-integration:
	go test -tags integration -race -timeout 180s ./...

# Aplica migrations manualmente (requer psql e DB acessível)
# Uso: make migrate BANCO=principal  ou  make migrate BANCO=all
BANCO ?= all
migrate:
	./scripts/migrate.sh $(BANCO)

# Compila todos os binários
build:
	go build ./...

# Lint (requer golangci-lint instalado)
lint:
	golangci-lint run
