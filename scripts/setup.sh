#!/bin/sh
# Setup inicial do ambiente de desenvolvimento.
# Uso: ./scripts/setup.sh

set -e

echo "==> Verificando dependências..."
command -v docker >/dev/null 2>&1 || { echo "Docker não encontrado. Instale em https://docs.docker.com/get-docker/"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Go não encontrado. Instale em https://go.dev/dl/"; exit 1; }

echo "==> Criando .env a partir de .env.example..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "   .env criado. Edite DB_PASSWORD e as chaves criptográficas antes de subir."
else
    echo "   .env já existe, pulando."
fi

echo "==> Baixando dependências Go..."
go mod download

echo "==> Verificando build..."
go build ./...

echo ""
echo "Pronto! Para subir o ambiente completo:"
echo "  docker compose up --build"
