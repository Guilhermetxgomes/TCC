#!/bin/sh
# Setup inicial do ambiente de desenvolvimento.
# Gera todas as chaves criptográficas e um .env funcional.
# Uso: ./scripts/setup.sh [passphrase]
#
# Se a passphrase não for informada como argumento, será pedida interativamente.

set -e

echo "==> Verificando dependências..."
command -v go >/dev/null 2>&1 || { echo "ERRO: Go não encontrado. Instale em https://go.dev/dl/"; exit 1; }
command -v docker >/dev/null 2>&1 || echo "AVISO: Docker não encontrado — 'make up' não funcionará."

# Passphrase para cifrar a chave mensal X25519
if [ -n "$1" ]; then
    PASSPHRASE="$1"
elif [ -n "$KEY_PASSPHRASE" ]; then
    PASSPHRASE="$KEY_PASSPHRASE"
else
    printf "Passphrase para a chave mensal (mínimo 12 caracteres): "
    read -r PASSPHRASE
    if [ ${#PASSPHRASE} -lt 12 ]; then
        echo "ERRO: passphrase muito curta."
        exit 1
    fi
fi

echo ""
echo "==> Baixando dependências Go..."
go mod download

echo ""
echo "==> Gerando chaves criptográficas e .env..."
if [ -f .env ]; then
    echo "   AVISO: .env já existe — fazendo backup em .env.bak"
    cp .env .env.bak
fi

KEY_PASSPHRASE="$PASSPHRASE" go run ./cmd/genkeys -- --secrets-dir ./secrets --passphrase "$PASSPHRASE"

echo ""
echo "==> Verificando build..."
go build ./...

echo ""
echo "============================================================"
echo "  Setup concluído!"
echo "============================================================"
echo ""
echo "  1. Edite .env e defina uma DB_PASSWORD segura"
echo "  2. make up                 # sobe todos os serviços"
echo "  3. make test               # testes unitários"
echo "  4. make test-integration   # testes com Docker (requer Docker)"
echo ""
echo "  ATENCAO: nunca comite os arquivos secrets/ ou .env"
echo "============================================================"
