#!/bin/sh
# Aplica as migrations SQL no banco especificado.
# Uso: ./scripts/migrate.sh <banco> [up|down]
#   banco: principal | bolo
#   direção: up (padrão) | down
#
# Exemplo:
#   ./scripts/migrate.sh principal
#   ./scripts/migrate.sh bolo down

set -e

BANCO=${1:?"Informe o banco: principal ou bolo"}
DIRECAO=${2:-up}
DIR="migrations/${BANCO}"

if [ ! -d "$DIR" ]; then
    echo "Diretório $DIR não encontrado."
    exit 1
fi

DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-tcc}
DB_PASSWORD=${DB_PASSWORD:?"DB_PASSWORD não definido"}

case $BANCO in
    principal) DB_NAME=${DB_PRINCIPAL_NAME:-tcc_principal} ;;
    bolo)      DB_NAME=${DB_BOLO_NAME:-tcc_bolo} ;;
esac

echo "==> Aplicando migrations ($DIRECAO) em $DB_NAME..."

for f in $(ls "$DIR"/*.${DIRECAO}.sql | sort); do
    echo "   -> $f"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$f"
done

echo "==> Migrations concluídas."
