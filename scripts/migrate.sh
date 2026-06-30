#!/bin/sh
# Aplica as migrations SQL no banco especificado.
# Uso: ./scripts/migrate.sh <banco> [up|down]
#   banco: principal | bolo | all
#   direção: up (padrão) | down
#
# Exemplos:
#   ./scripts/migrate.sh all
#   ./scripts/migrate.sh principal
#   ./scripts/migrate.sh bolo down

set -e

BANCO=${1:?"Informe o banco: principal | bolo | all"}
DIRECAO=${2:-up}

DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-tcc}
DB_PASSWORD=${DB_PASSWORD:?"DB_PASSWORD não definido"}

run_migrations() {
    NOME=$1
    DB_NAME=$2
    DIR="migrations/${NOME}"

    if [ ! -d "$DIR" ]; then
        echo "ERRO: diretório $DIR não encontrado."
        exit 1
    fi

    echo "==> Aplicando migrations ($DIRECAO) em $DB_NAME..."
    for f in $(ls "${DIR}/"*".${DIRECAO}.sql" 2>/dev/null | sort); do
        echo "   -> $f"
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$f"
    done
    echo "==> $DB_NAME: migrations concluídas."
}

case $BANCO in
    principal) run_migrations principal "${DB_PRINCIPAL_NAME:-tcc_principal}" ;;
    bolo)      run_migrations bolo      "${DB_BOLO_NAME:-tcc_bolo}" ;;
    all)
        run_migrations principal "${DB_PRINCIPAL_NAME:-tcc_principal}"
        run_migrations bolo      "${DB_BOLO_NAME:-tcc_bolo}"
        ;;
    *)
        echo "ERRO: banco inválido '$BANCO'. Use: principal | bolo | all"
        exit 1
        ;;
esac
