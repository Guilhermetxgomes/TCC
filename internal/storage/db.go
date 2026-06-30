package storage

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

// Connect abre uma conexão com o PostgreSQL usando variáveis de ambiente.
// Variáveis esperadas: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD.
func Connect() (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		env("DB_HOST", "localhost"),
		env("DB_PORT", "5432"),
		env("DB_NAME", "tcc_principal"),
		env("DB_USER", "tcc"),
		os.Getenv("DB_PASSWORD"),
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage.Connect: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("storage.Connect ping: %w", err)
	}
	return db, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
