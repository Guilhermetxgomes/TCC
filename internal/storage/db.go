package storage

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

// Connect abre uma conexão com o banco principal.
// Variáveis: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD.
func Connect() (*sql.DB, error) {
	return connectWith("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
		"localhost", "5432", "tcc_principal", "tcc")
}

// ConnectBOLO abre uma conexão com o banco BOLO.
// Variáveis: BOLO_DB_HOST, BOLO_DB_PORT, BOLO_DB_NAME, BOLO_DB_USER, BOLO_DB_PASSWORD.
func ConnectBOLO() (*sql.DB, error) {
	return connectWith("BOLO_DB_HOST", "BOLO_DB_PORT", "BOLO_DB_NAME", "BOLO_DB_USER", "BOLO_DB_PASSWORD",
		"localhost", "5432", "tcc_bolo", "tcc")
}

func connectWith(hostKey, portKey, nameKey, userKey, passKey, defHost, defPort, defName, defUser string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		env(hostKey, defHost),
		env(portKey, defPort),
		env(nameKey, defName),
		env(userKey, defUser),
		os.Getenv(passKey),
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
