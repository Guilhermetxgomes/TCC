package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/Guilhermetxgomes/TCC/internal/server"
	"github.com/Guilhermetxgomes/TCC/internal/storage"
)

func main() {
	dbPrincipal, err := storage.Connect()
	if err != nil {
		slog.Error("falha ao conectar banco principal", "err", err)
		os.Exit(1)
	}
	defer dbPrincipal.Close()

	dbBOLO, err := storage.ConnectBOLO()
	if err != nil {
		slog.Error("falha ao conectar banco BOLO", "err", err)
		os.Exit(1)
	}
	defer dbBOLO.Close()

	srv := server.New(dbPrincipal, dbBOLO)
	mux := http.NewServeMux()
	srv.Routes(mux)

	addr := ":" + env("PORT", "8080")
	slog.Info("servidor iniciado", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("servidor encerrado", "err", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
