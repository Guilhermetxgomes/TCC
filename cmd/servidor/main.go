package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
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

	judgePK, err := loadJudgePublicKey(env("JUDGE_PK_PATH", "/run/secrets/judge.pub.pem"))
	if err != nil {
		slog.Error("falha ao carregar chave pública do juiz", "err", err)
		os.Exit(1)
	}

	srv := server.New(dbPrincipal, dbBOLO, judgePK)
	mux := http.NewServeMux()
	srv.Routes(mux)

	addr := ":" + env("PORT", "8080")
	slog.Info("servidor iniciado", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("servidor encerrado", "err", err)
		os.Exit(1)
	}
}

func loadJudgePublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, os.ErrInvalid
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*ecdsa.PublicKey), nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
