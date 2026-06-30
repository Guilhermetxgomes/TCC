package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"

	"github.com/Guilhermetxgomes/TCC/internal/governance"
	"github.com/Guilhermetxgomes/TCC/internal/governance/govserver"
	"github.com/Guilhermetxgomes/TCC/internal/storage"
)

func main() {
	judgeSK, err := loadJudgeSK(mustEnv("JUDGE_SK_PATH"))
	if err != nil {
		slog.Error("falha ao carregar chave do juiz", "err", err)
		os.Exit(1)
	}

	keyStorePath := env("MONTHLY_KEY_PATH", "/run/secrets/monthly.key")
	passphrase := []byte(mustEnv("KEY_PASSPHRASE"))

	monthSK, keyMonth, err := governance.LoadMonthlyKey(keyStorePath, passphrase)
	if err != nil {
		slog.Info("chave mensal não encontrada — gerando nova", "path", keyStorePath)
		monthSK, err = governance.GenerateMonthlyKeyPair()
		if err != nil {
			slog.Error("falha ao gerar chave mensal", "err", err)
			os.Exit(1)
		}
		keyMonth = governance.KeyMonth()
		if err := governance.SaveMonthlyKey(keyStorePath, monthSK, passphrase); err != nil {
			slog.Error("falha ao salvar chave mensal", "err", err)
			os.Exit(1)
		}
		slog.Info("chave mensal gerada e salva", "key_month", keyMonth)
	} else {
		slog.Info("chave mensal carregada", "key_month", keyMonth)
	}

	kgov, err := loadOrGenerateKgov(env("KGOV_PATH", "/run/secrets/kgov.bin"))
	if err != nil {
		slog.Error("falha ao carregar K_gov", "err", err)
		os.Exit(1)
	}

	db, err := storage.Connect()
	if err != nil {
		slog.Warn("banco principal indisponível — tokens não serão persistidos", "err", err)
		db = nil
	} else {
		defer db.Close()
	}

	srv := govserver.New(govserver.Config{
		JudgeSK:            judgeSK,
		MonthlySK:          monthSK,
		KeyMonth:           keyMonth,
		Kgov:               kgov,
		CameraAPIKey:       mustEnv("CAMERA_API_KEY"),
		InvestigatorAPIKey: mustEnv("INVESTIGATOR_API_KEY"),
		DB:                 db,
	})

	mux := http.NewServeMux()
	srv.Routes(mux)

	addr := ":" + env("PORT", "8090")
	slog.Info("servidor de governança iniciado", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("servidor encerrado", "err", err)
		os.Exit(1)
	}
}

func loadJudgeSK(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, os.ErrInvalid
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func loadOrGenerateKgov(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) == 32 {
		return data, nil
	}
	slog.Info("K_gov não encontrado — gerando novo", "path", path)
	kgov, err := governance.GenerateKgov()
	if err != nil {
		return nil, err
	}
	if werr := os.WriteFile(path, kgov, 0600); werr != nil {
		slog.Warn("falha ao persistir K_gov", "err", werr)
	}
	return kgov, nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("variável obrigatória não definida", "key", key)
		os.Exit(1)
	}
	return v
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
