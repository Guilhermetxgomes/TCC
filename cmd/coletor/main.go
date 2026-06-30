package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/bolo"
	"github.com/Guilhermetxgomes/TCC/internal/collector"
	"github.com/Guilhermetxgomes/TCC/internal/crypto/signing"
)

func main() {
	cameraID := mustEnv("CAMERA_ID")
	region := env("REGION", "SP")
	keyMonth := mustEnv("KEY_MONTH")
	servidorURL := mustEnv("SERVIDOR_URL")
	cameraKeyPath := env("CAMERA_SK_PATH", "/run/secrets/camera.pem")
	blacklistPath := env("BOLO_BLACKLIST_PATH", "/etc/coletor/blacklist.json")
	intervalMs := envDuration("CAPTURE_INTERVAL_MS", 1000)

	kgov, err := hex.DecodeString(mustEnv("K_GOV_HEX"))
	if err != nil || len(kgov) != 32 {
		slog.Error("K_GOV_HEX inválido (precisa ser 64 hex chars)")
		os.Exit(1)
	}

	monthlyPKBytes, err := hex.DecodeString(mustEnv("MONTHLY_PK_HEX"))
	if err != nil {
		slog.Error("MONTHLY_PK_HEX inválido", "err", err)
		os.Exit(1)
	}
	monthlyPK, err := ecdh.X25519().NewPublicKey(monthlyPKBytes)
	if err != nil {
		slog.Error("MONTHLY_PK_HEX: chave X25519 inválida", "err", err)
		os.Exit(1)
	}

	cameraSK, err := signing.LoadOrGenerateKey(cameraKeyPath)
	if err != nil {
		slog.Error("falha ao carregar chave da câmera", "err", err)
		os.Exit(1)
	}

	cfg := collector.Config{
		CameraID:    cameraID,
		Region:      region,
		KeyMonth:    keyMonth,
		Kgov:        kgov,
		MonthlyPK:   monthlyPK,
		CameraSK:    cameraSK,
		ServidorURL: servidorURL,
	}
	col := collector.New(cfg)

	bl, err := bolo.Load(blacklistPath)
	if err != nil {
		slog.Warn("lista BOLO não carregada (continuando sem ela)", "err", err)
	} else {
		col.SetBlacklist(bl)
	}

	slog.Info("coletor iniciado", "camera_id", cameraID, "interval_ms", intervalMs)

	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	boloReloadTicker := time.NewTicker(6 * time.Hour)
	defer boloReloadTicker.Stop()

	for {
		select {
		case <-quit:
			slog.Info("coletor encerrado")
			return

		case <-boloReloadTicker.C:
			if newBL, err := bolo.Load(blacklistPath); err == nil {
				col.SetBlacklist(newBL)
				slog.Info("lista BOLO recarregada")
			} else {
				slog.Warn("falha ao recarregar lista BOLO", "err", err)
			}

		case <-ticker.C:
			capture := alpr.NewCapture(cameraID)
			if err := col.Process(capture.ToPlaintext()); err != nil {
				slog.Error("falha ao processar captura", "err", err)
			}
		}
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("variável de ambiente obrigatória não definida", "key", key)
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

func envDuration(key string, fallbackMs int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallbackMs
	}
	d, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallbackMs
	}
	return d
}
