package collector

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/bolo"
)

// Config reúne tudo que o coletor precisa para operar.
type Config struct {
	CameraID    string
	Region      string
	KeyMonth    string
	Kgov        []byte
	MonthlyPK   *ecdh.PublicKey
	CameraSK    *ecdsa.PrivateKey
	ServidorURL string // ex: "http://servidor:8080"
}

// Collector processa capturas e envia ao servidor de custódia.
type Collector struct {
	cfg       Config
	blacklist bolo.Blacklist
	http      *http.Client
}

func New(cfg Config) *Collector {
	return &Collector{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}
}

// SetBlacklist atualiza a lista negra BOLO em memória.
func (c *Collector) SetBlacklist(bl bolo.Blacklist) {
	c.blacklist = bl
}

// Process recebe uma captura, constrói o ALPRRecord, verifica BOLO e envia ao servidor.
func (c *Collector) Process(capture alpr.ALPRPlaintext) error {
	buildCfg := alpr.BuildConfig{
		CameraID:  c.cfg.CameraID,
		KeyMonth:  c.cfg.KeyMonth,
		Kgov:      c.cfg.Kgov,
		MonthlyPK: c.cfg.MonthlyPK,
		CameraSK:  c.cfg.CameraSK,
	}

	rec, err := alpr.Build(capture, buildCfg)
	if err != nil {
		return fmt.Errorf("collector.Process build: %w", err)
	}
	rec.Region = c.cfg.Region

	if err := c.postJSON(c.cfg.ServidorURL+"/records", rec); err != nil {
		return fmt.Errorf("collector.Process post record: %w", err)
	}

	if c.blacklist.Match(rec.PlateHMAC) {
		slog.Info("BOLO match", "record_id", rec.RecordID)
		if err := c.processBOLO(capture, rec.PlateHMAC); err != nil {
			// Não bloqueia: log e continua — o registro principal já foi enviado.
			slog.Error("BOLO post falhou", "err", err, "record_id", rec.RecordID)
		}
	}
	return nil
}

func (c *Collector) processBOLO(capture alpr.ALPRPlaintext, plateHMAC []byte) error {
	boloCfg := bolo.BuildConfig{
		Kgov:     c.cfg.Kgov,
		CameraSK: c.cfg.CameraSK,
		Region:   c.cfg.Region,
	}
	boloRec, err := bolo.Build(capture, plateHMAC, boloCfg)
	if err != nil {
		return fmt.Errorf("bolo.Build: %w", err)
	}
	return c.postJSON(c.cfg.ServidorURL+"/bolo/records", boloRec)
}

func (c *Collector) postJSON(url string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	resp, err := c.http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("servidor retornou %d para %s", resp.StatusCode, url)
	}
	return nil
}
