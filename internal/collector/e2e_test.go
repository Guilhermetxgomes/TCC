package collector_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/bolo"
	"github.com/Guilhermetxgomes/TCC/internal/collector"
)

func newE2EConfig(t *testing.T, servidorURL string) (collector.Config, []byte) {
	t.Helper()
	cameraSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	monthlySK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)
	return collector.Config{
		CameraID:    "CAM-E2E-001",
		Region:      "SP-Teste",
		KeyMonth:    "2026-06",
		Kgov:        kgov,
		MonthlyPK:   monthlySK.PublicKey(),
		CameraSK:    cameraSK,
		ServidorURL: servidorURL,
	}, kgov
}

func computeHMAC(plate string, kgov []byte) []byte {
	mac := hmac.New(sha256.New, kgov)
	mac.Write([]byte(plate))
	return mac.Sum(nil)
}

func blacklistWithPlate(plate string, kgov []byte) bolo.Blacklist {
	h := computeHMAC(plate, kgov)
	validUntil := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	data, _ := json.Marshal(map[string]any{
		"plate_hmacs": []string{hex.EncodeToString(h)},
		"valid_until": validUntil,
	})
	bl, _ := bolo.Parse(data)
	return bl
}

func TestEndToEnd_RecordPosted(t *testing.T) {
	var recordsReceived atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/records" {
			http.NotFound(w, r)
			return
		}
		var rec alpr.ALPRRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			t.Errorf("payload inválido: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if rec.RecordID == "" {
			t.Error("record_id ausente")
		}
		if len(rec.Signature) == 0 {
			t.Error("signature ausente")
		}
		if len(rec.OpenPayload.Ciphertext) == 0 {
			t.Error("open_payload vazio")
		}
		recordsReceived.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"record_id":%q}`, rec.RecordID)
	}))
	defer srv.Close()

	cfg, _ := newE2EConfig(t, srv.URL)
	col := collector.New(cfg)

	speed := float32(60.0)
	plaintext := alpr.ALPRPlaintext{
		Plate:           "TCC1A23",
		PreciseLocation: alpr.Location{Latitude: -23.55, Longitude: -46.63},
		CapturedAt:      time.Now().UTC(),
		Confidence:      0.99,
		Speed:           &speed,
	}

	if err := col.Process(plaintext); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if recordsReceived.Load() != 1 {
		t.Errorf("esperado 1 POST /records, got %d", recordsReceived.Load())
	}
}

func TestEndToEnd_BOLOMatchSendsToBoloEndpoint(t *testing.T) {
	var boloReceived atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("POST /records", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"record_id":"x"}`))
	})
	mux.HandleFunc("POST /bolo/records", func(w http.ResponseWriter, r *http.Request) {
		boloReceived.Add(1)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"record_id":"x"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg, kgov := newE2EConfig(t, srv.URL)
	col := collector.New(cfg)

	plate := "BOLO001"
	col.SetBlacklist(blacklistWithPlate(plate, kgov))

	speed := float32(80.0)
	capture := alpr.ALPRPlaintext{
		Plate:           plate,
		PreciseLocation: alpr.Location{Latitude: -23.55, Longitude: -46.63},
		CapturedAt:      time.Now().UTC(),
		Speed:           &speed,
	}

	if err := col.Process(capture); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if boloReceived.Load() != 1 {
		t.Errorf("esperado 1 POST /bolo/records, got %d", boloReceived.Load())
	}
}

func TestEndToEnd_NoBoloForUnmatchedPlate(t *testing.T) {
	var boloReceived atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("POST /records", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"record_id":"x"}`))
	})
	mux.HandleFunc("POST /bolo/records", func(w http.ResponseWriter, r *http.Request) {
		boloReceived.Add(1)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"record_id":"x"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg, kgov := newE2EConfig(t, srv.URL)
	col := collector.New(cfg)
	// Lista com placa diferente
	col.SetBlacklist(blacklistWithPlate("OUTROOO", kgov))

	speed := float32(50.0)
	if err := col.Process(alpr.ALPRPlaintext{
		Plate:      "INOCENTE",
		CapturedAt: time.Now().UTC(),
		Speed:      &speed,
	}); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if boloReceived.Load() != 0 {
		t.Errorf("não esperava POST /bolo/records, got %d", boloReceived.Load())
	}
}
