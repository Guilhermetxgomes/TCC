//go:build integration

package server_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/server"
	"github.com/Guilhermetxgomes/TCC/internal/token"
)

// migrationsDir retorna o caminho absoluto de migrations/principal.
func migrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	// internal/server/integration_test.go → root é 3 níveis acima
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "migrations", "principal")
}

func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	migDir := migrationsDir(t)
	initSQL, err := os.ReadFile(filepath.Join(migDir, "000001_init.up.sql"))
	if err != nil {
		t.Fatalf("lendo migration: %v", err)
	}

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("tcc_test"),
		postgres.WithUsername("tcc"),
		postgres.WithPassword("tcc"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("Docker indisponível, pulando teste de integração: %v", err)
	}
	t.Cleanup(func() { pgc.Terminate(ctx) })

	connStr, err := pgc.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.ExecContext(ctx, string(initSQL)); err != nil {
		t.Fatalf("aplicando migration: %v", err)
	}
	return db
}

func TestIntegration_IngestAndSearchOpen(t *testing.T) {
	db := setupDB(t)

	judgeSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cameraSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	monthlySK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)

	srv := server.New(db, db, &judgeSK.PublicKey) // usa mesmo db para simplificar
	mux := http.NewServeMux()
	srv.Routes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Constrói e ingere um registro
	speed := float32(70.0)
	p := alpr.ALPRPlaintext{
		Plate:           "TCC3I23",
		PreciseLocation: alpr.Location{Latitude: -23.55, Longitude: -46.63},
		CapturedAt:      time.Now().UTC(),
		Confidence:      0.95,
		Speed:           &speed,
	}
	rec, err := alpr.Build(p, alpr.BuildConfig{
		CameraID:  "CAM-INT-001",
		KeyMonth:  "2026-06",
		Kgov:      kgov,
		MonthlyPK: monthlySK.PublicKey(),
		CameraSK:  cameraSK,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.Region = "SP"

	body, _ := json.Marshal(rec)
	resp, err := http.Post(ts.URL+"/records", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /records: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Busca aberta com token válido
	tok := token.AuthToken{
		TokenID:    uuid.New().String(),
		SearchType: token.SearchOpen,
		CameraID:   "CAM-INT-001",
		DecodedBy:  "delegado-integração",
		ExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	token.Issue(&tok, judgeSK)
	raw, _ := json.Marshal(tok)

	url := fmt.Sprintf("%s/records?camera_id=CAM-INT-001&start=2020-01-01T00:00:00Z&end=2030-01-01T00:00:00Z", ts.URL)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(raw))

	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /records: got %d", resp2.StatusCode)
	}

	var results []alpr.ALPRRecord
	json.NewDecoder(resp2.Body).Decode(&results)
	if len(results) == 0 {
		t.Error("busca aberta não retornou registros")
	}
	if results[0].RecordID != rec.RecordID {
		t.Errorf("record_id esperado %s, got %s", rec.RecordID, results[0].RecordID)
	}

	// Verifica decode_log
	var count int
	db.QueryRow("SELECT COUNT(*) FROM decode_logs WHERE record_id = $1", rec.RecordID).Scan(&count)
	if count == 0 {
		t.Error("decode_log não registrado após busca")
	}
}

func TestIntegration_IngestAndSearchClosed(t *testing.T) {
	db := setupDB(t)

	judgeSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cameraSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	monthlySK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)

	srv := server.New(db, db, &judgeSK.PublicKey)
	mux := http.NewServeMux()
	srv.Routes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	speed := float32(50.0)
	p := alpr.ALPRPlaintext{
		Plate:      "CLOSED1",
		CapturedAt: time.Now().UTC(),
		Speed:      &speed,
	}
	rec, _ := alpr.Build(p, alpr.BuildConfig{
		CameraID:  "CAM-INT-002",
		KeyMonth:  "2026-06",
		Kgov:      kgov,
		MonthlyPK: monthlySK.PublicKey(),
		CameraSK:  cameraSK,
	})
	rec.Region = "SP"

	body, _ := json.Marshal(rec)
	http.Post(ts.URL+"/records", "application/json", bytes.NewReader(body))

	// Busca fechada
	tok := token.AuthToken{
		TokenID:    uuid.New().String(),
		SearchType: token.SearchClosed,
		DecodedBy:  "delegado-fechado",
		ExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	token.Issue(&tok, judgeSK)
	raw, _ := json.Marshal(tok)

	plateHex := fmt.Sprintf("%x", rec.PlateHMAC)
	url := fmt.Sprintf("%s/records/closed?plate_hmac=%s", ts.URL, plateHex)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(raw))

	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /records/closed: got %d", resp.StatusCode)
	}

	var results []alpr.ALPRRecord
	json.NewDecoder(resp.Body).Decode(&results)
	if len(results) == 0 {
		t.Error("busca fechada não retornou registros")
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM decode_logs WHERE record_id = $1", rec.RecordID).Scan(&count)
	if count == 0 {
		t.Error("decode_log não registrado após busca fechada")
	}
}
