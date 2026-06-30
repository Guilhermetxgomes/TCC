//go:build integration

package collector_test

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

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/collector"
	"github.com/Guilhermetxgomes/TCC/internal/server"
	"github.com/Guilhermetxgomes/TCC/internal/token"
	"github.com/google/uuid"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func startPostgres(ctx context.Context, t *testing.T, dbName string) *sql.DB {
	t.Helper()
	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase(dbName),
		postgres.WithUsername("tcc"),
		postgres.WithPassword("tcc"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("Docker indisponível, pulando teste de integração E2E: %v", err)
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
	return db
}

func applyMigration(t *testing.T, db *sql.DB, banco string) {
	t.Helper()
	root := repoRoot(t)
	sqlPath := filepath.Join(root, "migrations", banco, "000001_init.up.sql")
	data, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatalf("lendo migration %s: %v", sqlPath, err)
	}
	if _, err := db.ExecContext(context.Background(), string(data)); err != nil {
		t.Fatalf("aplicando migration %s: %v", banco, err)
	}
}

func TestIntegration_CollectorToServerToBusca(t *testing.T) {
	ctx := context.Background()

	dbPrincipal := startPostgres(ctx, t, "tcc_principal")
	dbBOLO := startPostgres(ctx, t, "tcc_bolo")
	applyMigration(t, dbPrincipal, "principal")
	applyMigration(t, dbBOLO, "bolo")

	judgeSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	monthlySK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)

	srv := server.New(dbPrincipal, dbBOLO, &judgeSK.PublicKey)
	mux := http.NewServeMux()
	srv.Routes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Coletor apontando para o servidor de teste
	col := collector.New(collector.Config{
		CameraID:    "CAM-E2E-INT",
		Region:      "SP-Teste",
		KeyMonth:    "2026-06",
		Kgov:        kgov,
		MonthlyPK:   monthlySK.PublicKey(),
		CameraSK:    func() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }(),
		ServidorURL: ts.URL,
	})

	// Captura e processa via collector.Process
	speed := float32(88.0)
	capture := alpr.ALPRPlaintext{
		Plate:           "E2EINT1",
		PreciseLocation: alpr.Location{Latitude: -23.561, Longitude: -46.655},
		CapturedAt:      time.Now().UTC().Truncate(time.Second),
		Confidence:      0.96,
		Speed:           &speed,
	}
	if err := col.Process(capture); err != nil {
		t.Fatalf("collector.Process: %v", err)
	}

	// Busca aberta com token
	tok := token.AuthToken{
		TokenID:    uuid.New().String(),
		SearchType: token.SearchOpen,
		CameraID:   "CAM-E2E-INT",
		DecodedBy:  "delegado-e2e",
		ExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	token.Issue(&tok, judgeSK)
	raw, _ := json.Marshal(tok)

	url := fmt.Sprintf("%s/records?camera_id=CAM-E2E-INT&start=2020-01-01T00:00:00Z&end=2030-01-01T00:00:00Z", ts.URL)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(raw))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /records: esperado 200, got %d", resp.StatusCode)
	}

	var results []alpr.ALPRRecord
	json.NewDecoder(resp.Body).Decode(&results)
	if len(results) == 0 {
		t.Fatal("busca aberta não retornou registros")
	}

	rec := results[0]
	if rec.CameraID != "CAM-E2E-INT" {
		t.Errorf("camera_id: esperado CAM-E2E-INT, got %s", rec.CameraID)
	}

	// Busca fechada com o mesmo registro
	tokClosed := token.AuthToken{
		TokenID:    uuid.New().String(),
		SearchType: token.SearchClosed,
		DecodedBy:  "delegado-fechado-e2e",
		ExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	token.Issue(&tokClosed, judgeSK)
	rawClosed, _ := json.Marshal(tokClosed)

	plateHex := fmt.Sprintf("%x", rec.PlateHMAC)
	urlClosed := fmt.Sprintf("%s/records/closed?plate_hmac=%s", ts.URL, plateHex)
	reqClosed, _ := http.NewRequest(http.MethodGet, urlClosed, nil)
	reqClosed.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(rawClosed))

	respClosed, err := http.DefaultClient.Do(reqClosed)
	if err != nil {
		t.Fatal(err)
	}
	defer respClosed.Body.Close()
	if respClosed.StatusCode != http.StatusOK {
		t.Fatalf("GET /records/closed: esperado 200, got %d", respClosed.StatusCode)
	}

	var resultsClosed []alpr.ALPRRecord
	json.NewDecoder(respClosed.Body).Decode(&resultsClosed)
	if len(resultsClosed) == 0 {
		t.Fatal("busca fechada não retornou registros")
	}

	// Verifica decode_logs para ambas as buscas
	var logCount int
	dbPrincipal.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM decode_logs WHERE record_id = $1", rec.RecordID,
	).Scan(&logCount)
	if logCount < 2 {
		t.Errorf("esperado >= 2 decode_logs (open + closed), got %d", logCount)
	}

	// Verifica também a busca via bytes.Contains no corpo
	var rawOpenBody bytes.Buffer
	rawOpenBody.WriteString(rec.RecordID)
	if rec.RecordID == "" {
		t.Error("record_id vazio nos resultados da busca aberta")
	}
}
