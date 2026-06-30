package server_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/server"
	"github.com/Guilhermetxgomes/TCC/internal/token"
	"github.com/google/uuid"
)

func newTestServer(t *testing.T) (*server.Server, *http.ServeMux, *ecdsa.PrivateKey) {
	t.Helper()
	judgeSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// nil DBs — testes cobrem validações de request antes do banco
	srv := server.New(nil, nil, &judgeSK.PublicKey)
	mux := http.NewServeMux()
	srv.Routes(mux)
	return srv, mux, judgeSK
}

func bearerToken(t *testing.T, sk *ecdsa.PrivateKey, st token.SearchType) string {
	t.Helper()
	tok := token.AuthToken{
		TokenID:    uuid.New().String(),
		SearchType: st,
		DecodedBy:  "teste",
		ExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	if err := token.Issue(&tok, sk); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(tok)
	return "Bearer " + base64.StdEncoding.EncodeToString(raw)
}

// ----- /health -----

func TestHealthOK(t *testing.T) {
	_, mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("esperado 200, got %d", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("body inesperado: %v", body)
	}
}

// ----- POST /records -----

func TestIngestRecordBadJSON(t *testing.T) {
	_, mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/records", bytes.NewBufferString("not-json"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestIngestRecordMissingFields(t *testing.T) {
	_, mux, _ := newTestServer(t)
	body, _ := json.Marshal(alpr.ALPRRecord{})
	req := httptest.NewRequest(http.MethodPost, "/records", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestIngestBOLORecordBadJSON(t *testing.T) {
	_, mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/bolo/records", bytes.NewBufferString("{"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestIngestBOLORecordMissingFields(t *testing.T) {
	_, mux, _ := newTestServer(t)
	body, _ := json.Marshal(alpr.BOLORecord{})
	req := httptest.NewRequest(http.MethodPost, "/bolo/records", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

// ----- GET /records (busca aberta) -----

func TestSearchOpenNoToken(t *testing.T) {
	_, mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/records?camera_id=X&start=2026-01-01T00:00:00Z&end=2026-01-02T00:00:00Z", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("esperado 401, got %d", rr.Code)
	}
}

func TestSearchOpenMissingParams(t *testing.T) {
	_, mux, judgeSK := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/records?camera_id=X", nil)
	req.Header.Set("Authorization", bearerToken(t, judgeSK, token.SearchOpen))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestSearchOpenWrongTokenType(t *testing.T) {
	_, mux, judgeSK := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/records?camera_id=X&start=2026-01-01T00:00:00Z&end=2026-01-02T00:00:00Z", nil)
	req.Header.Set("Authorization", bearerToken(t, judgeSK, token.SearchClosed)) // tipo errado
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("esperado 403, got %d", rr.Code)
	}
}

// ----- GET /records/closed (busca fechada) -----

func TestSearchClosedNoToken(t *testing.T) {
	_, mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/records/closed?plate_hmac=aabbcc", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("esperado 401, got %d", rr.Code)
	}
}

func TestSearchClosedMissingParam(t *testing.T) {
	_, mux, judgeSK := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/records/closed", nil)
	req.Header.Set("Authorization", bearerToken(t, judgeSK, token.SearchClosed))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestSearchClosedInvalidHex(t *testing.T) {
	_, mux, judgeSK := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/records/closed?plate_hmac=ZZZZ", nil)
	req.Header.Set("Authorization", bearerToken(t, judgeSK, token.SearchClosed))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

// ----- GET /bolo/records -----

func TestSearchBOLONoToken(t *testing.T) {
	_, mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/bolo/records?plate_hmac=aabbcc", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("esperado 401, got %d", rr.Code)
	}
}

func TestSearchBOLOWrongType(t *testing.T) {
	_, mux, judgeSK := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/bolo/records?plate_hmac=aabb", nil)
	req.Header.Set("Authorization", bearerToken(t, judgeSK, token.SearchOpen))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("esperado 403, got %d", rr.Code)
	}
}
