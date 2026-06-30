package server_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/server"
)

// stubDB implementa a interface mínima usada pelos handlers via storage.
// Como os handlers chamam storage.InsertRecord(ctx, db, r), precisamos de
// um *sql.DB real ou substituir a injeção. Aqui usamos nil e verificamos
// apenas os caminhos que não chegam ao banco (validações de request).
// Para o caminho feliz usamos um banco SQLite em memória como exercício
// isolado — mas como o projeto usa PostgreSQL, testamos apenas as
// validações de entrada sem dependência de banco.

func newTestServer(t *testing.T) (*server.Server, *http.ServeMux) {
	t.Helper()
	// nil DBs — os handlers só chegarão ao banco se a request for válida.
	// Testes abaixo cobrem os casos de rejeição antes do banco.
	srv := server.New(nil, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)
	return srv, mux
}

func TestHealthOK(t *testing.T) {
	_, mux := newTestServer(t)
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

func TestIngestRecordBadJSON(t *testing.T) {
	_, mux := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/records", bytes.NewBufferString("not-json"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestIngestRecordMissingFields(t *testing.T) {
	_, mux := newTestServer(t)
	body, _ := json.Marshal(alpr.ALPRRecord{}) // sem record_id nem assinatura
	req := httptest.NewRequest(http.MethodPost, "/records", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestIngestBOLORecordBadJSON(t *testing.T) {
	_, mux := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/bolo/records", bytes.NewBufferString("{"))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestIngestBOLORecordMissingFields(t *testing.T) {
	_, mux := newTestServer(t)
	body, _ := json.Marshal(alpr.BOLORecord{})
	req := httptest.NewRequest(http.MethodPost, "/bolo/records", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

// Garante que o pacote compila mesmo sem banco disponível.
var _ = context.Background
var _ = (*sql.DB)(nil)
