package server

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/storage"
)

// Server agrupa as duas conexões de banco necessárias ao servidor cego.
type Server struct {
	dbPrincipal *sql.DB
	dbBOLO      *sql.DB
}

func New(dbPrincipal, dbBOLO *sql.DB) *Server {
	return &Server{dbPrincipal: dbPrincipal, dbBOLO: dbBOLO}
}

// Routes registra todos os endpoints no mux fornecido.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /records", s.ingestRecord)
	mux.HandleFunc("POST /bolo/records", s.ingestBOLORecord)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) ingestRecord(w http.ResponseWriter, r *http.Request) {
	var rec alpr.ALPRRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
		return
	}
	if rec.RecordID == "" || len(rec.Signature) == 0 {
		http.Error(w, "record_id ou assinatura ausente", http.StatusBadRequest)
		return
	}
	if err := storage.InsertRecord(r.Context(), s.dbPrincipal, rec); err != nil {
		slog.Error("InsertRecord", "err", err, "record_id", rec.RecordID)
		http.Error(w, "erro ao persistir registro", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"record_id": rec.RecordID})
}

func (s *Server) ingestBOLORecord(w http.ResponseWriter, r *http.Request) {
	var rec alpr.BOLORecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
		return
	}
	if rec.RecordID == "" || len(rec.Signature) == 0 {
		http.Error(w, "record_id ou assinatura ausente", http.StatusBadRequest)
		return
	}
	if err := storage.InsertBOLORecord(r.Context(), s.dbBOLO, rec); err != nil {
		slog.Error("InsertBOLORecord", "err", err, "record_id", rec.RecordID)
		http.Error(w, "erro ao persistir registro BOLO", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"record_id": rec.RecordID})
}
