package server

import (
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/storage"
	"github.com/Guilhermetxgomes/TCC/internal/token"
)

// Server agrupa as duas conexões de banco e a chave pública do juiz.
type Server struct {
	dbPrincipal *sql.DB
	dbBOLO      *sql.DB
	judgePK     *ecdsa.PublicKey
}

func New(dbPrincipal, dbBOLO *sql.DB, judgePK *ecdsa.PublicKey) *Server {
	return &Server{dbPrincipal: dbPrincipal, dbBOLO: dbBOLO, judgePK: judgePK}
}

// Routes registra todos os endpoints no mux fornecido.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", s.health)

	// Ingestão (sem autenticação — câmera usa canal seguro interno)
	mux.HandleFunc("POST /records", s.ingestRecord)
	mux.HandleFunc("POST /bolo/records", s.ingestBOLORecord)

	// Busca — requer token assinado pelo juiz
	openMW := token.RequireToken(s.judgePK, token.SearchOpen)
	closedMW := token.RequireToken(s.judgePK, token.SearchClosed)
	boloMW := token.RequireToken(s.judgePK, token.SearchBOLO)

	mux.Handle("GET /records", openMW(http.HandlerFunc(s.searchOpen)))
	// Busca fechada: mesmo path, distinguida pelo parâmetro plate_hmac.
	// Usamos /records/closed para evitar ambiguidade de roteamento.
	mux.Handle("GET /records/closed", closedMW(http.HandlerFunc(s.searchClosed)))
	mux.Handle("GET /bolo/records", boloMW(http.HandlerFunc(s.searchBOLO)))
}

// ----- ingestão -----

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

// ----- busca aberta (T3.1) -----

func (s *Server) searchOpen(w http.ResponseWriter, r *http.Request) {
	cameraID := r.URL.Query().Get("camera_id")
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")
	if cameraID == "" || start == "" || end == "" {
		http.Error(w, "parâmetros obrigatórios: camera_id, start, end", http.StatusBadRequest)
		return
	}

	records, err := storage.FindByCameraTime(r.Context(), s.dbPrincipal, cameraID, start, end)
	if err != nil {
		slog.Error("FindByCameraTime", "err", err)
		http.Error(w, "erro na busca", http.StatusInternalServerError)
		return
	}

	s.logDecodes(r, records, "open")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

// ----- busca fechada (T3.2) -----

func (s *Server) searchClosed(w http.ResponseWriter, r *http.Request) {
	plateHex := r.URL.Query().Get("plate_hmac")
	if plateHex == "" {
		http.Error(w, "parâmetro obrigatório: plate_hmac", http.StatusBadRequest)
		return
	}
	plateHMAC, err := hex.DecodeString(plateHex)
	if err != nil {
		http.Error(w, "plate_hmac deve ser hex válido", http.StatusBadRequest)
		return
	}

	records, err := storage.FindByPlateHMAC(r.Context(), s.dbPrincipal, plateHMAC)
	if err != nil {
		slog.Error("FindByPlateHMAC", "err", err)
		http.Error(w, "erro na busca", http.StatusInternalServerError)
		return
	}

	s.logDecodes(r, records, "closed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

// ----- busca BOLO (T3.5) -----

func (s *Server) searchBOLO(w http.ResponseWriter, r *http.Request) {
	plateHex := r.URL.Query().Get("plate_hmac")
	if plateHex == "" {
		http.Error(w, "parâmetro obrigatório: plate_hmac", http.StatusBadRequest)
		return
	}
	plateHMAC, err := hex.DecodeString(plateHex)
	if err != nil {
		http.Error(w, "plate_hmac deve ser hex válido", http.StatusBadRequest)
		return
	}

	records, err := storage.FindBOLOByPlateHMAC(r.Context(), s.dbBOLO, plateHMAC)
	if err != nil {
		slog.Error("FindBOLOByPlateHMAC", "err", err)
		http.Error(w, "erro na busca BOLO", http.StatusInternalServerError)
		return
	}

	tok, _ := token.FromContext(r.Context())
	for _, rec := range records {
		if err := storage.LogBoloDecodeLog(r.Context(), s.dbBOLO, rec.RecordID, tok.TokenID, tok.DecodedBy); err != nil {
			slog.Warn("LogBoloDecodeLog falhou", "err", err, "record_id", rec.RecordID)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

// ----- audit log (T3.4) -----

// logDecodes registra cada ALPRRecord devolvido em decode_logs.
func (s *Server) logDecodes(r *http.Request, records []alpr.ALPRRecord, searchType string) {
	tok, ok := token.FromContext(r.Context())
	if !ok {
		return
	}
	for _, rec := range records {
		if err := storage.LogDecode(r.Context(), s.dbPrincipal, rec.RecordID, tok.TokenID, searchType, tok.DecodedBy); err != nil {
			slog.Warn("LogDecode falhou", "err", err, "record_id", rec.RecordID)
		}
	}
}
