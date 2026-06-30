package govserver

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/governance"
	"github.com/Guilhermetxgomes/TCC/internal/storage"
	"github.com/Guilhermetxgomes/TCC/internal/token"
	"github.com/google/uuid"
)

// Server é o servidor HTTP de governança.
type Server struct {
	judgeSK     *ecdsa.PrivateKey
	monthlySK   *ecdh.PrivateKey
	keyMonth    string
	kgov        []byte
	cameraAPIKey string // câmeras usam este API key para buscar K_gov
	investigatorAPIKey string // investigadores usam este API key para solicitar tokens
	db          *sql.DB // pode ser nil em testes
}

// Config reúne todas as dependências do servidor de governança.
type Config struct {
	JudgeSK            *ecdsa.PrivateKey
	MonthlySK          *ecdh.PrivateKey
	KeyMonth           string
	Kgov               []byte
	CameraAPIKey       string
	InvestigatorAPIKey string
	DB                 *sql.DB
}

func New(cfg Config) *Server {
	return &Server{
		judgeSK:            cfg.JudgeSK,
		monthlySK:          cfg.MonthlySK,
		keyMonth:           cfg.KeyMonth,
		kgov:               cfg.Kgov,
		cameraAPIKey:       cfg.CameraAPIKey,
		investigatorAPIKey: cfg.InvestigatorAPIKey,
		db:                 cfg.DB,
	}
}

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /keys/monthly-pk", s.monthlyPK)
	mux.HandleFunc("GET /keys/kgov", s.kgovEndpoint)
	mux.HandleFunc("POST /tokens", s.issueToken)
	mux.HandleFunc("POST /keys/split", s.splitKey)
	mux.HandleFunc("POST /keys/reconstruct", s.reconstructKey)
}

// ----- /health -----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// ----- GET /keys/monthly-pk (T4.2) — sem autenticação, PK é pública -----

func (s *Server) monthlyPK(w http.ResponseWriter, r *http.Request) {
	pkHex := hex.EncodeToString(s.monthlySK.PublicKey().Bytes())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"key_month":      s.keyMonth,
		"monthly_pk_hex": pkHex,
	})
}

// ----- GET /keys/kgov (T4.2) — requer X-Camera-Key -----

func (s *Server) kgovEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Camera-Key") != s.cameraAPIKey {
		http.Error(w, "X-Camera-Key ausente ou inválido", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"key_month": s.keyMonth,
		"kgov_hex":  hex.EncodeToString(s.kgov),
	})
}

// ----- POST /tokens (T4.3) -----

type issueTokenRequest struct {
	SearchType string `json:"search_type"`
	CameraID   string `json:"camera_id,omitempty"`
	PlateHMAC  string `json:"plate_hmac,omitempty"`
	Start      string `json:"start,omitempty"`
	End        string `json:"end,omitempty"`
	DecodedBy  string `json:"decoded_by"`
	TTLMinutes int    `json:"ttl_minutes"`
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Investigator-Key") != s.investigatorAPIKey {
		http.Error(w, "X-Investigator-Key ausente ou inválido", http.StatusUnauthorized)
		return
	}

	var req issueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
		return
	}
	if err := validateIssueRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ttl := req.TTLMinutes
	if ttl <= 0 {
		ttl = 60
	}

	tok := token.AuthToken{
		TokenID:    uuid.New().String(),
		SearchType: token.SearchType(req.SearchType),
		CameraID:   req.CameraID,
		PlateHMAC:  req.PlateHMAC,
		Start:      req.Start,
		End:        req.End,
		DecodedBy:  req.DecodedBy,
		ExpiresAt:  time.Now().Add(time.Duration(ttl) * time.Minute).UTC().Format(time.RFC3339),
	}

	if err := token.Issue(&tok, s.judgeSK); err != nil {
		slog.Error("Issue token", "err", err)
		http.Error(w, "erro ao assinar token", http.StatusInternalServerError)
		return
	}

	// Persiste no banco (opcional — nil-safe)
	if s.db != nil {
		subject := req.CameraID
		if subject == "" {
			subject = req.PlateHMAC
		}
		tokenJSON, _ := json.Marshal(tok)
		if err := storage.InsertToken(r.Context(), s.db, tok.TokenID, req.SearchType, subject, req.DecodedBy, tok.ExpiresAt, tokenJSON); err != nil {
			slog.Warn("InsertToken falhou (não bloqueia emissão)", "err", err)
		}
	}

	tokenJSON, _ := json.Marshal(tok)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"token_id": tok.TokenID,
		"token":    string(tokenJSON),
	})
}

// ----- POST /keys/split (T5.2) -----

type splitKeyRequest struct {
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`
}

func (s *Server) splitKey(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Investigator-Key") != s.investigatorAPIKey {
		http.Error(w, "X-Investigator-Key ausente ou inválido", http.StatusUnauthorized)
		return
	}
	var req splitKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
		return
	}
	if req.Threshold < 2 || req.Shares < req.Threshold {
		http.Error(w, "shares >= threshold >= 2 obrigatório", http.StatusBadRequest)
		return
	}

	shares, err := governance.SplitSK(s.monthlySK, req.Shares, req.Threshold)
	if err != nil {
		slog.Error("SplitSK", "err", err)
		http.Error(w, "erro ao dividir chave", http.StatusInternalServerError)
		return
	}

	hexShares := make([]string, len(shares))
	for i, sh := range shares {
		hexShares[i] = hex.EncodeToString(sh)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"key_month": s.keyMonth,
		"threshold": req.Threshold,
		"shares":    hexShares,
	})
}

// ----- POST /keys/reconstruct (T5.3) -----

type reconstructKeyRequest struct {
	KeyMonth string   `json:"key_month"`
	Shares   []string `json:"shares"` // hex-encoded
}

func (s *Server) reconstructKey(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Investigator-Key") != s.investigatorAPIKey {
		http.Error(w, "X-Investigator-Key ausente ou inválido", http.StatusUnauthorized)
		return
	}
	var req reconstructKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corpo JSON inválido", http.StatusBadRequest)
		return
	}
	if len(req.Shares) < 2 {
		http.Error(w, "mínimo de 2 shares necessárias", http.StatusBadRequest)
		return
	}

	rawShares := make([][]byte, len(req.Shares))
	for i, h := range req.Shares {
		b, err := hex.DecodeString(h)
		if err != nil {
			http.Error(w, fmt.Sprintf("share[%d] hex inválido", i), http.StatusBadRequest)
			return
		}
		rawShares[i] = b
	}

	sk, err := governance.CombineSK(rawShares, s.monthlySK.PublicKey())
	if err != nil {
		http.Error(w, "reconstrução falhou: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"key_month": s.keyMonth,
		"sk_hex":    hex.EncodeToString(sk.Bytes()),
	})
}

func validateIssueRequest(req issueTokenRequest) error {
	switch token.SearchType(req.SearchType) {
	case token.SearchOpen:
		if req.CameraID == "" || req.Start == "" || req.End == "" {
			return fmt.Errorf("busca open requer camera_id, start e end")
		}
	case token.SearchClosed, token.SearchBOLO:
		if req.PlateHMAC == "" {
			return fmt.Errorf("busca %s requer plate_hmac", req.SearchType)
		}
	default:
		return fmt.Errorf("search_type inválido: %q", req.SearchType)
	}
	if req.DecodedBy == "" {
		return fmt.Errorf("decoded_by é obrigatório")
	}
	return nil
}
