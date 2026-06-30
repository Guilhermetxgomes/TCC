package govserver_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Guilhermetxgomes/TCC/internal/governance/govserver"
	"github.com/Guilhermetxgomes/TCC/internal/token"
)

func newTestServer(t *testing.T) (*http.ServeMux, *ecdsa.PrivateKey) {
	t.Helper()
	judgeSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	monthlySK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)

	srv := govserver.New(govserver.Config{
		JudgeSK:            judgeSK,
		MonthlySK:          monthlySK,
		KeyMonth:           "2026-06",
		Kgov:               kgov,
		CameraAPIKey:       "camera-secret",
		InvestigatorAPIKey: "inv-secret",
		DB:                 nil,
	})
	mux := http.NewServeMux()
	srv.Routes(mux)
	return mux, judgeSK
}

func TestHealth(t *testing.T) {
	mux, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("esperado 200, got %d", rr.Code)
	}
}

// ----- GET /keys/monthly-pk -----

func TestMonthlyPK_NoAuth(t *testing.T) {
	mux, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/keys/monthly-pk", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("PK mensal é pública — esperado 200, got %d", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["monthly_pk_hex"] == "" {
		t.Error("monthly_pk_hex ausente")
	}
	if body["key_month"] == "" {
		t.Error("key_month ausente")
	}
	// Deve ser hex válido de 32 bytes (X25519)
	b, err := hex.DecodeString(body["monthly_pk_hex"])
	if err != nil || len(b) != 32 {
		t.Errorf("monthly_pk_hex inválido: %q", body["monthly_pk_hex"])
	}
}

// ----- GET /keys/kgov -----

func TestKgov_NoAuth(t *testing.T) {
	mux, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/keys/kgov", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("K_gov requer autenticação — esperado 401, got %d", rr.Code)
	}
}

func TestKgov_WithValidKey(t *testing.T) {
	mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/keys/kgov", nil)
	req.Header.Set("X-Camera-Key", "camera-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("esperado 200, got %d", rr.Code)
	}
	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	b, err := hex.DecodeString(body["kgov_hex"])
	if err != nil || len(b) != 32 {
		t.Errorf("kgov_hex inválido: %q", body["kgov_hex"])
	}
}

func TestKgov_WrongKey(t *testing.T) {
	mux, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/keys/kgov", nil)
	req.Header.Set("X-Camera-Key", "chave-errada")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("esperado 401, got %d", rr.Code)
	}
}

// ----- POST /tokens -----

func TestIssueToken_NoAuth(t *testing.T) {
	mux, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"search_type": "open", "camera_id": "X", "start": "2026-01-01T00:00:00Z", "end": "2026-02-01T00:00:00Z", "decoded_by": "del"})
	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("esperado 401, got %d", rr.Code)
	}
}

func TestIssueToken_Open_Valid(t *testing.T) {
	mux, judgeSK := newTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"search_type": "open",
		"camera_id":   "CAM-001",
		"start":       "2026-01-01T00:00:00Z",
		"end":         "2026-02-01T00:00:00Z",
		"decoded_by":  "delegado-silva",
		"ttl_minutes": 30,
	})
	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	req.Header.Set("X-Investigator-Key", "inv-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("esperado 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Fatal("token ausente na resposta")
	}

	// Verifica que o token é válido com a chave do juiz
	var tok token.AuthToken
	json.Unmarshal([]byte(resp["token"]), &tok)
	if err := token.Verify(tok, &judgeSK.PublicKey); err != nil {
		t.Errorf("token emitido não passa verificação: %v", err)
	}
	if tok.SearchType != token.SearchOpen {
		t.Errorf("search_type esperado open, got %s", tok.SearchType)
	}
}

func TestIssueToken_Closed_MissingPlateHMAC(t *testing.T) {
	mux, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"search_type": "closed",
		"decoded_by":  "delegado",
	})
	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	req.Header.Set("X-Investigator-Key", "inv-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400, got %d", rr.Code)
	}
}

func TestIssueToken_InvalidSearchType(t *testing.T) {
	mux, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"search_type": "total", "decoded_by": "del"})
	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	req.Header.Set("X-Investigator-Key", "inv-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("esperado 400 para search_type inválido, got %d", rr.Code)
	}
}
