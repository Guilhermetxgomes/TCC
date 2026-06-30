package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/token"
	"github.com/google/uuid"
)

func newJudgeKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func makeToken(t *testing.T, sk *ecdsa.PrivateKey, st token.SearchType, ttl time.Duration) token.AuthToken {
	t.Helper()
	tok := token.AuthToken{
		TokenID:    uuid.New().String(),
		SearchType: st,
		DecodedBy:  "delegado-teste",
		ExpiresAt:  time.Now().Add(ttl).UTC().Format(time.RFC3339),
	}
	if err := token.Issue(&tok, sk); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerify_Valid(t *testing.T) {
	sk := newJudgeKey(t)
	tok := makeToken(t, sk, token.SearchOpen, time.Hour)
	if err := token.Verify(tok, &sk.PublicKey); err != nil {
		t.Errorf("token válido rejeitado: %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	sk := newJudgeKey(t)
	tok := makeToken(t, sk, token.SearchOpen, -time.Minute)
	if err := token.Verify(tok, &sk.PublicKey); err == nil {
		t.Error("token expirado deveria ser rejeitado")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	sk := newJudgeKey(t)
	other := newJudgeKey(t)
	tok := makeToken(t, sk, token.SearchClosed, time.Hour)
	if err := token.Verify(tok, &other.PublicKey); err == nil {
		t.Error("assinatura com chave errada deveria ser rejeitada")
	}
}

func TestVerify_Tampered(t *testing.T) {
	sk := newJudgeKey(t)
	tok := makeToken(t, sk, token.SearchOpen, time.Hour)
	tok.DecodedBy = "hacker" // modifica após assinar
	if err := token.Verify(tok, &sk.PublicKey); err == nil {
		t.Error("token adulterado deveria ser rejeitado")
	}
}

func TestMiddleware_ValidToken(t *testing.T) {
	sk := newJudgeKey(t)
	tok := makeToken(t, sk, token.SearchOpen, time.Hour)
	raw, _ := json.Marshal(tok)

	handler := token.RequireToken(&sk.PublicKey, token.SearchOpen)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			injected, ok := token.FromContext(r.Context())
			if !ok {
				t.Error("token não injetado no contexto")
			}
			if injected.TokenID != tok.TokenID {
				t.Error("token_id diferente no contexto")
			}
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/records", nil)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(raw))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("esperado 200, got %d", rr.Code)
	}
}

func TestMiddleware_NoToken(t *testing.T) {
	sk := newJudgeKey(t)
	handler := token.RequireToken(&sk.PublicKey, token.SearchOpen)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	req := httptest.NewRequest(http.MethodGet, "/records", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("esperado 401, got %d", rr.Code)
	}
}

func TestMiddleware_WrongType(t *testing.T) {
	sk := newJudgeKey(t)
	tok := makeToken(t, sk, token.SearchClosed, time.Hour) // closed, mas endpoint é open
	raw, _ := json.Marshal(tok)

	handler := token.RequireToken(&sk.PublicKey, token.SearchOpen)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	req := httptest.NewRequest(http.MethodGet, "/records", nil)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(raw))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("esperado 403, got %d", rr.Code)
	}
}
