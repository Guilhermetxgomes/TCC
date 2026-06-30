package token

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"net/http"
	"strings"
)

type contextKey struct{}

// RequireToken retorna um middleware que valida o Bearer token e injeta-o no contexto.
// Rejeita com 401 se ausente, inválido ou expirado.
// Rejeita com 403 se o search_type não corresponde ao esperado.
func RequireToken(judgePK *ecdsa.PublicKey, required SearchType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := extractBearer(r)
			if err != nil {
				http.Error(w, "Authorization ausente ou inválido", http.StatusUnauthorized)
				return
			}

			tok, err := Parse(raw)
			if err != nil {
				http.Error(w, "token malformado", http.StatusUnauthorized)
				return
			}

			if err := Verify(tok, judgePK); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if tok.SearchType != required {
				http.Error(w, "token não autoriza este tipo de busca", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), contextKey{}, tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext extrai o AuthToken injetado pelo middleware.
func FromContext(ctx context.Context) (AuthToken, bool) {
	t, ok := ctx.Value(contextKey{}).(AuthToken)
	return t, ok
}

// extractBearer decodifica o payload do header "Authorization: Bearer <base64-JSON>".
func extractBearer(r *http.Request) ([]byte, error) {
	hdr := r.Header.Get("Authorization")
	after, ok := strings.CutPrefix(hdr, "Bearer ")
	if !ok || after == "" {
		return nil, http.ErrNoCookie // sentinel; erro real não importa
	}
	return base64.StdEncoding.DecodeString(after)
}
