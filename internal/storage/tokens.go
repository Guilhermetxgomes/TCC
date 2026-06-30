package storage

import (
	"context"
	"database/sql"
	"fmt"
)

// InsertToken registra um token emitido na tabela authorization_tokens.
func InsertToken(ctx context.Context, db *sql.DB, tokenID, searchType, subject, issuedBy, expiresAt string, tokenData []byte) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO authorization_tokens
			(token_id, token_data, search_type, subject, issued_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		tokenID, tokenData, searchType, subject, issuedBy, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("storage.InsertToken: %w", err)
	}
	return nil
}

// RevokeToken marca um token como revogado.
func RevokeToken(ctx context.Context, db *sql.DB, tokenID string) error {
	res, err := db.ExecContext(ctx,
		`UPDATE authorization_tokens SET revoked = TRUE WHERE token_id = $1`, tokenID)
	if err != nil {
		return fmt.Errorf("storage.RevokeToken: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("storage.RevokeToken: token %s não encontrado", tokenID)
	}
	return nil
}

// IsRevoked retorna true se o token existe e está revogado.
func IsRevoked(ctx context.Context, db *sql.DB, tokenID string) (bool, error) {
	var revoked bool
	err := db.QueryRowContext(ctx,
		`SELECT revoked FROM authorization_tokens WHERE token_id = $1`, tokenID,
	).Scan(&revoked)
	if err == sql.ErrNoRows {
		return false, nil // token desconhecido → não revogado (emitido fora do sistema)
	}
	if err != nil {
		return false, fmt.Errorf("storage.IsRevoked: %w", err)
	}
	return revoked, nil
}
