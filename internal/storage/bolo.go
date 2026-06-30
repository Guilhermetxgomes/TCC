package storage

import (
	"context"
	"database/sql"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
)

// InsertBOLORecord persiste um BOLORecord no banco BOLO.
func InsertBOLORecord(ctx context.Context, db *sql.DB, r alpr.BOLORecord) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO bolo_records (
			record_id, plate_hmac, captured_at, region,
			ciphertext, nonce, entropy_bits, puzzle_prefix,
			signature
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		r.RecordID, r.PlateHMAC, r.CapturedAt, r.Region,
		r.Payload.Ciphertext, r.Payload.Nonce, r.Payload.EntropyBits, r.Payload.PuzzlePrefix,
		r.Signature,
	)
	return err
}
