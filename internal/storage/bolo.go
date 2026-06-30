package storage

import (
	"context"
	"database/sql"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
)

// FindBOLOByPlateHMAC retorna registros BOLO para busca por HMAC de placa.
func FindBOLOByPlateHMAC(ctx context.Context, db *sql.DB, plateHMAC []byte) ([]alpr.BOLORecord, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT record_id, plate_hmac, captured_at, region,
		       ciphertext, nonce, entropy_bits, puzzle_prefix, signature
		FROM bolo_records
		WHERE plate_hmac = $1
		ORDER BY captured_at`,
		plateHMAC,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []alpr.BOLORecord
	for rows.Next() {
		var r alpr.BOLORecord
		err := rows.Scan(
			&r.RecordID, &r.PlateHMAC, &r.CapturedAt, &r.Region,
			&r.Payload.Ciphertext, &r.Payload.Nonce, &r.Payload.EntropyBits, &r.Payload.PuzzlePrefix,
			&r.Signature,
		)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// LogBoloDecodeLog registra uma decodificação autorizada no banco BOLO (append-only).
func LogBoloDecodeLog(ctx context.Context, db *sql.DB, recordID, tokenID, decodedBy string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO bolo_decode_logs (record_id, token_id, decoded_by)
		VALUES ($1, $2, $3)`,
		recordID, tokenID, decodedBy,
	)
	return err
}

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
