package storage

import (
	"context"
	"database/sql"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
)

// InsertRecord persiste um ALPRRecord no banco principal.
func InsertRecord(ctx context.Context, db *sql.DB, r alpr.ALPRRecord) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO alpr_records (
			record_id, camera_id, captured_at, region, key_month, plate_hmac,
			open_ciphertext,   open_nonce,   open_entropy_bits,   open_puzzle_prefix,
			closed_ciphertext, closed_nonce, closed_entropy_bits, closed_puzzle_prefix,
			total_ciphertext,  total_nonce,  total_encrypted_key, total_ephemeral_pk,
			signature
		) VALUES (
			$1,  $2,  $3,  $4,  $5,  $6,
			$7,  $8,  $9,  $10,
			$11, $12, $13, $14,
			$15, $16, $17, $18,
			$19
		)`,
		r.RecordID, r.CameraID, r.CapturedAt, r.Region, r.KeyMonth, r.PlateHMAC,
		r.OpenPayload.Ciphertext, r.OpenPayload.Nonce, r.OpenPayload.EntropyBits, r.OpenPayload.PuzzlePrefix,
		r.ClosedPayload.Ciphertext, r.ClosedPayload.Nonce, r.ClosedPayload.EntropyBits, r.ClosedPayload.PuzzlePrefix,
		r.TotalPayload.Ciphertext, r.TotalPayload.Nonce, r.TotalPayload.EncryptedKey, r.TotalPayload.EphemeralPK,
		r.Signature,
	)
	return err
}

// FindByCameraTime retorna registros para busca aberta (camera_id + janela de tempo).
func FindByCameraTime(ctx context.Context, db *sql.DB, cameraID, start, end string) ([]alpr.ALPRRecord, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT record_id, camera_id, captured_at, region, key_month, plate_hmac,
		       open_ciphertext, open_nonce, open_entropy_bits, open_puzzle_prefix,
		       closed_ciphertext, closed_nonce, closed_entropy_bits, closed_puzzle_prefix,
		       total_ciphertext, total_nonce, total_encrypted_key, total_ephemeral_pk,
		       signature
		FROM alpr_records
		WHERE camera_id = $1 AND captured_at BETWEEN $2 AND $3
		ORDER BY captured_at`,
		cameraID, start, end,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// FindByPlateHMAC retorna registros para busca fechada (HMAC da placa).
func FindByPlateHMAC(ctx context.Context, db *sql.DB, plateHMAC []byte) ([]alpr.ALPRRecord, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT record_id, camera_id, captured_at, region, key_month, plate_hmac,
		       open_ciphertext, open_nonce, open_entropy_bits, open_puzzle_prefix,
		       closed_ciphertext, closed_nonce, closed_entropy_bits, closed_puzzle_prefix,
		       total_ciphertext, total_nonce, total_encrypted_key, total_ephemeral_pk,
		       signature
		FROM alpr_records
		WHERE plate_hmac = $1
		ORDER BY captured_at`,
		plateHMAC,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// LogDecode registra uma decodificação autorizada (append-only).
func LogDecode(ctx context.Context, db *sql.DB, recordID, tokenID, searchType, decodedBy string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO decode_logs (record_id, token_id, search_type, decoded_by)
		VALUES ($1, $2, $3, $4)`,
		recordID, tokenID, searchType, decodedBy,
	)
	return err
}

func scanRecords(rows *sql.Rows) ([]alpr.ALPRRecord, error) {
	var records []alpr.ALPRRecord
	for rows.Next() {
		var r alpr.ALPRRecord
		err := rows.Scan(
			&r.RecordID, &r.CameraID, &r.CapturedAt, &r.Region, &r.KeyMonth, &r.PlateHMAC,
			&r.OpenPayload.Ciphertext, &r.OpenPayload.Nonce, &r.OpenPayload.EntropyBits, &r.OpenPayload.PuzzlePrefix,
			&r.ClosedPayload.Ciphertext, &r.ClosedPayload.Nonce, &r.ClosedPayload.EntropyBits, &r.ClosedPayload.PuzzlePrefix,
			&r.TotalPayload.Ciphertext, &r.TotalPayload.Nonce, &r.TotalPayload.EncryptedKey, &r.TotalPayload.EphemeralPK,
			&r.Signature,
		)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
