import base64
from datetime import datetime, timezone
from typing import Optional

from psycopg2.extras import execute_values

from database.connection import get_connection
from entities.record import Record

ENSURE_SCHEMA_SQL = """
    ALTER TABLE open_search_records ADD COLUMN IF NOT EXISTS run_id TEXT;
    CREATE INDEX IF NOT EXISTS idx_open_search_records_run_camera_time
        ON open_search_records (run_id, camera_id, captured_at);
"""


class Server:
    def __init__(self):
        self.conn = get_connection()

    def close(self):
        self.conn.close()

    def save(self, record: Record, captured_at: Optional[str] = None, run_id: Optional[str] = None):
        query = """
            INSERT INTO open_search_records (camera_id, c_prime, n, nonce, ciphertext, captured_at, run_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        # When the caller does not provide a capture timestamp (the original
        # scripts), fall back to the moment of this save() call -- the
        # captured_at column is NOT NULL. The web simulation passes its own
        # simulated clock instead.
        if captured_at is None:
            captured_at = datetime.now(timezone.utc).isoformat()
        values = (*self._record_to_columns(record), captured_at, run_id)
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        self.conn.commit()
        cursor.close()

    def save_many(self, entries: list[tuple[Record, str]], run_id: Optional[str] = None):
        """Bulk insert of (record, captured_at) pairs in one round trip / commit."""
        rows = [(*self._record_to_columns(record), captured_at, run_id) for record, captured_at in entries]
        cursor = self.conn.cursor()
        execute_values(
            cursor,
            "INSERT INTO open_search_records (camera_id, c_prime, n, nonce, ciphertext, captured_at, run_id) VALUES %s",
            rows,
        )
        self.conn.commit()
        cursor.close()

    def get_records_by_camera_id(self, camera_id: int) -> list[Record]:
        cursor = self.conn.cursor()
        query = """
            SELECT camera_id, c_prime, n, nonce, ciphertext FROM open_search_records
            WHERE camera_id = %s
            ORDER BY record_id ASC
        """
        cursor.execute(query, (camera_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [self._row_to_record(row) for row in rows]

    # ------------------------------------------------------------------
    # Simulation support (all scoped by run_id)
    # ------------------------------------------------------------------

    def ensure_schema(self):
        cursor = self.conn.cursor()
        cursor.execute(ENSURE_SCHEMA_SQL)
        self.conn.commit()
        cursor.close()

    def get_rows_in_window(self, run_id: str, camera_id: int, start: str, end: str) -> list[dict]:
        """
        Records of one camera captured in [start, end] (inclusive; ISO strings
        compare chronologically), oldest first. Unlike get_records_by_camera_id
        this also returns record_id and captured_at.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT record_id, captured_at, camera_id, c_prime, n, nonce, ciphertext
            FROM open_search_records
            WHERE run_id = %s AND camera_id = %s AND captured_at >= %s AND captured_at <= %s
            ORDER BY captured_at ASC, record_id ASC
            """,
            (run_id, camera_id, start, end),
        )
        rows = cursor.fetchall()
        cursor.close()
        return [
            {
                "record_id": record_id,
                "captured_at": captured_at,
                "record": self._row_to_record((camera, c_prime, n, nonce, ciphertext)),
            }
            for record_id, captured_at, camera, c_prime, n, nonce, ciphertext in rows
        ]

    def get_rows_for_camera(self, run_id: str, camera_id: int, limit: int = 100, offset: int = 0) -> dict:
        """What is stored for one camera, as the database holds it (Base64 columns, no plate)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM open_search_records WHERE run_id = %s AND camera_id = %s",
            (run_id, camera_id),
        )
        total = cursor.fetchone()[0]
        cursor.execute(
            """
            SELECT record_id, camera_id, captured_at, n, c_prime, nonce, ciphertext
            FROM open_search_records
            WHERE run_id = %s AND camera_id = %s
            ORDER BY captured_at ASC, record_id ASC
            LIMIT %s OFFSET %s
            """,
            (run_id, camera_id, limit, offset),
        )
        rows = cursor.fetchall()
        cursor.close()
        return {
            "total": total,
            "rows": [
                {
                    "record_id": record_id,
                    "camera_id": camera,
                    "captured_at": captured_at,
                    "n": n,
                    "c_prime": c_prime,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                }
                for record_id, camera, captured_at, n, c_prime, nonce, ciphertext in rows
            ],
        }

    def count_by_camera(self, run_id: str) -> dict[int, int]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT camera_id, COUNT(*) FROM open_search_records WHERE run_id = %s GROUP BY camera_id",
            (run_id,),
        )
        counts = {camera_id: count for camera_id, count in cursor.fetchall()}
        cursor.close()
        return counts

    def get_record_by_id(self, run_id: str, record_id: int) -> Optional[Record]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT camera_id, c_prime, n, nonce, ciphertext FROM open_search_records
            WHERE run_id = %s AND record_id = %s
            """,
            (run_id, record_id),
        )
        row = cursor.fetchone()
        cursor.close()
        return self._row_to_record(row) if row else None

    def clear_run(self, run_id: str):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM open_search_records WHERE run_id = %s", (run_id,))
        self.conn.commit()
        cursor.close()

    def clear_all_runs(self):
        """Removes every simulation run (rows with a run_id); script records (run_id NULL) are kept."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM open_search_records WHERE run_id IS NOT NULL")
        self.conn.commit()
        cursor.close()

    @staticmethod
    def _record_to_columns(record: Record) -> tuple:
        return (
            record.camera_id,
            base64.b64encode(record.c_prime).decode("ascii"),
            record.n,
            base64.b64encode(record.nonce).decode("ascii"),
            base64.b64encode(record.ciphertext).decode("ascii"),
        )

    def _row_to_record(self, row) -> Record:
        camera_id, c_prime_str, n, nonce_str, ciphertext_str = row
        return Record(
            camera_id=camera_id,
            c_prime=base64.b64decode(c_prime_str),
            n=n,
            nonce=base64.b64decode(nonce_str),
            ciphertext=base64.b64decode(ciphertext_str),
        )
