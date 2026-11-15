import base64
from datetime import datetime, timezone
from typing import Optional

from psycopg2.extras import execute_values

from database.connection import get_connection
from entities.block_header import BlockHeader
from entities.record import Record
from entities.session_key_wrap import SessionKeyWrap

ENSURE_SCHEMA_SQL = """
    ALTER TABLE open_search_records ADD COLUMN IF NOT EXISTS run_id TEXT;
    CREATE INDEX IF NOT EXISTS idx_open_search_records_run_camera_time
        ON open_search_records (run_id, camera_id, captured_at);

    ALTER TABLE open_search_records ALTER COLUMN n TYPE BIGINT;
    ALTER TABLE open_search_records ADD COLUMN IF NOT EXISTS block TEXT;
    CREATE TABLE IF NOT EXISTS block_headers (
        header_id SERIAL PRIMARY KEY, run_id TEXT, camera_id INTEGER NOT NULL, block TEXT NOT NULL,
        c_prime TEXT NOT NULL, t BIGINT NOT NULL, check_nonce TEXT NOT NULL, check_tag TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_block_headers_run_camera_block
        ON block_headers (run_id, camera_id, block);
    CREATE TABLE IF NOT EXISTS session_key_wraps (
        wrap_id SERIAL PRIMARY KEY, run_id TEXT, camera_id INTEGER NOT NULL, period TEXT NOT NULL,
        session TEXT NOT NULL, r TEXT NOT NULL, nonce TEXT NOT NULL, wrapped TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_session_key_wraps_run_period_session
        ON session_key_wraps (run_id, period, session, camera_id);

    ALTER TABLE open_search_records ADD COLUMN IF NOT EXISTS signature TEXT;
"""

# Columns that rebuild a Record, in the order _row_to_record expects.
RECORD_COLUMNS = "camera_id, c_prime, n, nonce, ciphertext, block, captured_at, signature"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class Server:
    _schema_checked = False  # ensure_schema runs once per process (it is idempotent)

    def __init__(self):
        self.conn = get_connection()
        if not Server._schema_checked:
            self.ensure_schema()
            Server._schema_checked = True

    def close(self):
        self.conn.close()

    def save(self, record: Record, captured_at: Optional[str] = None, run_id: Optional[str] = None):
        # The capture instant now comes from the camera (record.captured_at), which binds it
        # into the AES-GCM associated data and signs it. `captured_at` is only a fallback for
        # records built by hand without one (such a record cannot be decrypted afterwards).
        if record.captured_at is None:
            record.captured_at = captured_at or datetime.now(timezone.utc).isoformat()
        self.save_many([record], run_id=run_id)

    def save_many(self, records: list, run_id: Optional[str] = None):
        """
        Bulk insert in one round trip / commit. Takes Records; (record, captured_at) pairs
        are still accepted, but the record's own captured_at (set by the camera) wins.
        """
        normalized = []
        for entry in records:
            record, fallback = entry if isinstance(entry, tuple) else (entry, None)
            if record.captured_at is None:
                record.captured_at = fallback or datetime.now(timezone.utc).isoformat()
            normalized.append(record)
        rows = [(*self._record_to_columns(record), run_id) for record in normalized]
        cursor = self.conn.cursor()
        execute_values(
            cursor,
            "INSERT INTO open_search_records"
            " (camera_id, c_prime, n, nonce, ciphertext, captured_at, block, signature, run_id) VALUES %s",
            rows,
        )
        self.conn.commit()
        cursor.close()

    def get_records_by_camera_id(self, camera_id: int) -> list[Record]:
        cursor = self.conn.cursor()
        query = f"""
            SELECT {RECORD_COLUMNS} FROM open_search_records
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
            f"""
            SELECT record_id, {RECORD_COLUMNS}
            FROM open_search_records
            WHERE run_id = %s AND camera_id = %s AND captured_at >= %s AND captured_at <= %s
            ORDER BY captured_at ASC, record_id ASC
            """,
            (run_id, camera_id, start, end),
        )
        rows = cursor.fetchall()
        cursor.close()
        return [self._row_to_entry(row) for row in rows]

    def get_rows_in_session(self, run_id: str, camera_id: int, session: str) -> list[dict]:
        """
        Every record of one camera in one escrow session (a prefix of captured_at, e.g.
        "2026-01-01" for a day), oldest first: what a Busca Total over that session opens.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            f"""
            SELECT record_id, {RECORD_COLUMNS}
            FROM open_search_records
            WHERE run_id = %s AND camera_id = %s AND left(captured_at, %s) = %s
            ORDER BY captured_at ASC, record_id ASC
            """,
            (run_id, camera_id, len(session), session),
        )
        rows = cursor.fetchall()
        cursor.close()
        return [self._row_to_entry(row) for row in rows]

    # -- block crumpling ----------------------------------------------------------------

    def save_block_headers(self, headers: list[BlockHeader], run_id: Optional[str] = None):
        if not headers:
            return
        rows = [
            (run_id, h.camera_id, h.block, _b64(h.c_prime), h.t, _b64(h.check_nonce), _b64(h.check_tag))
            for h in headers
        ]
        cursor = self.conn.cursor()
        execute_values(
            cursor,
            "INSERT INTO block_headers (run_id, camera_id, block, c_prime, t, check_nonce, check_tag) VALUES %s",
            rows,
        )
        self.conn.commit()
        cursor.close()

    def get_block_header(self, run_id: str, camera_id: int, block: str) -> Optional[BlockHeader]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT camera_id, block, c_prime, t, check_nonce, check_tag FROM block_headers
            WHERE run_id = %s AND camera_id = %s AND block = %s
            """,
            (run_id, camera_id, block),
        )
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            return None
        camera, label, c_prime, t, check_nonce, check_tag = row
        return BlockHeader(
            camera_id=camera, block=label, c_prime=base64.b64decode(c_prime), t=t,
            check_nonce=base64.b64decode(check_nonce), check_tag=base64.b64decode(check_tag),
        )

    # -- escrow (Busca Total) -----------------------------------------------------------

    def save_session_wraps(self, wraps: list[SessionKeyWrap], run_id: Optional[str] = None):
        if not wraps:
            return
        rows = [
            (run_id, w.camera_id, w.period, w.session, _b64(w.r), _b64(w.nonce), _b64(w.wrapped))
            for w in wraps
        ]
        cursor = self.conn.cursor()
        execute_values(
            cursor,
            "INSERT INTO session_key_wraps (run_id, camera_id, period, session, r, nonce, wrapped) VALUES %s",
            rows,
        )
        self.conn.commit()
        cursor.close()

    def get_session_wraps(self, run_id: str, period: str, session: Optional[str] = None) -> list[SessionKeyWrap]:
        """The wraps of one period (optionally of a single session), by camera."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT camera_id, period, session, r, nonce, wrapped FROM session_key_wraps
            WHERE run_id = %s AND period = %s AND (%s IS NULL OR session = %s)
            ORDER BY session ASC, camera_id ASC
            """,
            (run_id, period, session, session),
        )
        rows = cursor.fetchall()
        cursor.close()
        return [
            SessionKeyWrap(
                camera_id=camera, period=wrap_period, session=wrap_session, r=base64.b64decode(r),
                nonce=base64.b64decode(nonce), wrapped=base64.b64decode(wrapped),
            )
            for camera, wrap_period, wrap_session, r, nonce, wrapped in rows
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
            SELECT record_id, camera_id, captured_at, n, c_prime, nonce, ciphertext, block, signature
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
                    "block": block,
                    "signature": signature,
                }
                for record_id, camera, captured_at, n, c_prime, nonce, ciphertext, block, signature in rows
            ],
        }

    def get_block_headers_for_camera(self, run_id: str, camera_id: int) -> list[dict]:
        """
        The public block headers of one camera (Base64, as stored), with how many records
        each block holds: what block crumpling adds to the database.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT h.block, h.t, h.c_prime, h.check_nonce, h.check_tag, COUNT(r.record_id)
            FROM block_headers h
            LEFT JOIN open_search_records r
                ON r.run_id = h.run_id AND r.camera_id = h.camera_id AND r.block = h.block
            WHERE h.run_id = %s AND h.camera_id = %s
            GROUP BY h.header_id
            ORDER BY h.block ASC
            """,
            (run_id, camera_id),
        )
        rows = cursor.fetchall()
        cursor.close()
        return [
            {"block": block, "t": t, "c_prime": c_prime, "check_nonce": check_nonce, "check_tag": check_tag,
             "records": records}
            for block, t, c_prime, check_nonce, check_tag, records in rows
        ]

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
        entry = self.get_entry_by_id(run_id, record_id)
        return entry["record"] if entry else None

    def get_entry_by_id(self, run_id: str, record_id: int) -> Optional[dict]:
        cursor = self.conn.cursor()
        cursor.execute(
            f"""
            SELECT record_id, {RECORD_COLUMNS} FROM open_search_records
            WHERE run_id = %s AND record_id = %s
            """,
            (run_id, record_id),
        )
        row = cursor.fetchone()
        cursor.close()
        return self._row_to_entry(row) if row else None

    def update_record(self, run_id: str, record_id: int, record: Record):
        """
        Overwrites one stored row. Only the tampering demo (web/app.py) calls this: it plays
        the role of a dishonest Servidor operator, who has write access to the database.
        """
        camera_id, c_prime, n, nonce, ciphertext, captured_at, block, signature = self._record_to_columns(record)
        cursor = self.conn.cursor()
        cursor.execute(
            """
            UPDATE open_search_records
            SET camera_id = %s, c_prime = %s, n = %s, nonce = %s, ciphertext = %s, captured_at = %s,
                block = %s, signature = %s
            WHERE run_id = %s AND record_id = %s
            """,
            (camera_id, c_prime, n, nonce, ciphertext, captured_at, block, signature, run_id, record_id),
        )
        self.conn.commit()
        cursor.close()

    def clear_run(self, run_id: str):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM open_search_records WHERE run_id = %s", (run_id,))
        cursor.execute("DELETE FROM block_headers WHERE run_id = %s", (run_id,))
        cursor.execute("DELETE FROM session_key_wraps WHERE run_id = %s", (run_id,))
        self.conn.commit()
        cursor.close()

    def clear_all_runs(self):
        """Removes every simulation run (rows with a run_id); script records (run_id NULL) are kept."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM open_search_records WHERE run_id IS NOT NULL")
        cursor.execute("DELETE FROM block_headers WHERE run_id IS NOT NULL")
        cursor.execute("DELETE FROM session_key_wraps WHERE run_id IS NOT NULL")
        self.conn.commit()
        cursor.close()

    @staticmethod
    def _record_to_columns(record: Record) -> tuple:
        return (
            record.camera_id,
            _b64(record.c_prime),
            record.n,
            _b64(record.nonce),
            _b64(record.ciphertext),
            record.captured_at,
            record.block,
            _b64(record.signature) if record.signature else None,
        )

    def _row_to_record(self, row) -> Record:
        # Same column order as RECORD_COLUMNS.
        camera_id, c_prime_str, n, nonce_str, ciphertext_str, block, captured_at, signature = row
        return Record(
            camera_id=camera_id,
            c_prime=base64.b64decode(c_prime_str),
            n=n,
            nonce=base64.b64decode(nonce_str),
            ciphertext=base64.b64decode(ciphertext_str),
            block=block,
            captured_at=captured_at,
            signature=base64.b64decode(signature) if signature else None,
        )

    def _row_to_entry(self, row) -> dict:
        record_id, *record_columns = row
        record = self._row_to_record(record_columns)
        return {"record_id": record_id, "captured_at": record.captured_at, "record": record}
