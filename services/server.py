import base64
from datetime import datetime, timezone

from database.connection import get_connection
from entities.record import Record


class Server:
    def __init__(self):
        self.conn = get_connection()

    def save(self, record: Record):
        query = """
            INSERT INTO open_search_records (camera_id, c_prime, n, nonce, ciphertext, captured_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        c_prime_str = base64.b64encode(record.c_prime).decode("ascii")
        nonce_str = base64.b64encode(record.nonce).decode("ascii")
        ciphertext_str = base64.b64encode(record.ciphertext).decode("ascii")
        # Camera does not generate a real capture timestamp yet (a pending
        # item in the project) -- using the moment of this save() call as a
        # stand-in so the NOT NULL captured_at column in the migration is
        # satisfied. Swap this for a real capture-time value once Camera
        # produces one.
        captured_at = datetime.now(timezone.utc).isoformat()
        values = (record.camera_id, c_prime_str, record.n, nonce_str, ciphertext_str, captured_at)
        cursor = self.conn.cursor()
        cursor.execute(query, values)
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

    def _row_to_record(self, row) -> Record:
        camera_id, c_prime_str, n, nonce_str, ciphertext_str = row
        return Record(
            camera_id=camera_id,
            c_prime=base64.b64decode(c_prime_str),
            n=n,
            nonce=base64.b64decode(nonce_str),
            ciphertext=base64.b64decode(ciphertext_str),
        )
