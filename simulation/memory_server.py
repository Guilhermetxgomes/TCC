"""
In-memory stand-in for services.server.Server, with the same simulation-facing methods.

It exists so that the simulation backend can be checked without Postgres:

    python -m simulation.selfcheck --memory

It is NOT used by the web app or by the main_*.py scripts, which keep talking to the
real database; the selfcheck without --memory is still the one that exercises the SQL.
"""
import copy
from typing import Optional

from entities.block_header import BlockHeader
from entities.record import Record
from entities.session_key_wrap import SessionKeyWrap


class MemoryServer:
    def __init__(self):
        self._rows: list[dict] = []  # {record_id, run_id, captured_at, record}
        self._headers: dict[tuple, BlockHeader] = {}
        self._wraps: list[tuple[Optional[str], SessionKeyWrap]] = []
        self._next_id = 1
        self._audit: list[tuple[Optional[str], dict]] = []

    def close(self):
        pass

    def ensure_schema(self):
        pass

    def save_many(self, records: list, run_id: Optional[str] = None):
        for entry in records:
            record, fallback = entry if isinstance(entry, tuple) else (entry, None)
            if record.captured_at is None:
                record.captured_at = fallback
            self._rows.append({
                "record_id": self._next_id, "run_id": run_id, "captured_at": record.captured_at, "record": record,
            })
            self._next_id += 1

    def get_entry_by_id(self, run_id: str, record_id: int) -> Optional[dict]:
        for row in self._rows:
            if row["run_id"] == run_id and row["record_id"] == record_id:
                return {"record_id": record_id, "captured_at": row["captured_at"], "record": row["record"]}
        return None

    def update_record(self, run_id: str, record_id: int, record: Record):
        for row in self._rows:
            if row["run_id"] == run_id and row["record_id"] == record_id:
                row["record"], row["captured_at"] = record, record.captured_at

    def _select(self, run_id: str, camera_id: int, keep) -> list[dict]:
        rows = [
            row for row in self._rows
            if row["run_id"] == run_id and row["record"].camera_id == camera_id and keep(row["captured_at"])
        ]
        rows.sort(key=lambda row: (row["captured_at"], row["record_id"]))
        return [{"record_id": r["record_id"], "captured_at": r["captured_at"], "record": r["record"]} for r in rows]

    def get_rows_in_window(self, run_id: str, camera_id: int, start: str, end: str) -> list[dict]:
        return self._select(run_id, camera_id, lambda captured_at: start <= captured_at <= end)

    def get_rows_in_session(self, run_id: str, camera_id: int, session: str) -> list[dict]:
        return self._select(run_id, camera_id, lambda captured_at: captured_at.startswith(session))

    def count_by_camera(self, run_id: str) -> dict[int, int]:
        counts: dict[int, int] = {}
        for row in self._rows:
            if row["run_id"] == run_id:
                camera_id = row["record"].camera_id
                counts[camera_id] = counts.get(camera_id, 0) + 1
        return counts

    def get_record_by_id(self, run_id: str, record_id: int) -> Optional[Record]:
        for row in self._rows:
            if row["run_id"] == run_id and row["record_id"] == record_id:
                return row["record"]
        return None

    def save_block_headers(self, headers: list[BlockHeader], run_id: Optional[str] = None):
        for header in headers:
            self._headers[(run_id, header.camera_id, header.block)] = header

    def get_block_header(self, run_id: str, camera_id: int, block: str) -> Optional[BlockHeader]:
        return self._headers.get((run_id, camera_id, block))

    def save_session_wraps(self, wraps: list[SessionKeyWrap], run_id: Optional[str] = None):
        self._wraps.extend((run_id, wrap) for wrap in wraps)

    def get_session_wraps(self, run_id: str, period: str, session: Optional[str] = None) -> list[SessionKeyWrap]:
        wraps = [
            wrap for wrap_run, wrap in self._wraps
            if wrap_run == run_id and wrap.period == period and (session is None or wrap.session == session)
        ]
        return sorted(wraps, key=lambda wrap: (wrap.session, wrap.camera_id))

    def append_audit(self, run_id: str, entry: dict):
        self._audit.append((run_id, copy.deepcopy(entry)))

    def get_audit_log(self, run_id: str) -> list[dict]:
        rows = [copy.deepcopy(entry) for entry_run, entry in self._audit if entry_run == run_id]
        return sorted(rows, key=lambda entry: entry["seq"])

    def get_audit_head(self, run_id: str) -> Optional[dict]:
        rows = [entry for entry_run, entry in self._audit if entry_run == run_id]
        return copy.deepcopy(max(rows, key=lambda entry: entry["seq"])) if rows else None

    def delete_audit(self, run_id: str, seqs: list[int]):
        self._audit = [(r, e) for r, e in self._audit if not (r == run_id and e["seq"] in set(seqs))]

    def clear_run(self, run_id: str):
        self._audit = [(r, e) for r, e in self._audit if r != run_id]
        self._rows = [row for row in self._rows if row["run_id"] != run_id]
        self._headers = {key: header for key, header in self._headers.items() if key[0] != run_id}
        self._wraps = [(wrap_run, wrap) for wrap_run, wrap in self._wraps if wrap_run != run_id]
