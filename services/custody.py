"""
The Servidor's gate (RF06, RF07): no encrypted row leaves the Custódia without a valid
authorization token, and every release -- or refusal -- is written to the log
(services/audit_log.py) before anything is returned.

Checks, in this order: the judge's signature, the modality, the deadline (against the
simulated clock of the investigation), the operator the token was issued to, and the
scope -- the window of a Busca Aberta, the remaining budget of a Busca Fechada, the
cameras and days of a Busca Total.

The budget of a Busca Fechada is counted from the log itself (rows already released
under the token), so it survives across requests and is exactly what the Auditor sees.
"""
import time
from datetime import datetime
from typing import Callable, Optional

from crypto.tokens import verify_token
from entities.auth_token import AuthToken
from services.audit_log import AuditLog


class AuthorizationError(Exception):
    def __init__(self, reason: str, entry: Optional[dict] = None):
        super().__init__(reason)
        self.reason = reason
        self.entry = entry  # the "denied" entry written to the log


def _before(a: str, b: str) -> bool:
    return datetime.fromisoformat(a) < datetime.fromisoformat(b)


class CustodyGateway:
    def __init__(self, server, run_id: str, judge_public_key: bytes, audit_log: AuditLog, now: Callable[[], str]):
        self.server = server
        self.run_id = run_id
        self.judge_public_key = judge_public_key
        self.log = audit_log
        self.now = now
        self._spent: dict[str, int] = {}
        self.overhead_seconds = 0.0  # time spent on token checks and log writes (not on the database)
        for entry in audit_log.entries():
            if entry["kind"] == "release" and entry["token_id"]:
                self._spent[entry["token_id"]] = self._spent.get(entry["token_id"], 0) + entry["records"]

    def spent(self, token_id: str) -> int:
        return self._spent.get(token_id, 0)

    # -- checks ------------------------------------------------------------------------

    def _deny(self, token: AuthToken, operator_id: str, reason: str, camera_id=None, start=None, end=None):
        entry = self.log.append("denied", self.now(), token.token_id, token.mode, operator_id, camera_id, start, end,
                                0, {"reason": reason})
        raise AuthorizationError(reason, entry)

    def _check(self, token: AuthToken, operator_id: str, modes: tuple, camera_id=None, start=None, end=None):
        started = time.perf_counter()
        try:
            self._check_token(token, operator_id, modes, camera_id, start, end)
        finally:
            self.overhead_seconds += time.perf_counter() - started

    def _append(self, *args, **kwargs) -> dict:
        started = time.perf_counter()
        try:
            return self.log.append(*args, **kwargs)
        finally:
            self.overhead_seconds += time.perf_counter() - started

    def _check_token(self, token: AuthToken, operator_id: str, modes: tuple, camera_id=None, start=None, end=None):
        now = self.now()
        if not verify_token(token, self.judge_public_key):
            self._deny(token, operator_id, "assinatura do token inválida (não foi emitido pelo Autorizador Legal)",
                       camera_id, start, end)
        if token.mode not in modes:
            self._deny(token, operator_id, f"token de Busca {token.mode.capitalize()} não autoriza esta operação",
                       camera_id, start, end)
        if _before(now, token.issued_at) or not _before(now, token.expires_at):
            self._deny(token, operator_id, f"token fora do prazo de validade (vence em {token.expires_at[:16]})",
                       camera_id, start, end)
        if operator_id != token.operator_id:
            self._deny(token, operator_id, f"token emitido para o operador {token.operator_id}, não para {operator_id}",
                       camera_id, start, end)

    # -- releases ----------------------------------------------------------------------

    def release_window(self, token: AuthToken, operator_id: str, camera_id: int, start: str, end: str) -> list[dict]:
        """Rows of one camera in [start, end], if the token allows it; logged either way."""
        self._check(token, operator_id, ("aberta", "fechada"), camera_id, start, end)
        if token.mode == "aberta":
            scope = token.scope
            if camera_id != scope["camera_id"] or _before(start, scope["start"]) or _before(scope["end"], end):
                self._deny(token, operator_id, f"janela fora do escopo do token (câmera {scope['camera_id']}, "
                           f"{scope['start'][11:19]}–{scope['end'][11:19]})", camera_id, start, end)
        rows = self.server.get_rows_in_window(self.run_id, camera_id, start, end)
        if token.mode == "fechada":
            budget = token.scope["budget_records"]
            if self.spent(token.token_id) + len(rows) > budget:
                self._deny(token, operator_id, f"orçamento do token esgotado ({self.spent(token.token_id)} de {budget} "
                           f"registros já liberados; a janela tem {len(rows)})", camera_id, start, end)
        self._release(token, operator_id, camera_id, start, end, rows)
        return rows

    def release_session(self, token: AuthToken, operator_id: str, camera_id: int, session: str) -> list[dict]:
        """Every row of one camera in one escrow session (Busca Total)."""
        self._check(token, operator_id, ("total",), camera_id, session, session)
        scope = token.scope
        if (session[:7] != scope["period"]
                or (scope["sessions"] is not None and session not in scope["sessions"])
                or (scope["camera_ids"] is not None and camera_id not in scope["camera_ids"])):
            self._deny(token, operator_id, "câmera ou sessão fora do escopo da Busca Total", camera_id, session, session)
        rows = self.server.get_rows_in_session(self.run_id, camera_id, session)
        self._release(token, operator_id, camera_id, session, session, rows)
        return rows

    def release_wraps(self, token: AuthToken, operator_id: str, period: str, session: Optional[str]) -> list:
        """The escrowed session keys the committee will open (Busca Total)."""
        self._check(token, operator_id, ("total",))
        if period != token.scope["period"]:
            self._deny(token, operator_id, f"período {period} fora do escopo ({token.scope['period']})")
        wraps = self.server.get_session_wraps(self.run_id, period, session)
        self._append("release_wraps", self.now(), token.token_id, token.mode, operator_id, None, session, session,
                        len(wraps), {"cameras": sorted({w.camera_id for w in wraps}), "period": period})
        return wraps

    def block_header(self, token: AuthToken, operator_id: str, camera_id: int, block: str):
        """Public header of a crumpled block; released with the rows, under the same token (not counted)."""
        self._check(token, operator_id, ("aberta", "fechada", "total"), camera_id)
        return self.server.get_block_header(self.run_id, camera_id, block)

    def _release(self, token, operator_id, camera_id, start, end, rows):
        self._append("release", self.now(), token.token_id, token.mode, operator_id, camera_id, start, end,
                        len(rows), {"record_ids": [row["record_id"] for row in rows]})
        self._spent[token.token_id] = self.spent(token.token_id) + len(rows)
