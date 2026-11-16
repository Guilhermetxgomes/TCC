import os
from datetime import datetime, timedelta
from typing import Optional

from crypto.tokens import SigningKey, plate_commitment, sign_token
from entities.auth_token import AuthToken

DEFAULT_VALIDITY_SECONDS = {"aberta": 7 * 86400, "fechada": 7 * 86400, "total": 86400}
DEFAULT_BUDGET_RECORDS = 500


def add_seconds(instant: str, seconds: float) -> str:
    return (datetime.fromisoformat(instant) + timedelta(seconds=seconds)).isoformat()


class LegalAuthorizer:
    """
    The Autorizador Legal (judge): issues and signs the authorization tokens of the three
    search modalities, and keeps the registry of issued tokens ("Tokens Emitidos").

    The registry and the HMAC key live with the Judiciary and the Governance layer -- in the
    simulation, in World.governance, outside the Servidor's database -- because they are
    what the Auditor compares the Servidor's log against.
    """

    def __init__(self):
        self._key = SigningKey()
        self.public_key = self._key.public_key_bytes
        self._hmac_key = os.urandom(32)  # k_jud: shared with the Auditor only
        self.issued: list[AuthToken] = []

    def hmac_key_for_auditor(self) -> bytes:
        return self._hmac_key

    def token(self, token_id: str) -> Optional[AuthToken]:
        return next((t for t in self.issued if t.token_id == token_id), None)

    def _issue(self, mode: str, operator_id: str, issued_at: str, scope: dict,
               validity_seconds: Optional[float]) -> AuthToken:
        validity = DEFAULT_VALIDITY_SECONDS[mode] if validity_seconds is None else validity_seconds
        token = AuthToken(
            token_id=f"T{len(self.issued) + 1:04d}-{mode[0].upper()}", mode=mode, operator_id=operator_id,
            issued_at=issued_at, expires_at=add_seconds(issued_at, validity), scope=scope,
        )
        token = sign_token(token, self._key)
        self.issued.append(token)
        return token

    def issue_aberta(self, operator_id: str, camera_id: int, start: str, end: str, issued_at: str,
                     validity_seconds: Optional[float] = None) -> AuthToken:
        """Busca Aberta: ECDSA(camera + time window). Opens every record of that window."""
        return self._issue("aberta", operator_id, issued_at,
                           {"camera_id": camera_id, "start": start, "end": end}, validity_seconds)

    def issue_fechada(self, operator_id: str, plate: str, issued_at: str,
                      budget_records: int = DEFAULT_BUDGET_RECORDS,
                      validity_seconds: Optional[float] = None) -> AuthToken:
        """Busca Fechada: ECDSA(HMAC(plate) + deadline + budget of releasable records)."""
        return self._issue("fechada", operator_id, issued_at,
                           {"plate_hmac": plate_commitment(self._hmac_key, plate), "budget_records": budget_records},
                           validity_seconds)

    def issue_total(self, operator_id: str, period: str, sessions: Optional[list[str]],
                    camera_ids: Optional[list[int]], reason: str, issued_at: str,
                    validity_seconds: Optional[float] = None) -> AuthToken:
        """Busca Total: the scope the Comitê de Emergência may open (one month, some days/cameras)."""
        return self._issue("total", operator_id, issued_at, {
            "period": period, "sessions": sorted(sessions) if sessions is not None else None,
            "camera_ids": sorted(camera_ids) if camera_ids is not None else None, "reason": reason,
        }, validity_seconds)
