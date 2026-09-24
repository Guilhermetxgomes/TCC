from dataclasses import dataclass
from typing import Optional


@dataclass
class Alert:
    """
    Plain-text alert a camera sends straight to the police when it spots,
    at capture time, a plate that is on its local blocklist.

    Unrelated to Record/puzzle: unlike busca_aberta and busca_fechada,
    this alert never goes through any encryption, because the camera
    already had the plate in the clear -- this happens the instant before
    it would otherwise encrypt it (see services/camera.py).
    """
    camera_id: int
    location_id: int
    plate: str
    reason: str = ""
    timestamp: Optional[str] = None
