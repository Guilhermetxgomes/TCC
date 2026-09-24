from dataclasses import dataclass


@dataclass
class BlocklistEntry:
    """
    One BOLO plate held in a camera's local blocklist. Carries a TTL
    (`expires_at`) so it does not sit in the camera's limited memory
    forever -- optimized for the camera's constrained hardware, not for
    police convenience.
    """
    reason: str
    expires_at: float
