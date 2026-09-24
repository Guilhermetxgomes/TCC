import time

from entities.blocklist_entry import BlocklistEntry


class Blocklist:
    """
    A camera's own local, in-memory BOLO list -- the piece that makes the
    "bolo_normal" case (forward-looking) from preBOLO.md cheap:

        1. Cameras are notified of the blocklist
        2. Cameras that see a blocklisted plate alert the police directly

    Design decisions:

    - Storage is local to the camera (a plain dict), not a remote lookup.
      The blocklist check runs on every single plate capture, so it has to
      be as cheap as possible on constrained camera hardware -- O(1),
      no network round-trip.

    - The blocklist itself is not a secret (unlike PreBOLO's bloom
      filters, which deliberately leak little): it is the same plate the
      police already publicized, so there is no privacy concern in every
      camera holding it in clear text.

    - Every entry carries a TTL. Without one, a camera that stays online
      for months would accumulate every BOLO ever issued and its memory
      footprint would grow without bound. Expired entries are purged
      lazily, on the next access that touches them, so the camera never
      needs a background timer or a housekeeping task running outside its
      normal capture loop.
    """

    def __init__(self):
        self._entries: dict[str, BlocklistEntry] = {}

    def add(self, plate: str, reason: str = "", ttl_seconds: float = 24 * 3600) -> None:
        self._entries[plate] = BlocklistEntry(reason=reason, expires_at=time.time() + ttl_seconds)

    def contains(self, plate: str) -> bool:
        self._purge_expired()
        return plate in self._entries

    def reason_for(self, plate: str) -> str:
        self._purge_expired()
        entry = self._entries.get(plate)
        return entry.reason if entry else ""

    def _purge_expired(self) -> None:
        now = time.time()
        expired_plates = [plate for plate, entry in self._entries.items() if entry.expires_at <= now]
        for plate in expired_plates:
            del self._entries[plate]

    def __len__(self) -> int:
        self._purge_expired()
        return len(self._entries)
