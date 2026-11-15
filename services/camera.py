from datetime import datetime, timezone
from typing import Optional

from crypto.block_crumpling import seal_block
from crypto.crumpling import encrypt, generate_nonce, generate_c_prime, generate_k, derive_key
from crypto.escrow import BLOCK_LABEL, GRANULARITY, RECORD_LABEL, CameraEscrow, derive_secret, time_slot
from crypto.signing import CameraSigner, record_ad
from entities.alert import Alert
from entities.blocklist import Blocklist
from entities.record import Record


class Camera:
    def __init__(self, id, location_id, puzzle_level=100, blocklist: Optional[Blocklist] = None, police=None,
                 block_level: Optional[int] = None, block_granularity: str = "hour",
                 block_max_records: Optional[int] = None, escrow: Optional[CameraEscrow] = None):
        self.id = id
        self.location_id = location_id
        self.puzzle_level = puzzle_level # parâmetro configurável do sistema

        # Signing key of this camera (crypto/signing.py). The public half is registered once,
        # at installation, in a registry the Servidor cannot rewrite; every record is signed.
        self.signer = CameraSigner()
        self.public_key = self.signer.public_key_bytes

        # Block crumpling (crypto/block_crumpling.py), off by default. With block_level = T
        # every capture of one time slot (block_granularity) shares one puzzle of size T,
        # and puzzle_level becomes the per-record level inside the block (1 = none).
        # block_max_records optionally closes a block early, so that a single puzzle
        # never opens more than that many records.
        self.block_level = block_level
        self.block_granularity = block_granularity
        self.block_max_records = block_max_records
        self._block_slot: Optional[str] = None
        self._block_seq = 0
        self._block_count = 0
        self._block_label: Optional[str] = None
        self._block_key: Optional[bytes] = None
        self._pending_headers = []

        # Escrow for the Busca Total (crypto/escrow.py), off by default.
        self.escrow = escrow
        if escrow is not None and block_level is not None \
                and GRANULARITY[block_granularity] < GRANULARITY[escrow.session_granularity]:
            raise ValueError("a block cannot span more than one escrow session")

        # bolo_normal (forward-looking, preBOLO.md) support. This is the
        # same physical hardware that runs encrypt_plate below -- it isn't
        # a separate device -- so the blocklist check lives on Camera
        # itself instead of on a wrapper class. Both are optional: a
        # camera created without them behaves exactly as before, with
        # encrypt_plate as its only concern (used as-is by busca_aberta
        # and busca_fechada).
        self.blocklist = blocklist
        self.police = police
        if self.police is not None:
            self.police.register_camera(self)

    def encrypt_plate(self, plate, captured_at: Optional[str] = None) -> Record:
        """
        Encrypts one capture. The capture instant is generated here, by the camera (now, unless
        the simulation passes its own clock), and bound with camera_id into the AES-GCM
        associated data; the finished record is then signed with the camera's key.
        """
        if captured_at is None:
            captured_at = datetime.now(timezone.utc).isoformat()
        session_key = self.escrow.session_key(captured_at) if self.escrow is not None else None

        # Block crumpling: every record of the block also depends on the block key.
        prefix, block = b"", None
        if self.block_level is not None:
            prefix, block = self._block_for(captured_at, session_key)

        c_prime = generate_c_prime()
        if session_key is None:
            k = generate_k(self.puzzle_level)
        else:
            k = derive_secret(session_key, RECORD_LABEL, c_prime, self.puzzle_level)
        nonce = generate_nonce()
        ciphertext = encrypt(plate.encode(), derive_key(prefix + c_prime, k), nonce, record_ad(self.id, captured_at))
        record = Record(
            camera_id=self.id,
            c_prime=c_prime,
            n=self.puzzle_level,
            nonce=nonce,
            ciphertext=ciphertext,
            block=block,
            captured_at=captured_at,
        )
        record.signature = self.signer.sign(record)
        return record

    def _block_for(self, captured_at: str, session_key: Optional[bytes]):
        """Key and label of the block this capture falls in, opening a new block if needed."""
        slot = time_slot(captured_at, self.block_granularity)
        full = self.block_max_records is not None and self._block_count >= self.block_max_records
        if slot != self._block_slot or full:
            self._block_seq = self._block_seq + 1 if slot == self._block_slot else 0
            self._block_slot = slot
            self._block_count = 0
            self._block_label = f"{slot}#{self._block_seq}"
            secret_for = None
            if session_key is not None:
                secret_for = lambda c_prime: derive_secret(session_key, BLOCK_LABEL, c_prime, self.block_level)
            # The previous block key is overwritten here: the camera can no longer open old blocks.
            header, self._block_key = seal_block(self.id, self._block_label, self.block_level, secret_for)
            self._pending_headers.append(header)
        self._block_count += 1
        return self._block_key, self._block_label

    def drain_block_headers(self) -> list:
        """Headers of the blocks opened since the last call (to be uploaded with the records)."""
        headers, self._pending_headers = self._pending_headers, []
        return headers

    def drain_session_wraps(self) -> list:
        """Escrow wraps created since the last call (to be uploaded with the records)."""
        return self.escrow.drain_wraps() if self.escrow is not None else []

    def capture_plate(self, plate: str, timestamp: Optional[str] = None) -> dict:
        """
        Real-time capture flow for bolo_normal: check the local blocklist
        in the clear -- free, O(1), and resolved before encrypt_plate
        would even run -- and, either way, still produce the normal
        encrypted Record via encrypt_plate. bolo_normal is a real-time
        alert layer on top of capture, not a replacement for the usual
        storage (which still serves future busca_aberta/busca_fechada
        requests, including ones about this very plate).

        Only meaningful once a blocklist and a police reference were
        given to this camera; callers that only need encrypt_plate never
        call this method.
        """
        alerted = False
        if self.blocklist is not None and self.blocklist.contains(plate):
            alert = Alert(
                camera_id=self.id,
                location_id=self.location_id,
                plate=plate,
                reason=self.blocklist.reason_for(plate),
                timestamp=timestamp,
            )
            self.police.receive_alert(alert)
            alerted = True

        record = self.encrypt_plate(plate, timestamp)
        return {"record": record, "alerted": alerted}

'''
A ideia do BOLO para o passado é fazer uma decriptação para trás usando câmeras vizinhas, tipo decripta de uma câmera, olha para as vizinhas e tenta encontrar 

É preciso ter um grafo de câmeras

É aqui que mora a relação entre um policial honesto vs stalker 

Cada câmera poderia ter um filtro de bloom (Pesquisar) vazando poucas informaçÕes para facilitar a busca do BOLO -> Serve para avisar se um elemento pertence a um conjunto 
'''
