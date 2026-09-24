from typing import Optional

from crypto.crumpling import encrypt, generate_nonce, generate_c_prime, generate_k, derive_key
from entities.alert import Alert
from entities.blocklist import Blocklist
from entities.record import Record


class Camera:
    def __init__(self, id, location_id, puzzle_level=100, blocklist: Optional[Blocklist] = None, police=None):
        self.id = id
        self.location_id = location_id
        self.puzzle_level = puzzle_level # parâmetro configurável do sistema

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

    def generate_key_pair(self):
        c_prime = generate_c_prime()
        k = generate_k(self.puzzle_level)
        return {
            "c_prime": c_prime,
            "key": derive_key(c_prime, k)
        }

    def encrypt_plate(self, plate):
        key_pair = self.generate_key_pair()
        key = key_pair["key"]
        c_prime = key_pair["c_prime"]
        nonce = generate_nonce()
        encrypt_plate = encrypt(plate.encode(), key, nonce, None)
        return Record(
            camera_id=self.id,
            c_prime=c_prime,
            n=self.puzzle_level,
            nonce=nonce,
            ciphertext=encrypt_plate
        )

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

        record = self.encrypt_plate(plate)
        return {"record": record, "alerted": alerted}

'''
A ideia do BOLO para o passado é fazer uma decriptação para trás usando câmeras vizinhas, tipo decripta de uma câmera, olha para as vizinhas e tenta encontrar 

É preciso ter um grafo de câmeras

É aqui que mora a relação entre um policial honesto vs stalker 

Cada câmera poderia ter um filtro de bloom (Pesquisar) vazando poucas informaçÕes para facilitar a busca do BOLO -> Serve para avisar se um elemento pertence a um conjunto 
'''
