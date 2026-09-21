from crypto.crumpling import encrypt, generate_nonce, generate_c_prime, generate_k, derive_key
from entities.record import Record


class Camera:
    def __init__(self, id, location_id, puzzle_level = 100):
        self.id = id
        self.location_id = location_id
        self.puzzle_level = puzzle_level # parâmetro configurável do sistema

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

'''
A ideia do BOLO para o passado é fazer uma decriptação para trás usando câmeras vizinhas, tipo decripta de uma câmera, olha para as vizinhas e tenta encontrar 

É preciso ter um grafo de câmeras

É aqui que mora a relação entre um policial honesto vs stalker 

Cada câmera poderia ter um filtro de bloom (Pesquisar) vazando poucas informaçÕes para facilitar a busca do BOLO -> Serve para avisar se um elemento pertence a um conjunto 
'''
