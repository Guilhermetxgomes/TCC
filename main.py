from services.camera import Camera
from services.servidor import Servidor
from crypto.puzzle import solve_puzzle


def rodar_cenario(puzzle_level: int, placa: str = "ABC1234"):
    print(f"\n=== Testando com N = {puzzle_level} ===")

    camera = Camera(id=1, location_id=42)
    camera.puzzle_level = puzzle_level

    record = camera.encrypt_plate(placa)
    print(f"Placa cifrada. c_prime={record.c_prime.hex()[:16]}...")

    servidor = Servidor()
    servidor.save(record)
    print("Registro salvo no banco.")

    registros = servidor.get_records_by_camera_id(camera.id)
    registro_recuperado = registros[-1]  # pega o mais recente
    print("Registro recuperado do banco.")

    resultado = solve_puzzle(registro_recuperado)

    if resultado["success"]:
        print(f"Puzzle resolvido! Placa: {resultado['plate']}")
        print(f"K encontrado: {resultado['k_found']}")
        print(f"Tentativas: {resultado['attempts']}")
        print(f"Tempo: {resultado['elapsed_seconds']:.4f} segundos")
    else:
        print("Puzzle NÃO resolvido dentro do espaço de busca.")


if __name__ == "__main__":
    rodar_cenario(puzzle_level=100)
    rodar_cenario(puzzle_level=10_000)
    rodar_cenario(puzzle_level=1_000_000)