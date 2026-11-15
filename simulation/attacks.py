"""
The same attacks against two systems built from the same simulated captures:

- a conventional ALPR backend (ConventionalServer): what a typical deployment stores --
  plate, camera and instant per capture, searchable by plate. Encrypting the table at
  rest with one server key does not change any result below: whoever runs the server,
  or steals the key with the database, reads it as if it were in the clear.
- the Nêmesis (services.server.Server + the cameras' puzzles, AD and signatures).

Attacks (the attacker is a dishonest Servidor operator or whoever dumped its database):

- dump:   read every stored plate (mass surveillance / leak, attackers A2 and A3).
- track:  follow one arbitrary vehicle, knowing only its plate (a stalker).
- move:   rewrite camera and instant of a capture (false alibi / false accusation).
- forge:  replace the plate of a capture (make the criminal's car disappear).

Against the Nêmesis, dump and track are run for real for a small time budget, with the
simulation's N, and the full cost is extrapolated to a realistic N; move and forge reuse
simulation/tampering.py.
"""
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from crypto.block_crumpling import solve_block
from crypto.puzzle import solve_puzzle
from crypto.signing import verify_record
from simulation import costs
from simulation.engine import World

if TYPE_CHECKING:
    from services.server import Server


@dataclass
class ConventionalRow:
    record_id: int
    camera_id: int
    captured_at: str
    plate: str


class ConventionalServer:
    """Plates stored as they are read, indexed by plate (the usual design)."""

    def __init__(self, world: World):
        captures = sorted(
            (tick, vehicle.id, node, vehicle.plate) for vehicle in world.vehicles for tick, node in vehicle.arrivals
        )
        self.rows = [ConventionalRow(i + 1, node, world.clock.iso(tick), plate)
                     for i, (tick, _, node, plate) in enumerate(captures)]
        self.by_plate: dict[str, list[ConventionalRow]] = {}
        for row in self.rows:
            self.by_plate.setdefault(row.plate, []).append(row)

    def dump(self) -> list[ConventionalRow]:
        return list(self.rows)  # SELECT * FROM captures

    def track(self, plate: str) -> list[ConventionalRow]:
        return sorted(self.by_plate.get(plate, []), key=lambda r: r.captured_at)  # WHERE plate = %s

    def at(self, camera_id: int, captured_at: str) -> list[ConventionalRow]:
        return [r for r in self.rows if r.camera_id == camera_id and r.captured_at == captured_at]

    def update(self, row: ConventionalRow, **changes):
        old = row.plate
        for key, value in changes.items():
            setattr(row, key, value)
        if "plate" in changes:  # keep the index consistent, as the database would
            self.by_plate[old].remove(row)
            self.by_plate.setdefault(row.plate, []).append(row)


def _side(blocked: bool, headline: str, details: list[str], **extra) -> dict:
    return {"blocked": blocked, "headline": headline, "details": details, **extra}


def conventional_dump(conv: ConventionalServer) -> dict:
    started = time.perf_counter()
    rows = conv.dump()
    routes: dict[str, int] = {}
    for row in rows:
        routes[row.plate] = routes.get(row.plate, 0) + 1
    seconds = time.perf_counter() - started
    return _side(False, f"leu as {fmt_int(len(rows))} placas em {fmt_ms(seconds)}", [
        f"{len(routes)} veículos com o trajeto completo reconstruído (média de "
        f"{len(rows) / max(1, len(routes)):.0f} avistamentos por veículo).",
        "Cifrar a tabela com uma chave do servidor não muda nada: quem opera o servidor ou leva a chave junto "
        "com o banco lê tudo do mesmo jeito.",
    ], records=len(rows), seconds=seconds)


def conventional_track(conv: ConventionalServer, plate: str) -> dict:
    started = time.perf_counter()
    rows = conv.track(plate)
    seconds = time.perf_counter() - started
    route = [f"câmera {r.camera_id} às {r.captured_at[11:19]}" for r in rows[:8]]
    return _side(False, f"{len(rows)} avistamentos de {plate} em {fmt_ms(seconds)}, com uma consulta", [
        "Trajeto: " + "; ".join(route) + ("…" if len(rows) > 8 else "."),
        "Não é preciso saber onde nem quando o veículo passou: a placa é o índice da tabela.",
    ], sightings=len(rows), seconds=seconds)


def _all_rows(server: "Server", world: World) -> list[dict]:
    day = world.clock.iso(0)[:10]
    rows = []
    for camera_id in sorted(server.count_by_camera(world.run_id)):
        rows += server.get_rows_in_session(world.run_id, camera_id, day)
    rows.sort(key=lambda r: (r["captured_at"], r["record_id"]))
    return rows


def nemesis_brute_force(server: "Server", world: World, budget_seconds: float, realistic_n: int,
                        target_plate: Optional[str] = None) -> dict:
    """
    Opens stored records one after another, with the simulation's N, until the time budget
    runs out (what an attacker holding the dumped database can do), then extrapolates the
    cost of opening all of them with a realistic N.
    """
    rows = _all_rows(server, world)
    block_keys: dict[tuple, bytes] = {}
    opened, attempts, sightings, rejected = 0, 0, 0, 0
    started = time.perf_counter()
    for row in rows:
        if time.perf_counter() - started >= budget_seconds:
            break
        record = row["record"]
        if not verify_record(record, world.camera_keys.get(record.camera_id)):
            rejected += 1
            continue
        prefix = b""
        if record.block is not None:
            key = (record.camera_id, record.block)
            if key not in block_keys:
                solved = solve_block(server.get_block_header(world.run_id, record.camera_id, record.block),
                                     sequential=True)
                block_keys[key] = solved["key"]
                attempts += solved["attempts"]
            prefix = block_keys[key]
        result = solve_puzzle(record, key_prefix=prefix, sequential=True)
        attempts += result["attempts"]
        opened += 1
        sightings += result["plate"] == target_plate
    seconds = time.perf_counter() - started
    per_attempt = seconds / attempts if attempts else 0.0
    block_mode = world.params.get("block_level") is not None
    if block_mode:  # one block puzzle per camera and 10-minute slot opens all its records
        blocks = len({(r["record"].camera_id, r["record"].block) for r in rows})
        full_attempts = blocks * costs.expected_attempts(realistic_n)
    else:
        full_attempts = len(rows) * costs.expected_attempts(realistic_n)
    full_seconds = full_attempts * per_attempt
    return {
        "records": len(rows), "opened": opened, "attempts": attempts, "seconds": seconds, "rejected": rejected,
        "sightings": sightings, "seconds_per_attempt": per_attempt, "realistic_n": realistic_n,
        "full_seconds": full_seconds, "full_usd": costs.cost_usd(full_seconds),
        "city_seconds": costs.CITY_CAMERAS * costs.CITY_RECORDS_PER_CAMERA_HOUR * costs.CITY_HOURS
        * costs.expected_attempts(realistic_n) * per_attempt,
    }


def describe_nemesis_dump(result: dict, sim_n: int) -> dict:
    pct = 100 * result["opened"] / max(1, result["records"])
    share = f"{pct:.1f}".replace(".", ",")
    return _side(True, f"abriu {fmt_int(result['opened'])} de {fmt_int(result['records'])} registros "
                       f"({share}%) no mesmo tempo de ataque", [
        f"Com o N da simulação ({fmt_int(sim_n)}), cada registro custou em média "
        f"{fmt_int(result['attempts'] / max(1, result['opened']))} tentativas; nada no banco indica a placa.",
        f"Abrir a base inteira com N = {fmt_int(result['realistic_n'])}: {fmt_duration(result['full_seconds'])} "
        f"de um núcleo, {fmt_usd(result['full_usd'])}.",
        f"Uma cidade inteira por um ano (5.000 câmeras × 1.000 veículos/h), mesmo N: "
        f"{fmt_duration(result['city_seconds'])} de um núcleo.",
    ], **result)


def describe_nemesis_track(result: dict, plate: str, total_sightings: int) -> dict:
    return _side(True, f"achou {result['sightings']} de {total_sightings} avistamentos de {plate} no mesmo tempo", [
        "Não há índice por placa: sem saber onde e quando o veículo passou, só resta abrir os registros "
        f"um a um. No tempo do ataque foram abertos {fmt_int(result['opened'])} de {fmt_int(result['records'])}.",
        f"Achar todos os avistamentos exige abrir a base inteira: com N = {fmt_int(result['realistic_n'])}, "
        f"{fmt_duration(result['full_seconds'])} de um núcleo, o mesmo custo da varredura em massa.",
        "Uma Busca Fechada legítima é barata porque parte de um local e de um instante conhecidos (o crime).",
    ], **result)


def fmt_int(value: float) -> str:
    return f"{value:,.0f}".replace(",", ".")


def fmt_ms(seconds: float) -> str:
    return f"{seconds * 1000:.2f} ms".replace(".", ",")


def fmt_usd(value: float) -> str:
    return "US$ " + f"{value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def fmt_duration(seconds: float) -> str:
    for limit, div, unit in ((60, 1, "s"), (3600, 60, "min"), (86400, 3600, "h"), (86400 * 365, 86400, "dias")):
        if seconds < limit:
            return f"{seconds / div:.1f} {unit}".replace(".", ",")
    return f"{seconds / (86400 * 365):,.0f} anos".replace(",", ".")
