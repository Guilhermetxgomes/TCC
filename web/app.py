"""
Web UI for the city simulation:

    docker compose up db
    flask --app web.app run          # http://127.0.0.1:5000
"""
import base64
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, jsonify, request

from crypto.block_crumpling import solve_block
from crypto.puzzle import solve_puzzle
from crypto.signing import verify_record
from entities.record import Record
from services.auditor import Auditor, entry_view
from services.committee import QuorumError
from services.judge import DEFAULT_BUDGET_RECORDS
from services.server import Server
from simulation import investigation
from simulation.city_graph import CityGraph
from simulation.engine import World, run_simulation
from simulation.investigation import Investigator
from simulation import attacks, real_search, tolls
from simulation.attacks import ConventionalServer
from simulation import governance_attacks
from simulation.tampering import forge_attack, move_attack

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_RUNS_KEPT = 1  # single-user tool: a new simulation replaces the previous one

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
graph = CityGraph.load()
runs: dict[str, World] = {}
tampered: dict[str, dict[int, Record]] = {}  # run_id -> record_id -> original record (to restore)
conventional: dict[str, ConventionalServer] = {}  # run_id -> the same captures in a conventional backend
governance_undo: dict[str, list] = {}  # run_id -> what the governance attacks changed (to restore)
lock = threading.Lock()  # the simulation is a single-user tool; serialise heavy calls


def _startup() -> None:
    server = Server()
    try:
        server.ensure_schema()
        server.clear_all_runs()  # runs from a previous process are no longer in memory
    finally:
        server.close()


_startup()


def _int(body: dict, key: str, default: int, low: int, high: int) -> int:
    try:
        value = int(body.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


def _world(run_id: str) -> World:
    world = runs.get(run_id)
    if world is None:
        raise KeyError(run_id)
    return world


@app.errorhandler(KeyError)
def unknown_run(error):
    return jsonify({"error": f"simulation run {error} not found; start a new simulation"}), 404


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.get("/api/graph")
def api_graph():
    return jsonify(graph.to_json())


@app.post("/api/simulate")
def api_simulate():
    body = request.get_json(silent=True) or {}
    seed = _int(body, "seed", 1, 0, 1_000_000)
    n_vehicles = _int(body, "n_vehicles", 120, 10, 400)
    ticks = _int(body, "ticks", 240, 60, 600)
    # N is the size of the puzzle. With `block` it protects each camera's 10-minute block as a
    # whole (one puzzle of size N per block, records inside carry none); without it, each record.
    n = _int(body, "puzzle_level", 1000, 2, 100_000)
    block = bool(body.get("block"))
    puzzle_level, block_level = (1, n) if block else (n, None)
    crime_tick = _int(body, "crime_tick", 60, 0, ticks)
    run_id = f"sim-{uuid.uuid4().hex[:8]}"

    with lock:
        server = Server()
        try:
            while len(runs) >= MAX_RUNS_KEPT:
                old = runs.pop(next(iter(runs))).run_id
                tampered.pop(old, None)
                conventional.pop(old, None)
                governance_undo.pop(old, None)
                server.clear_run(old)
            try:
                world = run_simulation(graph, server, run_id, n_vehicles, ticks, puzzle_level, crime_tick, seed,
                                       block_level=block_level)
            except ValueError as error:
                server.clear_run(run_id)
                return jsonify({"error": str(error)}), 400
            runs[run_id] = world
            counts = server.count_by_camera(run_id)
        finally:
            server.close()

    payload = world.to_json()
    payload["record_counts"] = counts
    return jsonify(payload)


@app.post("/api/search")
def api_search():
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    mode = body.get("mode", "fechada")
    window = _int(body, "window_ticks", investigation.DEFAULT_WINDOW_TICKS, 1, 30)
    # until_lost: follow the car until no camera has it any more (no hop limit)
    max_hops = None if body.get("until_lost") else _int(body, "max_hops", investigation.DEFAULT_MAX_HOPS, 1, 20)
    realistic_n = _int(body, "realistic_n", investigation.DEFAULT_REALISTIC_N, 2, 10**12)
    realistic_t = realistic_n  # with block crumpling the same realistic N applies to the block puzzle
    budget = _int(body, "budget_records", DEFAULT_BUDGET_RECORDS, 1, 100_000)  # Busca Fechada token budget

    with lock:
        server = Server()
        try:
            investigator = Investigator(graph, server, world, budget_records=budget)
            if mode == "fechada":
                result = investigator.busca_fechada(window, max_hops, realistic_n, realistic_t)
            elif mode == "aberta":
                result = investigator.busca_aberta(
                    hint_len=_int(body, "hint_len", 3, 0, 7), window_ticks=window, max_hops=max_hops,
                    realistic_n=realistic_n, realistic_t=realistic_t,
                )
            elif mode == "total":
                # `members`: how many committee members take part (the first ones); fewer than
                # the threshold and the request is refused.
                members = _int(body, "members", world.params["committee_threshold"], 0,
                               world.params["committee_members"])
                try:
                    result = investigator.busca_total(member_indexes=list(range(1, members + 1)))
                except QuorumError as error:
                    return jsonify({"error": f"Busca Total recusada: {error}"}), 400
            elif mode == "bolo":
                result = investigator.bolo(delay_ticks=_int(body, "bolo_delay_ticks", 2, 0, 60))
            else:
                return jsonify({"error": f"unknown mode {mode!r}"}), 400
        finally:
            server.close()

    result["crime_plate"] = world.crime.plate
    return jsonify(result)


@app.get("/api/vertex/<int:node_id>")
def api_vertex(node_id: int):
    world = _world(request.args.get("run_id", ""))
    if node_id not in graph.nodes:
        return jsonify({"error": "unknown vertex"}), 404
    limit = _int(request.args, "limit", 100, 1, 500)
    offset = _int(request.args, "offset", 0, 0, 10**9)
    server = Server()
    try:
        data = server.get_rows_for_camera(world.run_id, node_id, limit, offset)
        blocks = server.get_block_headers_for_camera(world.run_id, node_id) if world.params.get("block_level") else []
    finally:
        server.close()
    for row in data["rows"]:
        row["tick"] = world.clock.tick_of(row["captured_at"])
        row["signature_ok"] = verify_record(_record_from_columns(row), world.camera_keys.get(row["camera_id"]))
        row["tampered"] = row["record_id"] in tampered.get(world.run_id, {})
    node = graph.nodes[node_id]
    return jsonify({
        "node": {"id": node.id, "name": node.name, "lat": node.lat, "lon": node.lon},
        "total": data["total"],
        "limit": limit,
        "offset": offset,
        "rows": data["rows"],
        "blocks": blocks,
        "note": "O banco guarda câmera, instante, c_prime, n, nonce, ciphertext e a assinatura da câmera "
                "(Base64). A placa não é armazenada: "
                + ("só é obtida resolvendo o puzzle do bloco (câmera, 10 min) a que o registro pertence."
                   if world.params.get("block_level") else "só é obtida resolvendo o puzzle de cada registro."),
    })


@app.post("/api/record/<int:record_id>/solve")
def api_solve(record_id: int):
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    server = Server()
    try:
        record = server.get_record_by_id(world.run_id, record_id)
        header = None
        if record is not None and record.block is not None:
            header = server.get_block_header(world.run_id, record.camera_id, record.block)
    finally:
        server.close()
    if record is None:
        return jsonify({"error": "record not found"}), 404
    if not verify_record(record, world.camera_keys.get(record.camera_id)):
        # Checked before brute force: a tampered record is refused without spending any attempt.
        return jsonify({"rejected": True, "reason": "assinatura da câmera inválida"})
    attempts, elapsed, prefix = 0, 0.0, b""
    if header is not None:  # block crumpling: the block puzzle comes first
        block = solve_block(header)
        attempts, elapsed, prefix = block["attempts"], block["elapsed_seconds"], block["key"]
    result = solve_puzzle(record, key_prefix=prefix)
    return jsonify({
        "plate": result["plate"], "attempts": attempts + result["attempts"],
        "elapsed_seconds": elapsed + result["elapsed_seconds"], "n": record.n,
    })


def _record_from_columns(row: dict) -> Record:
    return Record(
        camera_id=row["camera_id"], c_prime=base64.b64decode(row["c_prime"]), n=row["n"],
        nonce=base64.b64decode(row["nonce"]), ciphertext=base64.b64decode(row["ciphertext"]),
        block=row["block"], captured_at=row["captured_at"],
        signature=base64.b64decode(row["signature"]) if row["signature"] else None,
    )


def _solve_any(server: Server, world: World, record: Record) -> dict:
    """Brute force as anyone can do it (here: the dishonest operator): block puzzle first, if any."""
    attempts, elapsed, prefix = 0, 0.0, b""
    if record.block is not None:
        block = solve_block(server.get_block_header(world.run_id, record.camera_id, record.block))
        attempts, elapsed, prefix = block["attempts"], block["elapsed_seconds"], block["key"]
    result = solve_puzzle(record, key_prefix=prefix)
    return {"plate": result["plate"], "k": result["k_found"], "prefix": prefix,
            "attempts": attempts + result["attempts"], "seconds": elapsed + result["elapsed_seconds"]}


class TamperError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _tamper(world: World, body: dict) -> dict:
    """
    The dishonest Servidor operator attacks one stored record (by default the criminal's record
    at the crime camera): `move` rewrites its camera and instant, `forge` solves its puzzle and
    re-encrypts another plate. With `persist` the tampered row is written to the database, so
    the searches run afterwards meet it (and reject it); /api/tamper/restore undoes it.
    """
    attack = body.get("attack", "forge")
    if attack not in ("move", "forge"):
        raise TamperError(f"unknown attack {attack!r}")
    crime = world.crime
    with lock:
        server = Server()
        try:
            entry, solved = None, None
            record_id = body.get("record_id")
            if record_id:
                entry = server.get_entry_by_id(world.run_id, int(record_id))
                if entry is None:
                    raise TamperError("registro não encontrado", 404)
            else:  # the criminal's capture at the crime camera: the operator finds it by brute force
                instant = world.clock.iso(crime.tick)
                for candidate in server.get_rows_in_window(world.run_id, crime.node, instant, instant):
                    if not verify_record(candidate["record"], world.camera_keys.get(crime.node)):
                        continue
                    attempt = _solve_any(server, world, candidate["record"])
                    if attempt["plate"] == crime.plate:
                        entry, solved = candidate, attempt
                        break
            if entry is None:
                raise TamperError("registro do carro do crime não encontrado (já adulterado? restaure o banco)", 404)
            if entry["record_id"] in tampered.get(world.run_id, {}):
                raise TamperError("este registro já foi adulterado; restaure o banco primeiro")
            record = entry["record"]
            public_key = world.camera_keys.get(record.camera_id)
            if not verify_record(record, public_key):
                raise TamperError("este registro já não confere com a assinatura")
            if solved is None:
                solved = _solve_any(server, world, record)

            if attack == "move":
                target = _int(body, "target_node", crime.node, min(graph.nodes), max(graph.nodes))
                if target not in graph.nodes or target == record.camera_id:
                    target = next(n for n in sorted(graph.nodes, reverse=True) if n != record.camera_id)
                shift = _int(body, "shift_minutes", 50, -600, 600)
                new_instant = (datetime.fromisoformat(record.captured_at) + timedelta(minutes=shift)).isoformat()
                tampered_record, checks = move_attack(record, solved["k"], solved["prefix"], public_key,
                                                      solved["plate"], target, new_instant)
                summary = {"camera_id": target, "captured_at": new_instant, "plate": solved["plate"]}
            else:
                fake = str(body.get("fake_plate") or "XYZ9Z99").upper()[:7]
                tampered_record, checks = forge_attack(record, solved["k"], solved["prefix"], public_key, fake)
                summary = {"camera_id": record.camera_id, "captured_at": record.captured_at, "plate": fake}

            persisted = bool(body.get("persist", True))
            if persisted:
                server.update_record(world.run_id, entry["record_id"], tampered_record)
                tampered.setdefault(world.run_id, {})[entry["record_id"]] = record
        finally:
            server.close()

    return {
        "attack": attack,
        "record_id": entry["record_id"],
        "is_criminal_record": solved["plate"] == crime.plate,
        "original": {"camera_id": record.camera_id, "captured_at": record.captured_at, "plate": solved["plate"]},
        "tampered": summary,
        "solve": {"attempts": solved["attempts"], "seconds": solved["seconds"]},
        "checks": checks,
        "persisted": persisted,
    }


@app.post("/api/tamper")
def api_tamper():
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    try:
        return jsonify(_tamper(world, body))
    except TamperError as error:
        return jsonify({"error": str(error)}), error.status


def _conventional(world: World) -> ConventionalServer:
    if world.run_id not in conventional:
        conventional.clear()
        conventional[world.run_id] = ConventionalServer(world)
    return conventional[world.run_id]


@app.post("/api/attack")
def api_attack():
    """
    One attack against both systems built from the same captures (simulation/attacks.py):
    the conventional ALPR backend and the Nêmesis. Returns {"conventional": ..., "nemesis": ...}.
    """
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    attack = body.get("attack", "dump")
    realistic_n = _int(body, "realistic_n", investigation.DEFAULT_REALISTIC_N, 2, 10**12)
    budget = min(10.0, max(0.5, float(body.get("budget_seconds") or 3)))
    conv = _conventional(world)
    sim_n = world.params.get("block_level") or world.params["puzzle_level"]

    if attack in ("dump", "track"):
        plate = None
        if attack == "track":  # an arbitrary innocent vehicle, unless a plate is given
            plate = str(body.get("plate") or "").upper().strip()
            if plate not in conv.by_plate:
                innocents = [v.plate for v in world.vehicles if v.plate != world.crime.plate]
                plate = innocents[world.params["seed"] % len(innocents)]
        left = attacks.conventional_dump(conv) if attack == "dump" else attacks.conventional_track(conv, plate)
        with lock:
            server = Server()
            try:
                result = attacks.nemesis_brute_force(server, world, budget, realistic_n, plate)
            finally:
                server.close()
        if attack == "dump":
            right = attacks.describe_nemesis_dump(result, sim_n)
        else:
            right = attacks.describe_nemesis_track(result, plate, len(conv.track(plate)))
        return jsonify({"attack": attack, "plate": plate, "budget_seconds": budget,
                        "conventional": left, "nemesis": right})

    if attack in ("move", "forge"):
        try:
            nemesis = _tamper(world, {**body, "attack": attack})
        except TamperError as error:
            return jsonify({"error": str(error)}), error.status
        original, forged = nemesis["original"], nemesis["tampered"]
        rows = conv.at(original["camera_id"], original["captured_at"])
        row = next((r for r in rows if r.plate == original["plate"]), None)
        if row is None:
            return jsonify({"error": "registro já adulterado no sistema convencional; gere uma nova simulação"}), 400
        if attack == "move":
            conv.update(row, camera_id=forged["camera_id"], captured_at=forged["captured_at"])
            answer = conv.track(original["plate"])
            hit = next(r for r in answer if r.record_id == row.record_id)
            left = attacks._side(False, "UPDATE aceito; a consulta devolve o local e a hora falsos", [
                f"“Onde estava {original['plate']}?” → câmera {hit.camera_id} às {hit.captured_at[11:19]}, "
                f"em vez de câmera {original['camera_id']} às {original['captured_at'][11:19]}.",
                "Nada no registro permite perceber a troca: ele não está vinculado à câmera nem ao instante.",
            ])
        else:
            conv.update(row, plate=forged["plate"])
            present = [r.plate for r in conv.at(original["camera_id"], original["captured_at"])]
            left = attacks._side(False, "UPDATE aceito; o carro do crime some da câmera do crime", [
                f"“Quem passou na câmera {original['camera_id']} às {original['captured_at'][11:19]}?” → "
                + ", ".join(present) + f". {original['plate']} não aparece mais.",
                "A investigação segue a placa falsa ou conclui que o criminoso não passou ali.",
            ])
        if not nemesis["persisted"]:  # a dry run: the conventional copy goes back to the untouched captures
            conventional.pop(world.run_id, None)
        detected = [c for c in nemesis["checks"] if c["detected"]]
        right = attacks._side(bool(detected), "adulteração detectada: " + ", ".join(c["label"] for c in detected), [
            f"{c['label']}: {'detectou' if c['detected'] else 'não detectou'}. {c['detail']}" for c in nemesis["checks"]
        ], persisted=nemesis["persisted"], record_id=nemesis["record_id"])
        return jsonify({"attack": attack, "conventional": left, "nemesis": right, "tamper": nemesis})

    return jsonify({"error": f"unknown attack {attack!r}"}), 400


# ---------- governance: tokens, log, bulletin, reconciliation ----------


@app.get("/api/audit")
def api_audit():
    """Everything the Auditor and the Conselho see for the current run (view 4)."""
    world = _world(request.args.get("run_id", ""))
    gov = world.governance
    with lock:
        server = Server()
        try:
            report = Auditor.for_world(world).reconcile(world, server)
            log = server.get_audit_log(world.run_id)
        finally:
            server.close()
    broken = set(report["chain"]["broken_seqs"])
    bulletin_broken = set(report["bulletin_chain"]["broken_seqs"])
    return jsonify({
        "run_id": world.run_id,
        "now": world.investigation_time(),
        "keys": {"judge": gov.judge.public_key.hex(), "server_log": gov.server_log_public_key.hex()},
        "tokens": report["tokens"],
        "log": [entry_view(entry, broken) for entry in log],
        "checkpoints": gov.checkpoints,
        "bulletin": [{**entry, "broken": entry["seq"] in bulletin_broken} for entry in gov.bulletin.entries()],
        "reconciliation": {key: report[key] for key in ("ok", "discrepancies", "by_operator", "totals")},
        "chain": {key: report["chain"][key] for key in ("ok", "length", "head", "problems")},
        "bulletin_chain": {key: report["bulletin_chain"][key] for key in ("ok", "length", "head", "problems")},
        "pending_restore": len(governance_undo.get(world.run_id, [])),
    })


@app.post("/api/audit/attack")
def api_audit_attack():
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    attack = str(body.get("attack", ""))
    params = {
        "budget_records": _int(body, "budget_records", 3, 1, 1000),
        "realistic_n": _int(body, "realistic_n", investigation.DEFAULT_REALISTIC_N, 2, 10**12),
    }
    with lock:
        server = Server()
        try:
            result = governance_attacks.run(attack, graph, server, world, **params)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        finally:
            server.close()
    if result.get("undo"):
        governance_undo.setdefault(world.run_id, []).append(result["undo"])
    result.pop("undo", None)
    result["pending_restore"] = len(governance_undo.get(world.run_id, []))
    return jsonify(result)


@app.post("/api/audit/restore")
def api_audit_restore():
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    undo = governance_undo.pop(world.run_id, [])
    with lock:
        server = Server()
        try:
            restored = governance_attacks.restore(server, world, undo)
        finally:
            server.close()
    return jsonify({"restored": restored})


# ---------- real traffic (ARTESP toll plazas) ----------

_tolls_summary: dict = {}


@app.get("/api/tolls/summary")
def api_tolls_summary():
    if _tolls_summary:
        return jsonify(_tolls_summary)
    if not tolls.available():
        return jsonify({"error": "simulation/data/pedagio_2026_horario.csv.gz ausente; rode "
                                 "python -m simulation.tolls build <pasta dos CSVs>"}), 404
    data = tolls.load()
    hourly = []
    cameras = []
    for camera in data.cameras:
        nonzero = [i for i, v in enumerate(camera.hourly) if v]
        active = camera.hourly[nonzero[0]:nonzero[-1] + 1] if nonzero else []
        hourly += active
        cameras.append({"id": camera.id, "lot": camera.lot, "plaza": camera.plaza, "direction": camera.direction,
                        "total": camera.total(), "mean_per_hour": camera.total() / data.hours})
    hourly.sort()
    quantile = lambda q: hourly[int(q * (len(hourly) - 1))] if hourly else 0
    total = sum(c["total"] for c in cameras)
    _tolls_summary.update({
        "source": tolls.SOURCE, "start": tolls.START.date().isoformat(), "last_day": data.last_day(),
        "hours": data.hours, "cameras": cameras,
        "network": {
            "cameras": len(cameras), "total": total, "per_year": total * 8760 / data.hours,
            "mean_per_camera_hour": sum(hourly) / len(hourly) if hourly else 0,
            "quantiles": {k: quantile(q) for k, q in (("p10", .1), ("p50", .5), ("p90", .9), ("p99", .99))},
            "max": hourly[-1] if hourly else 0,
            "cameras_over_1000": sum(1 for c in cameras if c["mean_per_hour"] >= 1000),
            "cameras_under_100": sum(1 for c in cameras if c["mean_per_hour"] < 100),
        },
    })
    return jsonify(_tolls_summary)


@app.get("/api/tolls/camera/<int:camera_id>")
def api_tolls_camera(camera_id: int):
    data = tolls.load()
    camera = next((c for c in data.cameras if c.id == camera_id), None)
    if camera is None:
        return jsonify({"error": "praça não encontrada"}), 404
    day = request.args.get("day") or "2026-03-10"
    try:
        first = data.hour_index(datetime.fromisoformat(day))
    except ValueError:
        return jsonify({"error": "data inválida"}), 400
    days = data.hours // 24
    daily = [sum(camera.hourly[d * 24:(d + 1) * 24]) for d in range(days)]
    profile = [sum(camera.hourly[h::24]) / days for h in range(24)]
    return jsonify({
        "camera": {"id": camera.id, "name": camera.name, "lot": camera.lot},
        "day": day, "hourly": camera.hourly[first:first + 24], "profile": profile,
        "daily": daily, "start": tolls.START.date().isoformat(), "total": camera.total(),
    })


@app.post("/api/tolls/search")
def api_tolls_search():
    body = request.get_json(silent=True) or {}
    data = tolls.load()
    camera = next((c for c in data.cameras if c.id == _int(body, "camera_id", 0, 0, 10**6)), None)
    if camera is None:
        return jsonify({"error": "praça não encontrada"}), 404
    try:
        with lock:
            result = real_search.run(
                data, camera, str(body.get("day") or "2026-03-10"), _int(body, "start_hour", 17, 0, 23),
                _int(body, "hours", 1, 1, 6), _int(body, "demo_n", 100, 2, 1000),
                _int(body, "realistic_n", investigation.DEFAULT_REALISTIC_N, 2, 10**12),
                seed=_int(body, "seed", 0, 0, 10**9),
            )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(result)


@app.post("/api/tamper/restore")
def api_tamper_restore():
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    originals = tampered.pop(world.run_id, {})
    conventional.pop(world.run_id, None)  # the conventional copy is rebuilt from the untouched captures
    with lock:
        server = Server()
        try:
            for record_id, record in originals.items():
                server.update_record(world.run_id, record_id, record)
        finally:
            server.close()
    return jsonify({"restored": sorted(originals)})
