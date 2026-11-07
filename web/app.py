"""
Web UI for the city simulation:

    docker compose up db
    flask --app web.app run          # http://127.0.0.1:5000
"""
import threading
import uuid
from pathlib import Path

from flask import Flask, jsonify, request

from crypto.puzzle import solve_puzzle
from services.server import Server
from simulation import investigation
from simulation.city_graph import CityGraph
from simulation.engine import World, run_simulation
from simulation.investigation import Investigator

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_RUNS_KEPT = 1  # single-user tool: a new simulation replaces the previous one

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
graph = CityGraph.load()
runs: dict[str, World] = {}
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
    puzzle_level = _int(body, "puzzle_level", 1000, 2, 100_000)
    crime_tick = _int(body, "crime_tick", 60, 0, ticks)
    run_id = f"sim-{uuid.uuid4().hex[:8]}"

    with lock:
        server = Server()
        try:
            while len(runs) >= MAX_RUNS_KEPT:
                server.clear_run(runs.pop(next(iter(runs))).run_id)
            try:
                world = run_simulation(graph, server, run_id, n_vehicles, ticks, puzzle_level, crime_tick, seed)
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

    with lock:
        server = Server()
        try:
            investigator = Investigator(graph, server, world)
            if mode == "fechada":
                result = investigator.busca_fechada(window, max_hops, realistic_n)
            elif mode == "aberta":
                result = investigator.busca_aberta(
                    hint_len=_int(body, "hint_len", 3, 0, 7), window_ticks=window, max_hops=max_hops,
                    realistic_n=realistic_n,
                )
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
    finally:
        server.close()
    for row in data["rows"]:
        row["tick"] = world.clock.tick_of(row["captured_at"])
    node = graph.nodes[node_id]
    return jsonify({
        "node": {"id": node.id, "name": node.name, "lat": node.lat, "lon": node.lon},
        "total": data["total"],
        "limit": limit,
        "offset": offset,
        "rows": data["rows"],
        "note": "O banco guarda só c_prime, n, nonce e ciphertext (Base64). A placa não é armazenada: "
                "só é obtida resolvendo o puzzle de cada registro.",
    })


@app.post("/api/record/<int:record_id>/solve")
def api_solve(record_id: int):
    body = request.get_json(silent=True) or {}
    world = _world(str(body.get("run_id", "")))
    server = Server()
    try:
        record = server.get_record_by_id(world.run_id, record_id)
    finally:
        server.close()
    if record is None:
        return jsonify({"error": "record not found"}), 404
    result = solve_puzzle(record)
    return jsonify({
        "plate": result["plate"], "attempts": result["attempts"],
        "elapsed_seconds": result["elapsed_seconds"], "n": record.n,
    })
