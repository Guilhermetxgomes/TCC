"""
Headless check of the simulation backend (needs simulation/data/city.json):

    python -m simulation.selfcheck            # against Postgres (docker compose up db)
    python -m simulation.selfcheck --memory   # no database: simulation.memory_server
"""
import sys

from crypto.puzzle import solve_puzzle
from crypto.signing import verify_record
from services.auditor import Auditor
from services.committee import QuorumError
from simulation import governance_attacks
from simulation.tampering import forge_attack, move_attack
from simulation.city_graph import CityGraph
from simulation.engine import run_simulation
from simulation.investigation import Investigator

RUN_ID = "selfcheck"
SEEDS = (1, 2, 3)


def check(condition: bool, message: str) -> None:
    print(f"  [{'ok' if condition else 'FAIL'}] {message}")
    if not condition:
        raise AssertionError(message)


def run_seed(graph: CityGraph, server, seed: int) -> None:
    print(f"seed {seed}")
    server.clear_run(RUN_ID)
    world = run_simulation(graph, server, RUN_ID, n_vehicles=80, ticks=240, puzzle_level=1000,
                           crime_tick=60, seed=seed)
    crime = world.crime
    counts = server.count_by_camera(RUN_ID)
    check(sum(counts.values()) == world.params["records"], "every capture was stored in the database")
    check(counts.get(crime.node, 0) > 0, "the crime camera has records")

    investigator = Investigator(graph, server, world)

    closed = investigator.busca_fechada()
    check(closed["truth"]["followed_criminal"], "busca_fechada trail matches the real escape route")
    check(closed["truth"]["traced_nodes"] >= 4, f"busca_fechada followed {closed['truth']['traced_nodes']} cameras")

    opened = investigator.busca_aberta(hint_len=3)
    decrypt = opened["steps"][0]
    first_probe = closed["steps"][0]
    check(decrypt["records_tested"] >= first_probe["records_tested"],
          "busca_aberta decrypts at least as many records as busca_fechada at the crime camera")
    check(opened["truth"]["followed_criminal"], "busca_aberta (3-letter hint) also follows the criminal")

    mass = investigator.busca_aberta(hint_len=0)
    check(mass["totals"]["records_tested"] > closed["totals"]["records_tested"],
          "busca_aberta without a hint costs more than busca_fechada")

    bolo = investigator.bolo(delay_ticks=2)
    alert_ticks = [s["tick"] for s in bolo["steps"]]
    check(all(t > bolo["extra"]["bolo_tick"] for t in alert_ticks), "BOLO alerts only after the broadcast")
    check(bolo["totals"]["attempts"] == 0, "BOLO costs no puzzle attempts")
    check(bolo["truth"]["followed_criminal"] and len(alert_ticks) > 0, "BOLO alerts follow the criminal")

    total = investigator.busca_total()
    extra = total["extra"]
    check(total["totals"]["attempts"] == 0, "busca_total costs no puzzle attempts")
    check(total["truth"]["followed_criminal"] and total["truth"]["skipped_sightings"] == 0
          and total["truth"]["traced_nodes"] == len(total["truth"]["escape"]),
          "busca_total recovers the criminal's complete route")
    check(total["totals"]["records_tested"] == world.params["records"],
          "busca_total opens every record of the session")
    check(extra["partial_decryptions"] == extra["threshold"] * extra["wraps_opened"],
          f"busca_total used {extra['threshold']} partial decryptions per camera wrap")
    check(extra["other_plates_exposed"] == world.params["n_vehicles"] - 1,
          "busca_total exposes every other vehicle too")
    try:
        investigator.busca_total(member_indexes=list(range(1, extra["threshold"])))
        check(False, "busca_total without quorum must be refused")
    except QuorumError:
        check(True, f"busca_total is refused with {extra['threshold'] - 1} of {extra['threshold']} members")
    scoped = investigator.busca_total(camera_ids=[crime.node])
    check(scoped["extra"]["wraps_opened"] == 1 and scoped["totals"]["records_tested"] == counts[crime.node],
          "busca_total restricted to one camera opens only that camera")

    check(all(verify_record(r["record"], world.camera_keys[crime.node])
              for r in server.get_rows_in_session(RUN_ID, crime.node, crime_session(world))),
          "every stored record of the crime camera carries a valid camera signature")
    run_tamper_checks(graph, server, world)
    run_governance_checks(graph, server, world)

    print(f"     crime at camera {crime.node}, tick {crime.tick}; records tested: "
          f"fechada={closed['totals']['records_tested']} aberta={opened['totals']['records_tested']} "
          f"aberta-sem-dica={mass['totals']['records_tested']} bolo=0 total={total['totals']['records_tested']}")


def crime_session(world) -> str:
    return world.clock.iso(world.crime.tick)[:10]


def run_tamper_checks(graph: CityGraph, server, world) -> None:
    """A dishonest operator forges the criminal's record: the search must reject it, not follow it."""
    crime = world.crime
    instant = world.clock.iso(crime.tick)
    entry = next(row for row in server.get_rows_in_window(RUN_ID, crime.node, instant, instant)
                 if solve_puzzle(row["record"])["plate"] == crime.plate)
    record = entry["record"]
    k = solve_puzzle(record)["k_found"]
    forged, _ = forge_attack(record, k, b"", world.camera_keys[crime.node], "XYZ9Z99")
    server.update_record(RUN_ID, entry["record_id"], forged)
    try:
        closed = Investigator(graph, server, world).busca_fechada()
        first = closed["steps"][0]
        check(first["rejected"] == 1 and entry["record_id"] in first["rejected_ids"] and not first["found"],
              "busca_fechada rejects the forged record (signature) instead of reading the forged plate")
        moved, _ = move_attack(record, k, b"", world.camera_keys[crime.node], crime.plate,
                               crime.node, world.clock.iso(crime.tick + 1))
        server.update_record(RUN_ID, entry["record_id"], moved)
        total = Investigator(graph, server, world).busca_total(camera_ids=[crime.node])
        check(total["totals"]["rejected"] == 1, "busca_total also rejects a record moved to another instant")
    finally:
        server.update_record(RUN_ID, entry["record_id"], record)
    check(Investigator(graph, server, world).busca_fechada()["truth"]["followed_criminal"],
          "after restoring the record the search follows the criminal again")


def run_governance_checks(graph: CityGraph, server, world) -> None:
    """Tokens, log, bulletin and reconciliation over the searches this seed already ran."""
    log = server.get_audit_log(RUN_ID)
    report = Auditor.for_world(world).reconcile(world, server)
    totals = report["totals"]
    check(report["chain"]["ok"] and len(log) == totals["log_entries"] > 0,
          f"the Servidor's log is an intact chain of {len(log)} entries")
    check(report["ok"], f"honest searches reconcile clean: {totals['tokens']} tokens, {totals['releases']} releases, "
                        f"{totals['verified']} of {totals['declared']} declarations verified")
    check(all(e["token_id"] for e in log if e["kind"] in ("release", "release_wraps")), "every release names its token")
    check(any(e["kind"] == "activation" for e in world.governance.bulletin.entries()),
          "the Busca Total left a public trace in the bulletin")
    undo = []
    for attack in governance_attacks.ATTACKS:
        result = governance_attacks.run(attack, graph, server, world)
        if result["undo"]:
            undo.append(result["undo"])
        if attack == "offlog_dump":
            check(not result["checks"][0]["detected"] and not result["checks"][1]["detected"],
                  "a copy of the database outside the gate leaves no trace in the log (only the puzzle cost remains)")
        else:
            check(result["contained"], f"governance attack '{attack}' is caught: "
                  + ", ".join(c["label"] for c in result["checks"] if c["detected"]))
    governance_attacks.restore(server, world, undo)
    check(Auditor.for_world(world).reconcile(world, server)["ok"], "after restoring, the reconciliation is clean again")


def run_block_seed(graph: CityGraph, server, seed: int) -> None:
    """Same crime, cameras using block crumpling (one puzzle per camera per 10 simulated minutes)."""
    print(f"seed {seed} (block crumpling)")
    server.clear_run(RUN_ID)
    per_record = run_simulation(graph, server, RUN_ID, n_vehicles=80, ticks=240, puzzle_level=1000,
                                crime_tick=60, seed=seed)
    baseline = Investigator(graph, server, per_record).busca_aberta(hint_len=0)

    server.clear_run(RUN_ID)
    world = run_simulation(graph, server, RUN_ID, n_vehicles=80, ticks=240, puzzle_level=1,
                           crime_tick=60, seed=seed, block_level=20_000)
    investigator = Investigator(graph, server, world)

    closed = investigator.busca_fechada()
    check(closed["truth"]["followed_criminal"], "busca_fechada over blocks matches the real escape route")
    check(closed["totals"]["blocks_solved"] > 0, f"busca_fechada solved {closed['totals']['blocks_solved']} block puzzles")
    check(closed["totals"]["attempts"] == closed["totals"]["block_attempts"] + closed["totals"]["records_tested"],
          "with n = 1 all the work is in the block puzzles")

    again = investigator.busca_fechada()
    check(again["totals"]["blocks_solved"] == 0, "a block that was already solved costs nothing the second time")

    opened = Investigator(graph, server, world).busca_aberta(hint_len=0)
    check(opened["totals"]["records_tested"] == baseline["totals"]["records_tested"],
          "busca_aberta opens the same records in both schemes")
    check(opened["totals"]["blocks_solved"] < opened["totals"]["records_tested"],
          f"busca_aberta: {opened['totals']['blocks_solved']} block puzzles for "
          f"{opened['totals']['records_tested']} records")

    total = investigator.busca_total()
    check(total["truth"]["followed_criminal"] and total["totals"]["attempts"] == 0,
          "busca_total also opens block-crumpled records without any puzzle")


def main() -> int:
    graph = CityGraph.load()
    check(graph.is_valid(), f"graph loaded: {len(graph.nodes)} vertices, {len(graph.edges)} edges, all with a way out")
    if "--memory" in sys.argv[1:]:
        from simulation.memory_server import MemoryServer
        server = MemoryServer()
    else:
        from services.server import Server
        server = Server()
    try:
        server.ensure_schema()
        for seed in SEEDS:
            run_seed(graph, server, seed)
        run_block_seed(graph, server, SEEDS[0])
    finally:
        server.clear_run(RUN_ID)
        server.close()
    print("selfcheck passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
