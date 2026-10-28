"""
Headless check of the simulation backend (needs Postgres up and simulation/data/city.json):

    python -m simulation.selfcheck
"""
import sys

from services.server import Server
from simulation.city_graph import CityGraph
from simulation.engine import run_simulation
from simulation.investigation import Investigator

RUN_ID = "selfcheck"
SEEDS = (1, 2, 3)


def check(condition: bool, message: str) -> None:
    print(f"  [{'ok' if condition else 'FAIL'}] {message}")
    if not condition:
        raise AssertionError(message)


def run_seed(graph: CityGraph, server: Server, seed: int) -> None:
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

    print(f"     crime at camera {crime.node}, tick {crime.tick}; records tested: "
          f"fechada={closed['totals']['records_tested']} aberta={opened['totals']['records_tested']} "
          f"aberta-sem-dica={mass['totals']['records_tested']} bolo=0")


def main() -> int:
    graph = CityGraph.load()
    check(graph.is_valid(), f"graph loaded: {len(graph.nodes)} vertices, {len(graph.edges)} edges, all with a way out")
    server = Server()
    try:
        server.ensure_schema()
        for seed in SEEDS:
            run_seed(graph, server, seed)
    finally:
        server.clear_run(RUN_ID)
        server.close()
    print("selfcheck passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
