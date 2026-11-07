"""
The three ways of looking for the criminal's car after the crime:

- busca_fechada: the plate is known; puzzles are solved record by record until it appears,
  first at the crime camera and then, hop by hop, at the neighbour cameras the car may
  have taken (most probable edge first).
- busca_aberta: the plate is unknown (maybe a partial one from a witness); every record in
  the crime window is decrypted, the candidates are filtered by the hint and each one is
  traced like in busca_fechada.
- bolo: the police broadcasts the plate to every camera, which then alert in the clear
  (no puzzle) -- but only about sightings after the broadcast.

Every function returns the list of `steps` that the web UI animates, the traced paths and
the cost (measured with the real, small puzzle_level + extrapolated to a realistic one).
"""
import contextlib
import io
from typing import Optional

from crypto.puzzle import solve_puzzle
from entities.blocklist import Blocklist
from services.camera import Camera
from services.police import Police
from services.server import Server
from simulation import costs
from simulation.city_graph import CityGraph
from simulation.engine import World, travel_window

DEFAULT_WINDOW_TICKS = 6  # +-1 min around the crime
DEFAULT_MAX_HOPS = 6
DEFAULT_MAX_SUSPECTS = 30
DEFAULT_REALISTIC_N = 10_000_000


class Investigator:
    def __init__(self, graph: CityGraph, server: Server, world: World):
        self.graph = graph
        self.server = server
        self.world = world
        self.clock = world.clock
        self.run_id = world.run_id

    # -- building blocks ------------------------------------------------

    def _window(self, node: int, tick_from: int, tick_to: int) -> list[dict]:
        return self.server.get_rows_in_window(
            self.run_id, node, self.clock.iso(max(tick_from, 0)), self.clock.iso(tick_to)
        )

    def _probe(self, node: int, tick_from: int, tick_to: int, plate: str) -> dict:
        """Solves the puzzles of one camera window in order until `plate` shows up."""
        rows = self._window(node, tick_from, tick_to)
        step = {
            "kind": "probe", "node": node, "from_tick": tick_from, "to_tick": tick_to,
            "records_in_window": len(rows), "records_tested": 0, "attempts": 0,
            "real_seconds": 0.0, "found": False, "tick": None, "record_id": None,
        }
        for row in rows:
            result = solve_puzzle(row["record"])
            step["records_tested"] += 1
            step["attempts"] += result["attempts"]
            step["real_seconds"] += result["elapsed_seconds"]
            if result["plate"] == plate:
                step.update(found=True, tick=self.clock.tick_of(row["captured_at"]), record_id=row["record_id"])
                break
        return step

    def _trace(self, plate: str, node: int, tick: int, max_hops: Optional[int], suspect: Optional[str] = None):
        """
        Follows `plate` away from (node, tick): probe the likeliest next cameras first.

        max_hops=None follows the car until the trail goes cold. That always terminates:
        every hop moves at least one tick forward and there are no records past the end
        of the recording. Returns (steps, path, stop_reason), where stop_reason is
        "max_hops" (limit reached) or "lost" (no camera has the plate in its window:
        end of the recording or a lost trail).
        """
        steps, path = [], [(node, tick)]
        previous = None  # the investigator does not know where the car came from
        stop_reason = "lost"
        hops = 0
        while True:
            if max_hops is not None and hops >= max_hops:
                stop_reason = "max_hops"
                break
            probs = self.graph.next_probs(node, previous)
            hit = None
            order = sorted(probs, key=probs.get, reverse=True)
            if previous is not None and previous not in probs and (node, previous) in self.graph.edges:
                # Last resort before giving up: the no-U-turn rule assumes we know where the car came
                # from, but if the window skipped a camera we do not, and going back may be legitimate.
                order.append(previous)
            for candidate in order:
                low, high = travel_window(self.graph, node, candidate)
                step = self._probe(candidate, tick + low, tick + high, plate)
                step.update(from_node=node, p=probs.get(candidate, 0.0), suspect=suspect)
                steps.append(step)
                if step["found"]:
                    hit = step
                    break
            if hit is None:
                break  # lost the trail (e.g. beyond the end of the recordings)
            previous, node, tick = node, hit["node"], hit["tick"]
            path.append((node, tick))
            hops += 1
        return steps, path, stop_reason

    # -- modalities -----------------------------------------------------

    def busca_fechada(self, window_ticks: int = DEFAULT_WINDOW_TICKS, max_hops: Optional[int] = DEFAULT_MAX_HOPS,
                      realistic_n: int = DEFAULT_REALISTIC_N) -> dict:
        crime = self.world.crime
        first = self._probe(crime.node, crime.tick - window_ticks, crime.tick + window_ticks, crime.plate)
        first.update(from_node=None, p=None, suspect=crime.plate)
        steps, paths = [first], []
        if first["found"]:
            trace_steps, path, stop = self._trace(crime.plate, crime.node, first["tick"], max_hops, crime.plate)
            steps += trace_steps
            paths.append({"plate": crime.plate, "is_criminal": True, "nodes": path, "stopped_by": stop})
        return self._result("fechada", steps, paths, realistic_n)

    def busca_aberta(self, hint_len: int = 3, window_ticks: int = DEFAULT_WINDOW_TICKS,
                     max_hops: Optional[int] = DEFAULT_MAX_HOPS, max_suspects: int = DEFAULT_MAX_SUSPECTS,
                     realistic_n: int = DEFAULT_REALISTIC_N) -> dict:
        crime = self.world.crime
        rows = self._window(crime.node, crime.tick - window_ticks, crime.tick + window_ticks)
        decrypt = {
            "kind": "decrypt_window", "node": crime.node, "from_tick": crime.tick - window_ticks,
            "to_tick": crime.tick + window_ticks, "records_in_window": len(rows),
            "records_tested": 0, "attempts": 0, "real_seconds": 0.0, "found": False,
        }
        candidates = []  # (plate, tick) decrypted from the window
        for row in rows:
            result = solve_puzzle(row["record"])
            decrypt["records_tested"] += 1
            decrypt["attempts"] += result["attempts"]
            decrypt["real_seconds"] += result["elapsed_seconds"]
            candidates.append((result["plate"], self.clock.tick_of(row["captured_at"])))

        hint = crime.plate[:hint_len]  # what a witness remembers
        suspects = [(plate, tick) for plate, tick in candidates if plate.startswith(hint)]
        decrypt.update(candidates=len(candidates), hint=hint, suspects=len(suspects))
        steps, paths = [decrypt], []
        for plate, tick in suspects[:max_suspects]:
            trace_steps, path, stop = self._trace(plate, crime.node, tick, max_hops, plate)
            steps += trace_steps
            paths.append({"plate": plate, "is_criminal": plate == crime.plate, "nodes": path, "stopped_by": stop})
        result = self._result("aberta", steps, paths, realistic_n)
        result["extra"] = {
            "hint": hint, "candidates": len(candidates), "suspects": len(suspects),
            "suspects_traced": min(len(suspects), max_suspects),
        }
        return result

    def bolo(self, delay_ticks: int = 2, ttl_ticks: int = 120) -> dict:
        crime = self.world.crime
        bolo_tick = crime.tick + delay_ticks
        now = [self.clock.epoch(bolo_tick)]
        police = Police()
        cameras: dict[int, Camera] = {}

        def camera_for(node: int) -> Camera:
            if node not in cameras:
                cameras[node] = Camera(
                    id=node, location_id=node, puzzle_level=self.world.params["puzzle_level"],
                    blocklist=Blocklist(clock=lambda: now[0]), police=police,
                )
            return cameras[node]

        for node in self.graph.nodes:
            camera_for(node)
        with contextlib.redirect_stdout(io.StringIO()):  # Police.receive_alert prints each alert
            police.issue_bolo(crime.plate, reason="crime", ttl_seconds=ttl_ticks * self.clock.tick_seconds)
            captures = sorted(
                (tick, vehicle.id, node, vehicle.plate)
                for vehicle in self.world.vehicles for tick, node in vehicle.arrivals if tick > bolo_tick
            )
            for tick, _, node, plate in captures:
                now[0] = self.clock.epoch(tick)
                camera_for(node).capture_plate(plate, timestamp=self.clock.iso(tick))

        steps = []
        path = []  # only what the cameras reported: sightings before the broadcast are never alerted
        for alert in police.alerts_received:
            tick = self.clock.tick_of(alert.timestamp)
            steps.append({
                "kind": "alert", "node": alert.camera_id, "tick": tick, "found": True,
                "records_tested": 0, "attempts": 0, "real_seconds": 0.0,
            })
            path.append((alert.camera_id, tick))
        paths = [{"plate": crime.plate, "is_criminal": True, "nodes": path}]
        expected = [(node, tick) for node, tick in self._true_escape() if tick > bolo_tick]
        result = self._result("bolo", steps, paths, DEFAULT_REALISTIC_N, expected=expected)
        missed = [t for t, n in self.world.vehicle(crime.vehicle_id).arrivals if crime.tick < t <= bolo_tick]
        result["extra"] = {"bolo_tick": bolo_tick, "ttl_ticks": ttl_ticks, "missed_sightings": len(missed)}
        return result

    # -- result ---------------------------------------------------------

    def _result(self, mode: str, steps: list[dict], paths: list[dict], realistic_n: int,
                expected: Optional[list[tuple[int, int]]] = None) -> dict:
        totals = {
            "probes": sum(1 for s in steps if s["kind"] in ("probe", "decrypt_window")),
            "records_tested": sum(s["records_tested"] for s in steps),
            "attempts": sum(s["attempts"] for s in steps),
            "real_seconds": sum(s["real_seconds"] for s in steps),
        }
        estimate = costs.estimate(
            totals["records_tested"], totals["attempts"], totals["real_seconds"], realistic_n
        )
        truth = expected if expected is not None else self._true_escape()
        criminal_path = next((p["nodes"] for p in paths if p["is_criminal"]), [])
        # A plate match is exact, so every traced point is a real sighting; what can differ from the
        # real route is a camera the (wide) time window skipped. Count both.
        real_sightings = set(truth)
        matching = sum(1 for point in criminal_path if tuple(point) in real_sightings)
        skipped = 0
        if criminal_path:
            first_tick, last_tick = criminal_path[0][1], criminal_path[-1][1]
            skipped = max(0, sum(1 for _, tick in truth if first_tick <= tick <= last_tick) - matching)
        return {
            "mode": mode,
            "steps": steps,
            "paths": paths,
            "totals": totals,
            "estimate": estimate,
            "truth": {
                "escape": truth,
                "traced_nodes": len(criminal_path),
                "matching_nodes": matching,
                "skipped_sightings": skipped,
                "followed_criminal": bool(criminal_path) and matching == len(criminal_path),
            },
        }

    def _true_escape(self) -> list[tuple[int, int]]:
        crime = self.world.crime
        arrivals = self.world.vehicle(crime.vehicle_id).arrivals
        start = next(i for i, (tick, node) in enumerate(arrivals) if tick == crime.tick and node == crime.node)
        return [(node, tick) for tick, node in arrivals[start:]]  # same (node, tick) order as the traced paths
