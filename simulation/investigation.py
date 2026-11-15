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
- busca_total: exceptional access. A quorum of the Emergency Committee threshold-decrypts
  the session keys the cameras escrowed, and every record of the session is opened
  without any puzzle -- the criminal's whole route, and everybody else's.

Every record is checked against its camera's signature (World.camera_keys) before any
puzzle is attempted; a record that fails -- moved to another camera or instant, or
re-encrypted with another plate by someone who solved its puzzle -- is rejected and
reported in the step (`rejected`), never followed.

With block crumpling (World.params["block_level"]) busca_fechada and busca_aberta first
solve the puzzle of each block they touch (once per camera and time slot) and then the
records inside it.

Every function returns the list of `steps` that the web UI animates, the traced paths and
the cost (measured with the real, small puzzle_level + extrapolated to a realistic one).
"""
import contextlib
import io
import time
from typing import TYPE_CHECKING, Optional

from crypto.block_crumpling import solve_block
from crypto.escrow import open_with_session_key, time_slot
from crypto.puzzle import solve_puzzle
from crypto.signing import verify_record
from entities.blocklist import Blocklist
from services.camera import Camera
from services.committee import Scope
from services.police import Police
from simulation import costs
from simulation.city_graph import CityGraph
from simulation.engine import World, travel_window

DEFAULT_WINDOW_TICKS = 6  # +-1 min around the crime
DEFAULT_MAX_HOPS = 6
DEFAULT_MAX_SUSPECTS = 30
DEFAULT_REALISTIC_N = 10_000_000
DEFAULT_REALISTIC_T = 10_000_000_000  # block puzzle: ~1000 records/slot x DEFAULT_REALISTIC_N

if TYPE_CHECKING:  # only a type hint: lets the simulation run on simulation.memory_server too
    from services.server import Server


class Investigator:
    def __init__(self, graph: CityGraph, server: "Server", world: World):
        self.graph = graph
        self.server = server
        self.world = world
        self.clock = world.clock
        self.run_id = world.run_id
        self._block_keys: dict[tuple[int, str], bytes] = {}  # blocks this investigator already paid for

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
            "blocks_solved": 0, "block_attempts": 0, "rejected": 0, "rejected_ids": [],
            "real_seconds": 0.0, "found": False, "tick": None, "record_id": None,
        }
        for row in rows:
            result = self._solve(row, step)
            if result is not None and result["plate"] == plate:
                step.update(found=True, tick=self.clock.tick_of(row["captured_at"]), record_id=row["record_id"])
                break
        return step

    def _authentic(self, row: dict, step: dict) -> bool:
        """Checks the camera's signature; a record that fails is counted in `step` and skipped."""
        started = time.perf_counter()
        ok = verify_record(row["record"], self.world.camera_keys.get(row["record"].camera_id))
        step["real_seconds"] += time.perf_counter() - started
        if not ok:
            step["rejected"] = step.get("rejected", 0) + 1
            step.setdefault("rejected_ids", []).append(row["record_id"])
        return ok

    def _solve(self, row: dict, step: dict) -> Optional[dict]:
        """
        Opens one record by brute force and adds its cost to `step`; returns None (and counts
        the record as rejected) when its signature does not check. A record inside a
        crumpled block needs the block key first: the block puzzle is solved once per
        (camera, block) and reused by every later record of that block in this investigation.
        """
        if not self._authentic(row, step):
            return None
        record = row["record"]
        prefix = b""
        if record.block is not None:
            cache_key = (record.camera_id, record.block)
            if cache_key not in self._block_keys:
                solved = solve_block(self.server.get_block_header(self.run_id, record.camera_id, record.block))
                self._block_keys[cache_key] = solved["key"]
                step["blocks_solved"] += 1
                step["block_attempts"] += solved["attempts"]
                step["attempts"] += solved["attempts"]
                step["real_seconds"] += solved["elapsed_seconds"]
            prefix = self._block_keys[cache_key]
        result = solve_puzzle(record, key_prefix=prefix)
        step["records_tested"] += 1
        step["attempts"] += result["attempts"]
        step["real_seconds"] += result["elapsed_seconds"]
        return result

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
                      realistic_n: int = DEFAULT_REALISTIC_N, realistic_t: int = DEFAULT_REALISTIC_T) -> dict:
        crime = self.world.crime
        first = self._probe(crime.node, crime.tick - window_ticks, crime.tick + window_ticks, crime.plate)
        first.update(from_node=None, p=None, suspect=crime.plate)
        steps, paths = [first], []
        if first["found"]:
            trace_steps, path, stop = self._trace(crime.plate, crime.node, first["tick"], max_hops, crime.plate)
            steps += trace_steps
            paths.append({"plate": crime.plate, "is_criminal": True, "nodes": path, "stopped_by": stop})
        return self._result("fechada", steps, paths, realistic_n, realistic_t=realistic_t)

    def busca_aberta(self, hint_len: int = 3, window_ticks: int = DEFAULT_WINDOW_TICKS,
                     max_hops: Optional[int] = DEFAULT_MAX_HOPS, max_suspects: int = DEFAULT_MAX_SUSPECTS,
                     realistic_n: int = DEFAULT_REALISTIC_N, realistic_t: int = DEFAULT_REALISTIC_T) -> dict:
        crime = self.world.crime
        rows = self._window(crime.node, crime.tick - window_ticks, crime.tick + window_ticks)
        decrypt = {
            "kind": "decrypt_window", "node": crime.node, "from_tick": crime.tick - window_ticks,
            "to_tick": crime.tick + window_ticks, "records_in_window": len(rows),
            "records_tested": 0, "attempts": 0, "blocks_solved": 0, "block_attempts": 0,
            "rejected": 0, "rejected_ids": [], "real_seconds": 0.0, "found": False,
        }
        candidates = []  # (plate, tick) decrypted from the window
        for row in rows:
            result = self._solve(row, decrypt)
            if result is None:
                continue
            candidates.append((result["plate"], self.clock.tick_of(row["captured_at"])))

        hint = crime.plate[:hint_len]  # what a witness remembers
        suspects = [(plate, tick) for plate, tick in candidates if plate.startswith(hint)]
        decrypt.update(candidates=len(candidates), hint=hint, suspects=len(suspects))
        steps, paths = [decrypt], []
        for plate, tick in suspects[:max_suspects]:
            trace_steps, path, stop = self._trace(plate, crime.node, tick, max_hops, plate)
            steps += trace_steps
            paths.append({"plate": plate, "is_criminal": plate == crime.plate, "nodes": path, "stopped_by": stop})
        result = self._result("aberta", steps, paths, realistic_n, realistic_t=realistic_t)
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

    def busca_total(self, member_indexes: Optional[list[int]] = None,
                    camera_ids: Optional[list[int]] = None) -> dict:
        """
        Exceptional access: the committee members in `member_indexes` (default: the first
        t) threshold-decrypt the escrowed session keys of the crime's session -- for every
        camera, or only for `camera_ids` -- and each record of those cameras in that
        session is opened with one HMAC instead of a puzzle. Raises
        services.committee.QuorumError when fewer than t members take part.

        The cost is not computational but institutional (a quorum has to agree), and the
        exposure is total: `extra` reports how many plates other than the criminal's
        were revealed.
        """
        committee = self.world.committee
        if committee is None:
            raise ValueError("this simulation was generated without escrow; busca_total is not available")
        crime = self.world.crime
        crime_time = self.clock.iso(crime.tick)
        period = time_slot(crime_time, "month")
        session = time_slot(crime_time, self.world.params["session_granularity"])
        if member_indexes is None:
            member_indexes = list(range(1, committee.threshold + 1))
        scope = Scope(
            period=period, sessions=frozenset({session}),
            camera_ids=frozenset(camera_ids) if camera_ids is not None else None,
            reason=f"crime at camera {crime.node}, {crime_time}",
        )

        started = time.perf_counter()
        session_keys = committee.open_session_keys(
            scope, self.server.get_session_wraps(self.run_id, period, session), member_indexes
        )
        committee_seconds = time.perf_counter() - started
        activation = committee.activations[-1]
        steps = [{
            "kind": "quorum", "node": crime.node, "tick": None, "found": False, "records_tested": 0,
            "attempts": 0, "real_seconds": committee_seconds, "members": activation["members"],
            "wraps_opened": activation["wraps_opened"],
        }]

        plates: set[str] = set()
        sightings = []  # (tick, node) of the criminal's plate, from every opened camera
        for (camera_id, _), session_key in sorted(session_keys.items()):
            rows = self.server.get_rows_in_session(self.run_id, camera_id, session)
            step = {
                "kind": "open_session", "node": camera_id, "tick": None, "found": False, "record_id": None,
                "records_in_window": len(rows), "records_tested": 0, "attempts": 0, "real_seconds": 0.0,
                "rejected": 0, "rejected_ids": [],
            }
            started = time.perf_counter()
            headers, hit_record = {}, None
            for row in rows:
                if not self._authentic(row, step):
                    continue
                record = row["record"]
                header = None
                if record.block is not None:
                    if record.block not in headers:
                        headers[record.block] = self.server.get_block_header(self.run_id, camera_id, record.block)
                    header = headers[record.block]
                plate = open_with_session_key(record, session_key, header)
                plates.add(plate)
                if plate == crime.plate:
                    sightings.append((self.clock.tick_of(row["captured_at"]), camera_id))
                    hit_record = hit_record or row["record_id"]
            step.update(found=hit_record is not None, record_id=hit_record,
                        records_tested=len(rows) - step["rejected"], real_seconds=time.perf_counter() - started)
            steps.append(step)

        sightings.sort()
        path = [(node, tick) for tick, node in sightings if tick >= crime.tick]
        paths = [{"plate": crime.plate, "is_criminal": True, "nodes": path, "stopped_by": None}]
        expected = None
        if camera_ids is not None:  # only the opened cameras can be expected to report
            expected = [(node, tick) for node, tick in self._true_escape() if node in scope.camera_ids]
        result = self._result("total", steps, paths, DEFAULT_REALISTIC_N, expected=expected)
        result["estimate"] = costs.estimate(0, 0, 0.0, DEFAULT_REALISTIC_N)  # no puzzle is solved on this path
        result["extra"] = {
            "period": period, "session": session,
            "threshold": committee.threshold, "committee_members": len(committee.members),
            "members": activation["members"], "wraps_opened": activation["wraps_opened"],
            "partial_decryptions": activation["partial_decryptions"], "committee_seconds": committee_seconds,
            "plates_exposed": len(plates), "other_plates_exposed": len(plates - {crime.plate}),
            "sightings_before_crime": sum(1 for tick, _ in sightings if tick < crime.tick),
        }
        return result

    # -- result ---------------------------------------------------------

    def _result(self, mode: str, steps: list[dict], paths: list[dict], realistic_n: int,
                expected: Optional[list[tuple[int, int]]] = None, realistic_t: int = DEFAULT_REALISTIC_T) -> dict:
        totals = {
            "probes": sum(1 for s in steps if s["kind"] in ("probe", "decrypt_window", "open_session")),
            "records_tested": sum(s["records_tested"] for s in steps),
            "attempts": sum(s["attempts"] for s in steps),
            "blocks_solved": sum(s.get("blocks_solved", 0) for s in steps),
            "block_attempts": sum(s.get("block_attempts", 0) for s in steps),
            "rejected": sum(s.get("rejected", 0) for s in steps),
            "real_seconds": sum(s["real_seconds"] for s in steps),
        }
        block_mode = self.world.params.get("block_level") is not None
        if block_mode and self.world.params["puzzle_level"] == 1:
            realistic_n = 1  # pure block crumpling: the records carry no puzzle of their own
        estimate = costs.estimate(
            totals["records_tested"], totals["attempts"], totals["real_seconds"], realistic_n,
            totals["blocks_solved"], realistic_t if block_mode else 0,
            total_records=0 if block_mode else self.world.params["records"],
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
