import math
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from crypto.escrow import CameraEscrow
from services.camera import Camera
from services.committee import EmergencyCommittee
from simulation.city_graph import CityGraph

if TYPE_CHECKING:  # only a type hint: lets the simulation run on simulation.memory_server too
    from services.server import Server

TICK_SECONDS = 10
SPEED_MPS = 30 / 3.6  # nominal 30 km/h inside the campus
SIM_START = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
MIN_STEPS_AFTER_CRIME = 6  # the escape must be long enough to be worth tracing


class SimClock:
    """Simulated time: tick -> ISO timestamp (fixed width, so it sorts as TEXT in Postgres)."""

    def __init__(self, start: datetime = SIM_START, tick_seconds: int = TICK_SECONDS):
        self.start = start
        self.tick_seconds = tick_seconds

    def iso(self, tick: int) -> str:
        return (self.start + timedelta(seconds=tick * self.tick_seconds)).isoformat()

    def tick_of(self, iso: str) -> int:
        delta = datetime.fromisoformat(iso) - self.start
        return round(delta.total_seconds() / self.tick_seconds)

    def epoch(self, tick: int) -> float:
        return self.start.timestamp() + tick * self.tick_seconds


@dataclass
class Vehicle:
    id: int
    plate: str
    arrivals: list[tuple[int, int]] = field(default_factory=list)  # (tick, node): each one is a camera capture


@dataclass
class Crime:
    tick: int
    node: int
    vehicle_id: int
    plate: str


@dataclass
class World:
    run_id: str
    params: dict
    vehicles: list[Vehicle]
    crime: Crime
    clock: SimClock
    # Emergency Committee holding the escrow keys of this run (None: generated without escrow).
    committee: Optional[EmergencyCommittee] = None
    # Public signing key of each camera, registered at installation. This is the trust anchor
    # for the records' signatures, so it lives here and NOT in the Servidor's database, which
    # the tampering demo lets a dishonest operator rewrite.
    camera_keys: dict[int, bytes] = field(default_factory=dict)

    def vehicle(self, vehicle_id: int) -> Vehicle:
        return self.vehicles[vehicle_id]

    def to_json(self) -> dict:
        # Plates are deliberately absent: only the cameras' ciphertexts "know" them.
        return {
            "run_id": self.run_id,
            "params": self.params,
            "tick_seconds": self.clock.tick_seconds,
            "vehicles": [{"id": v.id, "events": [list(a) for a in v.arrivals]} for v in self.vehicles],
            "crime": {"tick": self.crime.tick, "node": self.crime.node, "vehicle_id": self.crime.vehicle_id},
        }


def travel_window(graph: CityGraph, source: int, target: int) -> tuple[int, int]:
    """
    Ticks (relative to the departure) within which a car leaving `source` can reach
    `target`. Cars drive with a +-25% speed jitter, so investigators look in a window
    instead of at one exact tick.
    """
    base = graph.travel_ticks(source, target, TICK_SECONDS, SPEED_MPS)
    return max(1, math.floor(base * 0.7)), math.ceil(base * 1.4) + 1


def generate_plate(rng: random.Random) -> str:
    letters = "".join(rng.choices(string.ascii_uppercase, k=3))
    digits = "".join(rng.choices(string.digits, k=4))
    return f"{letters}{digits}"


def simulate_traffic(graph: CityGraph, n_vehicles: int, ticks: int, rng: random.Random) -> list[Vehicle]:
    """Random walks on the graph: at each vertex a car picks the next one with graph.next_probs."""
    node_ids = list(graph.nodes)
    plates: set[str] = set()
    vehicles = []
    for vehicle_id in range(n_vehicles):
        plate = generate_plate(rng)
        while plate in plates:
            plate = generate_plate(rng)
        plates.add(plate)

        vehicle = Vehicle(id=vehicle_id, plate=plate)
        tick = rng.randrange(0, 10)  # staggered departures
        node = rng.choice(node_ids)
        previous = None
        while tick < ticks:
            vehicle.arrivals.append((tick, node))
            probs = graph.next_probs(node, previous)
            nxt = rng.choices(list(probs), weights=list(probs.values()))[0]
            base = graph.travel_ticks(node, nxt, TICK_SECONDS, SPEED_MPS)
            tick += max(1, round(base * rng.uniform(0.8, 1.25)))
            previous, node = node, nxt
        vehicles.append(vehicle)
    return vehicles


def pick_crime(vehicles: list[Vehicle], crime_tick: int, rng: random.Random) -> Crime:
    """The criminal commits the crime at the first camera it passes at or after `crime_tick`."""
    candidates = vehicles[:]
    rng.shuffle(candidates)
    for vehicle in candidates:
        for index, (tick, node) in enumerate(vehicle.arrivals):
            if tick >= crime_tick:
                if len(vehicle.arrivals) - 1 - index >= MIN_STEPS_AFTER_CRIME:
                    return Crime(tick=tick, node=node, vehicle_id=vehicle.id, plate=vehicle.plate)
                break
    raise ValueError("no vehicle has enough captures after crime_tick; lower crime_tick or increase ticks")


def populate_database(world_vehicles: list[Vehicle], server: "Server", run_id: str, puzzle_level: int,
                      clock: SimClock, block_level: Optional[int] = None, block_granularity: str = "10min",
                      committee: Optional[EmergencyCommittee] = None, session_granularity: str = "day",
                      key_registry: Optional[dict[int, bytes]] = None) -> int:
    """
    Every arrival is captured by that vertex's camera and stored encrypted (and signed), in
    capture order. The cameras' public keys are written to `key_registry`.
    With block_level the cameras use block crumpling (one puzzle of that size per camera
    per block_granularity slot); with a committee they escrow their session keys to it.
    """
    cameras: dict[int, Camera] = {}

    def camera_for(node: int) -> Camera:
        if node not in cameras:
            escrow = None
            if committee is not None:
                escrow = CameraEscrow(node, committee.public_key, session_granularity)
            cameras[node] = Camera(
                id=node, location_id=node, puzzle_level=puzzle_level, block_level=block_level,
                block_granularity=block_granularity, escrow=escrow,
            )
            if key_registry is not None:
                key_registry[node] = cameras[node].public_key
        return cameras[node]

    captures = sorted(
        ((tick, vehicle.id, node, vehicle.plate) for vehicle in world_vehicles for tick, node in vehicle.arrivals)
    )
    # The simulated clock plays the camera's own clock: captured_at goes into the AD and the signature.
    entries = [camera_for(node).encrypt_plate(plate, clock.iso(tick)) for tick, _, node, plate in captures]
    server.save_many(entries, run_id=run_id)
    for camera in cameras.values():
        server.save_block_headers(camera.drain_block_headers(), run_id=run_id)
        server.save_session_wraps(camera.drain_session_wraps(), run_id=run_id)
    return len(entries)


def run_simulation(graph: CityGraph, server: "Server", run_id: str, n_vehicles: int = 120, ticks: int = 240,
                   puzzle_level: int = 1000, crime_tick: int = 60, seed: int = 1,
                   block_level: Optional[int] = None, block_granularity: str = "10min", escrow: bool = True,
                   committee_threshold: int = 4, committee_members: int = 8,
                   session_granularity: str = "day") -> World:
    rng = random.Random(seed)
    clock = SimClock()
    vehicles = simulate_traffic(graph, n_vehicles, ticks, rng)
    crime = pick_crime(vehicles, crime_tick, rng)
    committee = EmergencyCommittee(committee_threshold, committee_members) if escrow else None
    camera_keys: dict[int, bytes] = {}
    records = populate_database(vehicles, server, run_id, puzzle_level, clock, block_level, block_granularity,
                                committee, session_granularity, camera_keys)
    params = {
        "seed": seed, "n_vehicles": n_vehicles, "ticks": ticks,
        "puzzle_level": puzzle_level, "crime_tick": crime_tick, "records": records,
        "block_level": block_level, "block_granularity": block_granularity if block_level else None,
        "escrow": escrow, "session_granularity": session_granularity,
        "committee_threshold": committee_threshold, "committee_members": committee_members,
    }
    return World(run_id=run_id, params=params, vehicles=vehicles, crime=crime, clock=clock, committee=committee,
                 camera_keys=camera_keys)
