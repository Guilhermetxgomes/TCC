import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

DEFAULT_PATH = Path(__file__).resolve().parent / "data" / "city.json"


@dataclass(frozen=True)
class Node:
    id: int
    lat: float
    lon: float
    name: str


@dataclass(frozen=True)
class Edge:
    source: int
    target: int
    length: float  # meters
    p: float  # base probability of choosing this edge from `source`
    highway: str
    name: str


class CityGraph:
    """
    Directed road graph: each vertex is an intersection with a camera, each edge a road
    segment annotated with the probability that a car at `source` takes it next
    (generated once by scripts/download_city.py from OpenStreetMap).
    """

    def __init__(self, nodes: list[Node], edges: list[Edge]):
        self.nodes: dict[int, Node] = {node.id: node for node in nodes}
        self.edges: dict[tuple[int, int], Edge] = {(e.source, e.target): e for e in edges}
        self._successors: dict[int, list[int]] = {node.id: [] for node in nodes}
        for edge in edges:
            self._successors[edge.source].append(edge.target)

    @classmethod
    def load(cls, path: Path = DEFAULT_PATH) -> "CityGraph":
        data = json.loads(Path(path).read_text())
        return cls(
            [Node(**node) for node in data["nodes"]],
            [Edge(**edge) for edge in data["edges"]],
        )

    def successors(self, node_id: int) -> list[int]:
        return self._successors[node_id]

    def next_probs(self, node_id: int, previous: Optional[int] = None) -> dict[int, float]:
        """
        Probability of each next vertex given where the car is and where it came from.
        An immediate U-turn is excluded when there is any other way out; the remaining
        probabilities are renormalised. Cars (engine) and investigators (who know the
        model) both use this, so it is the single source of truth for transitions.
        """
        candidates = self._successors[node_id]
        if previous is not None and len(candidates) > 1:
            candidates = [v for v in candidates if v != previous]
        total = sum(self.edges[(node_id, v)].p for v in candidates)
        return {v: self.edges[(node_id, v)].p / total for v in candidates}

    def travel_ticks(self, source: int, target: int, tick_seconds: float, speed_mps: float) -> int:
        """Nominal ticks to drive one edge (at least 1)."""
        return max(1, round(self.edges[(source, target)].length / (speed_mps * tick_seconds)))

    def to_json(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "lat": n.lat, "lon": n.lon, "name": n.name} for n in self.nodes.values()
            ],
            "edges": [
                {"source": e.source, "target": e.target, "p": e.p, "length": e.length, "name": e.name}
                for e in self.edges.values()
            ],
        }

    def is_valid(self) -> bool:
        """Every vertex has a way out (required by the traffic engine)."""
        return all(self._successors[node_id] for node_id in self.nodes) and not any(
            math.isnan(e.p) for e in self.edges.values()
        )
