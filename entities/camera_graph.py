import math
from dataclasses import dataclass

from entities.camera_id import CameraId


@dataclass
class CameraNode:
    camera_id: CameraId
    x: float  # synthetic position in km, only used to compute distance between cameras
    y: float


class CameraGraph:
    """
    Neighborhood graph between cameras. Used by the retroactive (BOLO-for-the-
    past) tracker to know which neighboring cameras are worth checking when
    trying to reconstruct a plate's past trajectory.
    """

    def __init__(self):
        self._nodes: dict[CameraId, CameraNode] = {}
        self._edges: dict[CameraId, set[CameraId]] = {}

    def add_camera(self, camera_id: CameraId, x: float, y: float):
        self._nodes[camera_id] = CameraNode(camera_id, x, y)
        self._edges.setdefault(camera_id, set())

    def add_edge(self, camera_a: CameraId, camera_b: CameraId):
        """Neighborhood is bidirectional: if you can go from A to B, you can go from B to A."""
        self._edges[camera_a].add(camera_b)
        self._edges[camera_b].add(camera_a)

    def neighbors(self, camera_id: CameraId) -> set[CameraId]:
        return self._edges.get(camera_id, set())

    def distance_km(self, camera_a: CameraId, camera_b: CameraId) -> float:
        a, b = self._nodes[camera_a], self._nodes[camera_b]
        return math.dist((a.x, a.y), (b.x, b.y))

    def camera_ids(self) -> list[CameraId]:
        return list(self._nodes.keys())
