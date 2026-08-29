from crypto.bloom_filter import BloomFilter
from entities.camera_graph import CameraGraph
from entities.camera_id import CameraId
from entities.sighting import Sighting
from services.camera import Camera


class CameraNetwork:
    """
    Simulates a network of cameras connected by a neighborhood graph. Each
    (camera, time bin) has its own Bloom filter with the plates seen in that
    window -- the cheap check used to decide where it's worth spending the
    real cryptographic puzzle (see services/bolo_tracker.py).
    """

    def __init__(self, graph: CameraGraph, puzzle_level: int = 1000, expected_items_per_bin: int = 50):
        self.graph = graph
        self.cameras = {cid: Camera(id=cid, location_id=cid, puzzle_level=puzzle_level) for cid in graph.camera_ids()}
        self._bloom_filters: dict[tuple[CameraId, int], BloomFilter] = {}
        self._sightings: dict[tuple[CameraId, int], list[Sighting]] = {}
        self._expected_items_per_bin = expected_items_per_bin

    def _bloom_for(self, camera_id: CameraId, time_bin: int) -> BloomFilter:
        key = (camera_id, time_bin)
        if key not in self._bloom_filters:
            self._bloom_filters[key] = BloomFilter(self._expected_items_per_bin)
        return self._bloom_filters[key]

    def register_sighting(self, camera_id: CameraId, time_bin: int, plate: str):
        camera = self.cameras[camera_id]
        record = camera.encrypt_plate(plate)
        self._sightings.setdefault((camera_id, time_bin), []).append(Sighting(time_bin, record))
        self._bloom_for(camera_id, time_bin).add(plate)

    def might_have_seen(self, camera_id: CameraId, time_bin: int, plate: str) -> bool:
        """Cheap lookup (no decryption involved): just checks the Bloom filter."""
        key = (camera_id, time_bin)
        if key not in self._bloom_filters:
            return False
        return self._bloom_filters[key].might_contain(plate)

    def sightings_at(self, camera_id: CameraId, time_bin: int) -> list[Sighting]:
        return self._sightings.get((camera_id, time_bin), [])

    def all_cells(self):
        return list(self._sightings.keys())
