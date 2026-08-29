import random

from entities.camera_graph import CameraGraph
from services.bolo_tracker import BoloTracker, TransitionModel
from services.camera_network import CameraNetwork


def build_example_graph() -> CameraGraph:
    """
    A linear string of cameras (like an avenue) with one detour, just to
    demonstrate the retroactive tracker. Coordinates in km, arbitrary.
    """
    graph = CameraGraph()
    positions = {
        1: (0, 0),
        2: (2, 0),
        3: (4, 0),
        4: (6, 0),
        5: (4, 2),  # camera on a parallel street / detour
        6: (8, 0),
    }
    for camera_id, (x, y) in positions.items():
        graph.add_camera(camera_id, x, y)

    for a, b in [(1, 2), (2, 3), (3, 4), (4, 6), (3, 5), (5, 4)]:
        graph.add_edge(a, b)
    return graph


def run_bolo_scenario():
    graph = build_example_graph()
    network = CameraNetwork(graph, puzzle_level=5_000)

    target_plate = "BOL0001"

    # the vehicle's real trajectory: camera 1 at bin 0 -> camera 6 at bin 4
    real_trajectory = [(1, 0), (2, 1), (3, 2), (4, 3), (6, 4)]
    for camera_id, time_bin in real_trajectory:
        network.register_sighting(camera_id, time_bin, target_plate)

    # noise: other plates circulating through the whole network at every
    # camera/bin, including the detour camera (5), so the scenario isn't trivial
    other_plates = [f"CAR{n:04d}" for n in range(40)]
    for time_bin in range(5):
        for camera_id in graph.camera_ids():
            for _ in range(random.randint(3, 8)):
                network.register_sighting(camera_id, time_bin, random.choice(other_plates))

    transition_model = TransitionModel(graph, bin_minutes=5, avg_speed_kmh=40)
    tracker = BoloTracker(network, transition_model)

    # anchor: the plate was confirmed at camera 6, bin 4 (e.g. it hit a BOLO by another means)
    path = tracker.most_likely_past_path(target_plate, anchor_camera=6, anchor_bin=4, bins_back=4)

    print("Most likely reconstructed path (bin, camera, log-prob):")
    for time_bin, camera_id, score in path:
        print(f"  bin={time_bin} camera={camera_id} log_prob={score:.3f}")

    result = tracker.confirm_candidates(path, target_plate)
    print(f"\nConfirmed cells: {result['confirmed_cells']}")
    print(f"Puzzle attempts spent (via Viterbi): {result['total_puzzle_attempts']}")

    total_cells = len(network.all_cells())
    print(f"\nTotal (camera, bin) cells in the network: {total_cells}")
    print(f"Cells actually attacked with the puzzle: {len(path)}")


if __name__ == "__main__":
    run_bolo_scenario()
