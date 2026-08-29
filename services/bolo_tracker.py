import math

from crypto.puzzle import solve_puzzle
from entities.camera_graph import CameraGraph
from services.camera_network import CameraNetwork


class TransitionModel:
    """
    Estimates P(destination_camera | origin_camera) for a 1-time-bin hop,
    from the distance between cameras and an assumed average speed. This is
    just a movement prior -- it doesn't depend on anything encrypted.
    """

    def __init__(self, graph: CameraGraph, bin_minutes: float, avg_speed_kmh: float,
                 sigma_bins: float = 1.0, stay_weight: float = 0.15):
        self.graph = graph
        self.km_per_bin = avg_speed_kmh * (bin_minutes / 60)
        self.sigma_bins = sigma_bins
        self.stay_weight = stay_weight

    def _gaussian(self, expected_bins: float, observed_bins: float = 1.0) -> float:
        diff = expected_bins - observed_bins
        return math.exp(-(diff ** 2) / (2 * self.sigma_bins ** 2))

    def transition_probs(self, from_camera: int) -> dict[int, float]:
        """Normalized distribution over {stay put} U {neighbors} for 1 time bin."""
        weights = {from_camera: self.stay_weight}
        for neighbor in self.graph.neighbors(from_camera):
            distance = self.graph.distance_km(from_camera, neighbor)
            expected_bins = distance / self.km_per_bin if self.km_per_bin > 0 else math.inf
            weights[neighbor] = self._gaussian(expected_bins)

        total = sum(weights.values()) or 1.0
        return {camera: weight / total for camera, weight in weights.items()}


def _emission_prob(bloom_hit: bool, plate_prior: float, false_positive_rate: float) -> float:
    """
    P(plate actually present | Bloom filter result), via Bayes. No false
    negatives: a "miss" implies certain absence (prob. 0). A "hit" can be a
    true positive or a filter false positive -- but since this works out to
    the same value for any camera with a hit, in practice it only filters
    candidates (hit vs. miss); the TransitionModel is what breaks ties among
    hits.
    """
    if not bloom_hit:
        return 0.0
    denominator = plate_prior + (1 - plate_prior) * false_positive_rate
    return plate_prior / denominator if denominator > 0 else 0.0


class BoloTracker:
    """
    Reconstructs the most likely path of cameras a BOLO plate traveled
    before a confirmed sighting (the anchor), combining the cheap Bloom
    filter signal with a movement prior -- without decrypting anything yet.

    The result is just a prioritized list of (camera, bin) cells to actually
    try the puzzle on: the cost of solving each puzzle is still paid in
    full, this only reduces HOW MANY puzzles need to be attempted.
    """

    def __init__(self, network: CameraNetwork, transition_model: TransitionModel,
                 plate_prior: float = 1e-4, false_positive_rate: float = 0.01):
        self.network = network
        self.transition_model = transition_model
        self.plate_prior = plate_prior
        self.false_positive_rate = false_positive_rate

    def most_likely_past_path(self, plate: str, anchor_camera: int, anchor_bin: int, bins_back: int):
        """
        Runs Viterbi walking backward in time from the anchor (the time bin
        where the plate was already confirmed). Returns the most likely path
        as a list of (time_bin, camera_id, log_prob), from oldest to most
        recent (the anchor is always the last element).
        """
        cameras = self.network.graph.camera_ids()
        time_bins = [anchor_bin - step for step in range(bins_back + 1)]

        # trellis[i] = {camera_id: (log_prob, backpointer_camera_or_None)}
        trellis = [{anchor_camera: (0.0, None)}]

        for time_bin in time_bins[1:]:
            prev_layer = trellis[-1]
            layer = {}

            for camera in cameras:
                hit = self.network.might_have_seen(camera, time_bin, plate)
                emission = _emission_prob(hit, self.plate_prior, self.false_positive_rate)
                if emission <= 0:
                    continue

                best_prev, best_score = None, -math.inf
                for prev_camera, (prev_score, _) in prev_layer.items():
                    trans = self.transition_model.transition_probs(prev_camera).get(camera, 0.0)
                    if trans <= 0:
                        continue
                    score = prev_score + math.log(trans)
                    if score > best_score:
                        best_prev, best_score = prev_camera, score

                if best_prev is not None:
                    layer[camera] = (best_score + math.log(emission), best_prev)

            if not layer:
                break  # no camera had a compatible Bloom hit in this window -- the trail stops here
            trellis.append(layer)

        reached_bins = time_bins[:len(trellis)]
        last_layer = trellis[-1]
        best_camera = max(last_layer, key=lambda c: last_layer[c][0])

        path = []
        camera = best_camera
        for layer, time_bin in zip(reversed(trellis), reversed(reached_bins)):
            score, backpointer = layer[camera]
            path.append((time_bin, camera, score))
            camera = backpointer

        path.reverse()
        return path

    def confirm_candidates(self, path, target_plate: str) -> dict:
        """
        This is where the real cryptographic cost is paid: runs solve_puzzle
        on the records of the cells flagged by Viterbi. The attempt count
        here is what actually matters for the surveillance cost.
        """
        total_attempts = 0
        confirmed_cells = []

        for time_bin, camera_id, _ in path:
            for sighting in self.network.sightings_at(camera_id, time_bin):
                result = solve_puzzle(sighting.record)
                total_attempts += result["attempts"]
                if result["success"] and result["plate"] == target_plate:
                    confirmed_cells.append((time_bin, camera_id))

        return {"confirmed_cells": confirmed_cells, "total_puzzle_attempts": total_attempts}
