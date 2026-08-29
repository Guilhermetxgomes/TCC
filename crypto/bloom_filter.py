import hashlib
import math


class BloomFilter:
    """
    Simple Bloom filter: tests whether a plate "might be" in a set (camera +
    time bin) without storing plates in the clear and without false
    negatives -- only false positives, at a configurable rate. This is the
    cheap, "leaky" signal mentioned in the original BOLO comment in
    services/camera.py.
    """

    def __init__(self, expected_items: int, false_positive_rate: float = 0.01):
        self.size = self._optimal_size(expected_items, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_items)
        self.false_positive_rate = false_positive_rate
        self._bits = bytearray((self.size + 7) // 8)

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        n = max(n, 1)
        return max(8, math.ceil(-(n * math.log(p)) / (math.log(2) ** 2)))

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        n = max(n, 1)
        return max(1, round((m / n) * math.log(2)))

    def _positions(self, item: str):
        h1 = int(hashlib.sha256(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.blake2b(item.encode()).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.size

    def add(self, item: str):
        for pos in self._positions(item):
            self._bits[pos // 8] |= (1 << (pos % 8))

    def might_contain(self, item: str) -> bool:
        return all(self._bits[pos // 8] & (1 << (pos % 8)) for pos in self._positions(item))
