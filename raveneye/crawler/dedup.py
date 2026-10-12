from __future__ import annotations
import hashlib, re
from collections import Counter, deque

from bs4 import BeautifulSoup

class BloomFilter:
    def __init__(self, size=1 << 20, hashes=3):
        self.bits = bytearray(max(8, size) // 8)
        self.size = len(self.bits) * 8
        self.hashes = hashes
    def _idx(self, value, salt):
        return int.from_bytes(hashlib.blake2b((str(salt) + value).encode(), digest_size=8).digest(), "big") % self.size
    def add(self, value):
        for n in range(self.hashes):
            i = self._idx(value, n); self.bits[i // 8] |= 1 << (i % 8)
    def __contains__(self, value):
        return all(self.bits[(i := self._idx(value, n)) // 8] & (1 << (i % 8)) for n in range(self.hashes))

def simhash(text: str) -> int:
    tokens = re.findall(r"\w+", text.lower())
    vec = [0] * 64
    for tok in tokens:
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
        for i in range(64): vec[i] += 1 if h >> i & 1 else -1
    return sum((1 << i) for i, v in enumerate(vec) if v >= 0)

def hamming_distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()

class SimHashIndex:
    def __init__(self, max_distance: int = 3, max_entries: int = 8192):
        self.max_distance = max_distance
        self.max_entries = max(128, max_entries)
        self._hashes = deque(maxlen=self.max_entries)
        self._exact_counts: Counter[int] = Counter()

    @staticmethod
    def main_text(markup: str) -> str:
        """Remove non-content nodes before similarity hashing."""
        soup = BeautifulSoup(markup[:2_000_000], "lxml")
        for node in soup.find_all(("script", "style", "noscript", "svg", "template")):
            node.decompose()
        return " ".join(soup.stripped_strings)

    def add(self, text: str):
        h = simhash(text); duplicate = self.is_duplicate(h)
        if len(self._hashes) == self.max_entries:
            old = self._hashes[0]
            self._exact_counts[old] -= 1
            if self._exact_counts[old] <= 0:
                del self._exact_counts[old]
        self._hashes.append(h)
        self._exact_counts[h] += 1
        return duplicate
    def is_duplicate(self, h: int):
        if h in self._exact_counts: return True
        return any(hamming_distance(h, old) <= self.max_distance for old in self._hashes)
