"""Scribble entropy for the optional "add my own randomness" step at key creation.

Kept free of GTK so it can be tested headless (see test_entropy_meter.py).

Two separate jobs:

* Hashing. Every pointer event, whatever it is, goes into one running BLAKE2b
  state. Its 64-byte digest is what the backend mixes into the new key, together
  with OS randomness (`keygen --entropy-fd`, derive_secret in the backend). The
  digest is handed over once and the meter forgets it; it is never shown,
  logged or stored.

* Crediting. Separately, and deliberately conservatively, each event is
  credited with an estimate of how many unpredictable bits it carries. The
  scribble is only usable once the credit reaches TARGET_BITS (twice X25519's
  ~128-bit security) and the coverage and duration gates below are met, so
  degenerate input such as a straight line or a repeated jiggle never gets
  there, however long it goes on.

How an event is credited. Positions are quantized to whole pixels. An event
whose position changed, and which comes at least MIN_INTERVAL_NS after the
previous such event, is a sample; samples are the "credited points" the motion
is measured between. For a sample, d is its displacement from the previous
sample and a = d - (the previous d), the second difference: how much the motion
changed speed or direction. A sample earns nothing when a is zero (constant
velocity, i.e. a straight line) or equals one of the last RECENT_ACCELS credited
a vectors (a repeated zig-zag); otherwise it earns
min(MAX_BITS_PER_EVENT, log2(1 + |ax| + |ay|) / 2). Every non-sample event
(no movement, or too soon after the last sample) earns nothing.

Advancing the reference on every sample, not only on those that earned credit,
is what keeps a straight line at zero: measured from a reference that stood
still, a constant-velocity line would show ever-growing d and so look like
acceleration.
"""

import hashlib
import math
import struct
import time
from collections import deque


class EntropyMeter:
    TARGET_BITS = 256
    MAX_BITS_PER_EVENT = 1.5
    MIN_INTERVAL_NS = 4_000_000  # 4 ms
    RECENT_ACCELS = 16
    GRID = 12  # coverage grid: GRID x GRID cells over the pad
    MIN_CELLS = 20
    MIN_DURATION_NS = 2_000_000_000  # 2 s from first to last credited event

    def __init__(self):
        # BLAKE2b allows at most 16 bytes of personalization.
        self._hash = hashlib.blake2b(digest_size=64, person=b"vaultsend-scr-v1")
        self._hash.update(struct.pack("<q", time.time_ns()))
        self._bits = 0.0
        self._ref = None  # (x, y, t_ns) of the previous sample
        self._prev_d = None  # its displacement
        self._recent_a = deque(maxlen=self.RECENT_ACCELS)
        self._first_credit_ns = None
        self._last_credit_ns = None
        self._bounds = None
        self._cells = set()

    def set_bounds(self, width: float, height: float) -> None:
        """Size of the pad, for the coverage grid. Call again on every resize."""
        if width > 0 and height > 0:
            self._bounds = (float(width), float(height))

    def add(self, x: float, y: float, t_ns: int, pressure: float = 0.0) -> None:
        if self._hash is None:
            raise RuntimeError("this scribble has already been used")
        self._hash.update(struct.pack("<ddqd", x, y, t_ns, pressure))
        if not (math.isfinite(x) and math.isfinite(y)):
            return
        self._cover(x, y)

        qx, qy = round(x), round(y)
        if self._ref is None:
            self._ref = (qx, qy, t_ns)
            return
        rx, ry, rt = self._ref
        d = (qx - rx, qy - ry)
        if d == (0, 0) or t_ns - rt < self.MIN_INTERVAL_NS:
            return
        prev_d, self._prev_d = self._prev_d, d
        self._ref = (qx, qy, t_ns)
        if prev_d is None:
            return
        a = (d[0] - prev_d[0], d[1] - prev_d[1])
        if a == (0, 0) or a in self._recent_a:
            return
        self._recent_a.append(a)
        self._bits += min(self.MAX_BITS_PER_EVENT, math.log2(1 + abs(a[0]) + abs(a[1])) / 2)
        if self._first_credit_ns is None:
            self._first_credit_ns = t_ns
        self._last_credit_ns = t_ns

    def _cover(self, x, y):
        if self._bounds is None:
            return
        w, h = self._bounds
        cx = min(self.GRID - 1, max(0, int(x * self.GRID / w)))
        cy = min(self.GRID - 1, max(0, int(y * self.GRID / h)))
        self._cells.add((cx, cy))

    @property
    def credited_bits(self) -> float:
        return self._bits

    @property
    def covered_enough(self) -> bool:
        """Whether the scribble has reached enough of the pad (the coverage gate)."""
        return len(self._cells) >= self.MIN_CELLS

    @property
    def done(self) -> bool:
        return (
            self._bits >= self.TARGET_BITS
            and self.covered_enough
            and self._last_credit_ns - self._first_credit_ns >= self.MIN_DURATION_NS
        )

    def digest(self) -> bytes:
        """The 64-byte scribble digest. Only once done, and only once: the hash
        state is discarded afterwards, so the same scribble can't be reused."""
        if self._hash is None:
            raise RuntimeError("this scribble has already been used")
        if not self.done:
            raise RuntimeError("not enough scribbling yet")
        out = self._hash.digest()
        self._hash = None
        return out
