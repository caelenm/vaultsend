"""Tests for entropy_meter.EntropyMeter. Stdlib only; no display needed.

    cd frontend && python3 -m unittest test_entropy_meter
"""

import math
import random
import unittest

from entropy_meter import EntropyMeter

W, H = 480, 300  # pad size in pixels
HZ = 120
T0 = 7_351_000_000_000  # an arbitrary perf_counter_ns()-like start


def times(seconds, hz=HZ, seed=0):
    """Event timestamps at ~hz with a little scheduling jitter, as from a real
    event loop."""
    rng = random.Random(seed)
    period = 1_000_000_000 // hz
    return [T0 + i * period + rng.randrange(-300_000, 300_000) for i in range(int(seconds * hz))]


def feed(points, ts, pressure=0.0):
    meter = EntropyMeter()
    meter.set_bounds(W, H)
    for (x, y), t in zip(points, ts):
        meter.add(x, y, t, pressure)
    return meter


def random_walk(n, seed, box=(0, 0, W, H), accel=4.0, damping=0.9):
    """A walk whose velocity is itself a random walk (varying acceleration),
    bouncing off the edges of `box`."""
    rng = random.Random(seed)
    x0, y0, x1, y1 = box
    x, y = (x0 + x1) / 2, (y0 + y1) / 2
    vx = vy = 0.0
    out = []
    for _ in range(n):
        vx = damping * vx + rng.uniform(-accel, accel)
        vy = damping * vy + rng.uniform(-accel, accel)
        x, y = x + vx, y + vy
        if not x0 <= x <= x1:
            vx = -vx
            x = min(max(x, x0), x1)
        if not y0 <= y <= y1:
            vy = -vy
            y = min(max(y, y0), y1)
        out.append((x, y))
    return out


class EntropyMeterTest(unittest.TestCase):
    def test_no_movement(self):
        ts = times(30)
        meter = feed([(W / 2, H / 2)] * len(ts), ts)
        self.assertFalse(meter.done)
        self.assertEqual(meter.credited_bits, 0)

    def test_straight_line_30s(self):
        # Constant velocity, at a fractional speed so the quantized steps jitter
        # between neighbouring whole-pixel values, as a real slow line does.
        ts = times(30)
        pts = [(10 + 0.37 * i, 20 + 0.23 * i) for i in range(len(ts))]
        meter = feed(pts, ts)
        self.assertFalse(meter.done)
        self.assertLess(meter.credited_bits, EntropyMeter.TARGET_BITS / 4)

    def test_line_back_and_forth_30s(self):
        # The same straight stroke, back and forth across the whole pad.
        ts = times(30)
        span = 2 * (W - 40)
        pts = []
        for i in range(len(ts)):
            p = (7 * i) % span
            pts.append((20 + (p if p < span / 2 else span - p), H / 2))
        meter = feed(pts, ts)
        self.assertFalse(meter.done)
        self.assertLess(meter.credited_bits, EntropyMeter.TARGET_BITS / 4)

    def test_repeated_zigzag_30s(self):
        # A small zig-zag, repeated exactly: the same handful of accelerations.
        ts = times(30)
        cycle = [(6, 4), (6, -4), (6, 4), (6, -4), (-6, 4), (-6, -4), (-6, 4), (-6, -4)]
        x, y, pts = W / 2, H / 2, []
        for i in range(len(ts)):
            dx, dy = cycle[i % len(cycle)]
            x, y = x + dx, y + dy
            pts.append((x, y))
        meter = feed(pts, ts)
        self.assertFalse(meter.done)
        self.assertLess(meter.credited_bits, EntropyMeter.TARGET_BITS / 4)

    def test_fast_motion_in_one_corner(self):
        # Plenty of unpredictable motion, but confined to one corner of the pad:
        # the credit is there, the coverage isn't.
        ts = times(30)
        pts = random_walk(len(ts), seed=7, box=(0, 0, 50, 40), accel=6.0)
        meter = feed(pts, ts)
        self.assertGreaterEqual(meter.credited_bits, EntropyMeter.TARGET_BITS)
        self.assertFalse(meter.covered_enough)
        self.assertFalse(meter.done)

    def test_random_walk_across_pad(self):
        ts = times(5)
        meter = feed(random_walk(len(ts), seed=1), ts)
        self.assertTrue(meter.done)

    def test_duration_gate(self):
        # Even with plenty of credit and coverage, not before 2 s of scribbling.
        ts = times(1.5, hz=240)
        meter = feed(random_walk(len(ts), seed=1, accel=12.0), ts)
        self.assertGreaterEqual(meter.credited_bits, EntropyMeter.TARGET_BITS)
        self.assertTrue(meter.covered_enough)
        self.assertFalse(meter.done)

    def test_fast_events_earn_no_extra_credit(self):
        # The same motion reported at 1000 Hz earns no more than at 120 Hz:
        # nothing is credited within 4 ms of the previous sample.
        slow_ts = times(5)
        fast_ts = times(5, hz=1000)
        path = random_walk(len(slow_ts), seed=3)
        fast_path = [path[min(len(path) - 1, i * HZ // 1000)] for i in range(len(fast_ts))]
        slow, fast = feed(path, slow_ts), feed(fast_path, fast_ts)
        self.assertLessEqual(fast.credited_bits, slow.credited_bits * 1.5)

    def test_credit_per_event_is_capped(self):
        ts = times(1)
        rng = random.Random(5)
        pts = [(rng.uniform(0, W), rng.uniform(0, H)) for _ in ts]
        meter = feed(pts, ts)
        self.assertLessEqual(meter.credited_bits, EntropyMeter.MAX_BITS_PER_EVENT * len(ts))

    def test_non_finite_input_is_ignored(self):
        meter = EntropyMeter()
        meter.set_bounds(W, H)
        meter.add(math.nan, 1.0, T0)
        meter.add(math.inf, 1.0, T0 + 10_000_000)
        self.assertEqual(meter.credited_bits, 0)

    def test_digest_before_done_raises(self):
        meter = EntropyMeter()
        meter.set_bounds(W, H)
        meter.add(1, 1, T0)
        with self.assertRaises(RuntimeError):
            meter.digest()

    def test_digest_after_done(self):
        ts = times(5)
        meter = feed(random_walk(len(ts), seed=1), ts)
        self.assertTrue(meter.done)
        digest = meter.digest()
        self.assertIsInstance(digest, bytes)
        self.assertEqual(len(digest), 64)

    def test_digest_is_single_use(self):
        ts = times(5)
        meter = feed(random_walk(len(ts), seed=1), ts)
        meter.digest()
        with self.assertRaises(RuntimeError):
            meter.digest()
        with self.assertRaises(RuntimeError):
            meter.add(1, 1, ts[-1] + 10_000_000)

    def test_same_scribble_gives_different_digests(self):
        # Seeded with the wall clock, so even an identical event stream does
        # not repeat a digest.
        ts = times(5)
        pts = random_walk(len(ts), seed=1)
        self.assertNotEqual(feed(pts, ts).digest(), feed(pts, ts).digest())


if __name__ == "__main__":
    unittest.main()
