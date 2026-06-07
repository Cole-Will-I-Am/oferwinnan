#!/usr/bin/env python3
"""
gut_check.py — A Matrix digital rain engine.

No dependencies. No frameworks. Just raw terminal manipulation,
bitwise entropy, and respect for the craft.

Run it: python3 gut_check.py
Kill it: Ctrl+C (it'll clean up after itself)
"""

import logging
import os
import random
import shutil
import signal
import sys
import time
from collections import deque

logger = logging.getLogger(__name__)

# ─── Terminal Control ────────────────────────────────────────────────────────
# Raw ANSI. No curses. No training wheels.

ESC = "\033"
HIDE_CURSOR = f"{ESC}[?25l"
SHOW_CURSOR = f"{ESC}[?25h"
CLEAR = f"{ESC}[2J"
HOME = f"{ESC}[H"
RESET = f"{ESC}[0m"

# ─── Pre-computed ANSI Escape Code Cache ─────────────────────────────────────
# Building f-strings every frame is expensive. We pre-compute and store them
# in flat lookup tables so rendering is just a dict/list lookup.

_BOLD = f"{ESC}[1m"
_DIM = f"{ESC}[2m"

# Pre-compute move(row, col) strings for a generous terminal size.
# We'll expand lazily if the terminal is larger.
_MOVE_CACHE_ROWS = 300
_MOVE_CACHE_COLS = 500
_move_cache = {}

def _ensure_move_cache(max_row, max_col):
    """Expand the move cache to cover at least (max_row, max_col)."""
    global _MOVE_CACHE_ROWS, _MOVE_CACHE_COLS
    if max_row <= _MOVE_CACHE_ROWS and max_col <= _MOVE_CACHE_COLS:
        return
    _MOVE_CACHE_ROWS = max(max_row, _MOVE_CACHE_ROWS)
    _MOVE_CACHE_COLS = max(max_col, _MOVE_CACHE_COLS)
    _move_cache.clear()
    for r in range(1, _MOVE_CACHE_ROWS + 1):
        for c in range(1, _MOVE_CACHE_COLS + 1):
            _move_cache[(r, c)] = f"{ESC}[{r};{c}H"

# Initialize for common terminal sizes
for _r in range(1, _MOVE_CACHE_ROWS + 1):
    for _c in range(1, _MOVE_CACHE_COLS + 1):
        _move_cache[(_r, _c)] = f"{ESC}[{_r};{_c}H"
del _r, _c

# Pre-compute fg color strings for the specific colors used in rendering.
# The rain uses a small, fixed palette — cache every color we'll ever need.
_fg_cache = {}

def _fg_cached(r, g, b):
    """Return cached fg color string."""
    key = (r, g, b)
    cached = _fg_cache.get(key)
    if cached is not None:
        return cached
    s = f"{ESC}[38;2;{r};{g};{b}m"
    _fg_cache[key] = s
    return s

# Pre-compute the fixed palette colors used in Stream.render
_HEAD_COLOR = f"{_BOLD}{_fg_cached(220, 255, 220)}"
_NEAR_HEAD_COLOR = f"{_BOLD}{_fg_cached(0, 230, 50)}"
_MID_TRAIL_COLOR = _fg_cached(0, 180, 30)

# Pre-compute dim tail colors for all possible intensity values (30..80)
_TAIL_COLORS = {}
for _intensity in range(30, 81):
    _TAIL_COLORS[_intensity] = f"{_DIM}{_fg_cached(0, _intensity, 0)}"
del _intensity

# Backward-compatible function signatures (used by InstrumentedRain and tests)
def move(row, col):
    return _move_cache.get((row, col)) or f"{ESC}[{row};{col}H"

def fg(r, g, b):
    return _fg_cached(r, g, b)

def bold():
    return _BOLD

def dim():
    return _DIM


# ─── The Glyphs ─────────────────────────────────────────────────────────────
# Half-width katakana + numerals + Latin fragments.
# The original film used a mirrored mix. We honor that.

GLYPHS = (
    "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿ"
    "ﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ":・.\"=*+-<>¦╌"
)

# ─── Batched Randomness ─────────────────────────────────────────────────────
# Calling random.choice() hundreds of times per frame adds overhead.
# We pre-generate a large ring buffer of random glyphs and floats,
# then consume them sequentially — nearly zero per-call cost.

_RANDOM_BATCH_SIZE = 8192
_glyph_ring = [random.choice(GLYPHS) for _ in range(_RANDOM_BATCH_SIZE)]
_glyph_ring_idx = 0

_float_ring = [random.random() for _ in range(_RANDOM_BATCH_SIZE)]
_float_ring_idx = 0

def _refill_glyph_ring():
    global _glyph_ring
    _glyph_ring = [random.choice(GLYPHS) for _ in range(_RANDOM_BATCH_SIZE)]

def _refill_float_ring():
    global _float_ring
    _float_ring = [random.random() for _ in range(_RANDOM_BATCH_SIZE)]


def random_glyph():
    global _glyph_ring_idx
    idx = _glyph_ring_idx
    g = _glyph_ring[idx]
    idx += 1
    if idx >= _RANDOM_BATCH_SIZE:
        idx = 0
        _refill_glyph_ring()
    _glyph_ring_idx = idx
    return g


def _fast_random():
    """Fast random float from the pre-generated ring buffer."""
    global _float_ring_idx
    idx = _float_ring_idx
    f = _float_ring[idx]
    idx += 1
    if idx >= _RANDOM_BATCH_SIZE:
        idx = 0
        _refill_float_ring()
    _float_ring_idx = idx
    return f


# ─── Stream ──────────────────────────────────────────────────────────────────
# Each vertical stream is an independent state machine.

class Stream:
    __slots__ = (
        "col", "head", "length", "speed", "tick",
        "trail", "max_rows", "alive", "respawn_delay", "age"
    )

    def __init__(self, col, max_rows):
        self.col = col
        self.max_rows = max_rows
        self.alive = False
        self.respawn_delay = 0
        self.trail = deque()
        self.age = 0
        self._spawn()

    def _spawn(self):
        self.head = random.randint(-20, -1)
        self.length = random.randint(4, max(5, self.max_rows // 2))
        self.speed = random.choice([1, 1, 1, 2, 2, 3])
        self.tick = 0
        self.trail.clear()
        self.alive = True
        self.age = 0

    def update(self):
        if not self.alive:
            self.respawn_delay -= 1
            if self.respawn_delay <= 0:
                self._spawn()
            return

        self.tick += 1
        if self.tick % self.speed != 0:
            return

        self.head += 1
        self.age += 1

        if 1 <= self.head <= self.max_rows:
            glyph = random_glyph()
            self.trail.append((self.head, glyph))

        while len(self.trail) > self.length:
            self.trail.popleft()

        if self.head - self.length > self.max_rows:
            self.alive = False
            self.respawn_delay = random.randint(2, 30)
            self.trail.clear()

    def render(self, cells):
        """Populate cells dict with {(row, col): ansi_string} for this frame."""
        n = len(self.trail)
        if n == 0:
            return

        col = self.col
        max_rows = self.max_rows
        half_n = n >> 1  # n // 2, but faster
        n_minus_1 = n - 1
        n_minus_3 = n - 3

        for i, (row, glyph) in enumerate(self.trail):
            if row < 1 or row > max_rows:
                continue

            # Mutation: glyphs occasionally flicker (batched random)
            if _fast_random() < 0.03:
                glyph = random_glyph()

            if i == n_minus_1:
                # Head: white-hot
                cells[(row, col)] = f"{_HEAD_COLOR}{glyph}"
            elif i >= n_minus_3:
                # Near-head: bright green
                cells[(row, col)] = f"{_NEAR_HEAD_COLOR}{glyph}"
            elif i >= half_n:
                # Mid-trail: medium green
                cells[(row, col)] = f"{_MID_TRAIL_COLOR}{glyph}"
            else:
                # Tail: dim, fading
                intensity = max(30, int(80 * (i / max(1, half_n))))
                cells[(row, col)] = f"{_TAIL_COLORS[intensity]}{glyph}"


# ─── Engine ──────────────────────────────────────────────────────────────────

class MatrixRain:
    def __init__(self):
        self.running = True
        self.cols = 0
        self.rows = 0
        self.streams = []
        self.prev_cells = {}
        self._detect_size()
        self._init_streams()

    def _detect_size(self):
        size = shutil.get_terminal_size((80, 24))
        self.cols = size.columns
        self.rows = size.lines
        # Ensure ANSI move cache covers the terminal
        _ensure_move_cache(self.rows, self.cols)

    def _init_streams(self):
        self.streams = []
        # One stream per column, staggered starts
        for col in range(1, self.cols + 1):
            if random.random() < 0.6:  # ~60% density
                s = Stream(col, self.rows)
                s.head = random.randint(-self.rows, 0)  # stagger
                self.streams.append(s)

    def _handle_resize(self):
        old_cols, old_rows = self.cols, self.rows
        self._detect_size()
        if self.cols != old_cols or self.rows != old_rows:
            self._init_streams()
            self.prev_cells.clear()
            sys.stdout.write(CLEAR)

    def run(self):
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        sys.stdout.write(HIDE_CURSOR + CLEAR)
        sys.stdout.flush()

        target_fps = 30
        frame_time = 1.0 / target_fps

        try:
            while self.running:
                t0 = time.monotonic()

                self._handle_resize()

                # Collect current frame cells
                cur_cells = {}
                for stream in self.streams:
                    stream.update()
                    stream.render(cur_cells)

                buf = []

                # Erase cells that were occupied last frame but aren't now
                prev = self.prev_cells
                _mc = _move_cache
                for pos in prev:
                    if pos not in cur_cells:
                        buf.append(f"{_mc.get(pos) or move(pos[0], pos[1])}{RESET} ")

                # Draw current cells
                for pos, content in cur_cells.items():
                    buf.append(f"{_mc.get(pos) or move(pos[0], pos[1])}{content}")

                buf.append(RESET)

                sys.stdout.write("".join(buf))
                sys.stdout.flush()

                self.prev_cells = cur_cells

                elapsed = time.monotonic() - t0
                sleep = frame_time - elapsed
                if sleep > 0:
                    time.sleep(sleep)

        finally:
            self._cleanup()

    def _shutdown(self, *_):
        self.running = False

    def _cleanup(self):
        sys.stdout.write(SHOW_CURSOR + RESET + CLEAR + HOME)
        sys.stdout.flush()


# ─── Instrumented Mode ───────────────────────────────────────────────────────
# Demonstrates the mirror_blend framework live on the rain engine.
# Usage: python3 gut_check.py --instrumented

class InstrumentedRain:
    """Wraps MatrixRain with live call-counting and timing stats via mirror_blend."""

    def __init__(self):
        from matrix.mirror_blend import MirrorRegistry, Blender, AdaptiveWrapper

        self.registry = MirrorRegistry()
        self.blender = Blender(self.registry)

        # Counters reset every frame
        self.glyph_calls = 0
        self.update_total_us = 0
        self.update_count = 0
        self.frame_num = 0

        # Mirror random_glyph with a call counter
        self._setup_glyph_counter()

        # Mirror Stream.update with a timing hook
        self._setup_update_timer()

        self.rain = MatrixRain()

    def _setup_glyph_counter(self):
        def count_glyph(fn, args, kwargs):
            self.glyph_calls += 1

        mirror = self.registry.mirror(random_glyph, pre=count_glyph, name="random_glyph")
        # Blend into this module's globals so Stream.render picks it up
        import matrix.gut_check as gut_check
        self.blender.blend_into_module(gut_check, "random_glyph", mirror)

    def _setup_update_timer(self):
        self._update_t0 = 0

        def time_pre(fn, args, kwargs):
            self._update_t0 = time.monotonic()

        def time_post(fn, result):
            elapsed_us = (time.monotonic() - self._update_t0) * 1_000_000
            self.update_total_us += elapsed_us
            self.update_count += 1

        original_update = Stream.update
        mirror = self.registry.mirror(original_update, pre=time_pre, post=time_post,
                                       name="Stream.update")
        # Patch the class method
        import matrix.gut_check as gut_check
        self.blender.blend_into_globals(
            vars(gut_check),
            "_instrumented_update", mirror
        )
        # Actually patch on the instances via the run loop — simpler: monkeypatch the class
        Stream.update = mirror

    def run(self):
        original_run = self.rain.run
        rain = self.rain

        signal.signal(signal.SIGINT, rain._shutdown)
        signal.signal(signal.SIGTERM, rain._shutdown)

        sys.stdout.write(HIDE_CURSOR + CLEAR)
        sys.stdout.flush()

        target_fps = 30
        frame_time = 1.0 / target_fps

        try:
            while rain.running:
                t0 = time.monotonic()

                # Reset per-frame counters
                self.glyph_calls = 0
                self.update_total_us = 0
                self.update_count = 0
                self.frame_num += 1

                rain._handle_resize()

                cur_cells = {}
                for stream in rain.streams:
                    stream.update()
                    stream.render(cur_cells)

                buf = []

                _mc = _move_cache
                for pos in rain.prev_cells:
                    if pos not in cur_cells:
                        buf.append(f"{_mc.get(pos) or move(pos[0], pos[1])}{RESET} ")

                for pos, content in cur_cells.items():
                    buf.append(f"{_mc.get(pos) or move(pos[0], pos[1])}{content}")

                buf.append(RESET)

                # Stats bar at the bottom
                avg_us = (self.update_total_us / max(1, self.update_count))
                stats = (
                    f" F:{self.frame_num:>6d}  "
                    f"glyphs/f:{self.glyph_calls:>4d}  "
                    f"streams:{self.update_count:>3d}  "
                    f"avg_update:{avg_us:>6.1f}\u00b5s  "
                    f"mirrors:{self.registry.mirror_count}  "
                    f"blends:{self.blender.blend_count} "
                )
                # Render stats bar: black bg, green text, bottom row
                bar = (
                    f"{_mc.get((rain.rows, 1)) or move(rain.rows, 1)}"
                    f"{ESC}[48;2;0;0;0m{_fg_cached(0, 200, 40)}{_BOLD}"
                    f"{stats:<{rain.cols}}"
                )
                buf.append(bar)

                sys.stdout.write("".join(buf))
                sys.stdout.flush()

                rain.prev_cells = cur_cells

                elapsed = time.monotonic() - t0
                sleep_time = frame_time - elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)

        finally:
            self.blender.revert_all()
            rain._cleanup()


# ─── Entry ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not sys.stdout.isatty():
        logger.error("gut_check.py demands a real terminal.")
        sys.exit(1)

    if "--instrumented" in sys.argv:
        engine = InstrumentedRain()
        engine.run()
    else:
        rain = MatrixRain()
        rain.run()
