#!/usr/bin/env python3
"""
gut_check.py — A Matrix digital rain engine.

No dependencies. No frameworks. Just raw terminal manipulation,
bitwise entropy, and respect for the craft.

Run it: python3 gut_check.py
Kill it: Ctrl+C (it'll clean up after itself)
"""

import os
import sys
import time
import random
import signal
import shutil
from collections import deque

# ─── Terminal Control ────────────────────────────────────────────────────────
# Raw ANSI. No curses. No training wheels.

ESC = "\033"
HIDE_CURSOR = f"{ESC}[?25l"
SHOW_CURSOR = f"{ESC}[?25h"
CLEAR = f"{ESC}[2J"
HOME = f"{ESC}[H"
RESET = f"{ESC}[0m"

def move(row, col):
    return f"{ESC}[{row};{col}H"

def fg(r, g, b):
    return f"{ESC}[38;2;{r};{g};{b}m"

def bold():
    return f"{ESC}[1m"

def dim():
    return f"{ESC}[2m"


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


def random_glyph():
    return random.choice(GLYPHS)


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

    def render(self, buf):
        n = len(self.trail)
        if n == 0:
            return

        for i, (row, glyph) in enumerate(self.trail):
            if row < 1 or row > self.max_rows:
                continue

            # Mutation: glyphs occasionally flicker
            if random.random() < 0.03:
                glyph = random_glyph()

            if i == n - 1:
                # Head: white-hot
                buf.append(f"{move(row, self.col)}{bold()}{fg(220, 255, 220)}{glyph}")
            elif i >= n - 3:
                # Near-head: bright green
                buf.append(f"{move(row, self.col)}{bold()}{fg(0, 230, 50)}{glyph}")
            elif i >= n // 2:
                # Mid-trail: medium green
                buf.append(f"{move(row, self.col)}{fg(0, 180, 30)}{glyph}")
            else:
                # Tail: dim, fading
                intensity = max(30, int(80 * (i / max(1, n // 2))))
                buf.append(f"{move(row, self.col)}{dim()}{fg(0, intensity, 0)}{glyph}")


# ─── Engine ──────────────────────────────────────────────────────────────────

class MatrixRain:
    def __init__(self):
        self.running = True
        self.cols = 0
        self.rows = 0
        self.streams = []
        self._detect_size()
        self._init_streams()

    def _detect_size(self):
        size = shutil.get_terminal_size((80, 24))
        self.cols = size.columns
        self.rows = size.lines

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

                buf = [HOME]
                for stream in self.streams:
                    stream.update()
                    stream.render(buf)
                buf.append(RESET)

                sys.stdout.write("".join(buf))
                sys.stdout.flush()

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


# ─── Entry ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not sys.stdout.isatty():
        print("gut_check.py demands a real terminal.", file=sys.stderr)
        sys.exit(1)

    rain = MatrixRain()
    rain.run()
