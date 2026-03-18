import unittest
from collections import deque
from types import SimpleNamespace
from unittest.mock import patch

import gut_check


class TestStream(unittest.TestCase):
    def test_init_sets_defaults(self):
        with patch("gut_check.random.randint", side_effect=[-5, 8]), patch("gut_check.random.choice", return_value=2):
            stream = gut_check.Stream(3, 20)

        self.assertEqual(stream.col, 3)
        self.assertEqual(stream.max_rows, 20)
        self.assertTrue(stream.alive)
        self.assertEqual(stream.respawn_delay, 0)
        self.assertEqual(stream.age, 0)
        self.assertEqual(stream.tick, 0)
        self.assertIsInstance(stream.trail, deque)

    def test_spawn_produces_valid_ranges(self):
        stream = gut_check.Stream(1, 40)
        for _ in range(50):
            stream._spawn()
            self.assertGreaterEqual(stream.head, -20)
            self.assertLessEqual(stream.head, -1)
            self.assertGreaterEqual(stream.length, 4)
            self.assertLessEqual(stream.length, max(5, stream.max_rows // 2))
            self.assertIn(stream.speed, [1, 2, 3])

    def test_update_advances_head_based_on_speed_and_tick(self):
        stream = gut_check.Stream(2, 20)
        stream.alive = True
        stream.head = 0
        stream.length = 5
        stream.speed = 2
        stream.tick = 0
        stream.age = 0
        stream.trail.clear()

        stream.update()
        self.assertEqual(stream.head, 0)
        self.assertEqual(stream.tick, 1)

        with patch("gut_check.random_glyph", return_value="A"):
            stream.update()

        self.assertEqual(stream.head, 1)
        self.assertEqual(stream.age, 1)
        self.assertEqual(list(stream.trail), [(1, "A")])

    def test_update_marks_not_alive_when_past_max_rows(self):
        stream = gut_check.Stream(1, 5)
        stream.alive = True
        stream.head = 11
        stream.length = 5
        stream.speed = 1
        stream.tick = 0
        stream.trail.append((5, "Z"))

        with patch("gut_check.random.randint", return_value=7):
            stream.update()

        self.assertFalse(stream.alive)
        self.assertEqual(stream.respawn_delay, 7)
        self.assertEqual(len(stream.trail), 0)

    def test_update_respawns_after_delay_reaches_zero(self):
        stream = gut_check.Stream(1, 10)
        stream.alive = False
        stream.respawn_delay = 1

        with patch.object(gut_check.Stream, "_spawn") as spawn:
            stream.update()

        spawn.assert_called_once_with()
        self.assertEqual(stream.respawn_delay, 0)

    def test_render_populates_cells(self):
        stream = gut_check.Stream(4, 10)
        stream.trail = deque([(1, "A"), (2, "B"), (3, "C")])
        cells = {}

        with patch("gut_check._fast_random", return_value=1.0):
            stream.render(cells)

        self.assertEqual(set(cells.keys()), {(1, 4), (2, 4), (3, 4)})

    def test_render_returns_empty_for_no_trail(self):
        stream = gut_check.Stream(2, 10)
        stream.trail.clear()
        cells = {(1, 1): "x"}
        stream.render(cells)
        self.assertEqual(cells, {(1, 1): "x"})


class TestRandomHelpers(unittest.TestCase):
    def test_random_glyph_returns_valid_character(self):
        for _ in range(100):
            self.assertIn(gut_check.random_glyph(), gut_check.GLYPHS)

    def test_fast_random_in_range(self):
        for _ in range(100):
            value = gut_check._fast_random()
            self.assertGreaterEqual(value, 0.0)
            self.assertLess(value, 1.0)

    def test_ring_buffer_refill(self):
        with patch("gut_check.random.choice", return_value="Z"):
            gut_check._glyph_ring_idx = gut_check._RANDOM_BATCH_SIZE - 5
            values = [gut_check.random_glyph() for _ in range(gut_check._RANDOM_BATCH_SIZE + 10)]

        self.assertEqual(len(values), gut_check._RANDOM_BATCH_SIZE + 10)
        self.assertTrue(all(value in gut_check.GLYPHS for value in values))


class TestMatrixRain(unittest.TestCase):
    def test_init_creates_streams_list(self):
        rain = gut_check.MatrixRain()
        self.assertIsInstance(rain.streams, list)

    def test_detect_size_sets_rows_and_cols(self):
        rain = gut_check.MatrixRain()
        with patch("gut_check.shutil.get_terminal_size", return_value=SimpleNamespace(columns=120, lines=55)):
            rain._detect_size()
        self.assertEqual(rain.cols, 120)
        self.assertEqual(rain.rows, 55)

    def test_handle_resize_reinits_streams_when_size_changes(self):
        rain = gut_check.MatrixRain()
        with patch.object(rain, "_init_streams") as init_streams, patch(
            "gut_check.shutil.get_terminal_size",
            return_value=SimpleNamespace(columns=rain.cols + 1, lines=rain.rows + 1),
        ):
            rain._handle_resize()
        init_streams.assert_called_once_with()

    def test_move_cache_precomputed(self):
        self.assertIn((1, 1), gut_check._move_cache)
        self.assertIn((gut_check._MOVE_CACHE_ROWS, gut_check._MOVE_CACHE_COLS), gut_check._move_cache)

    def test_fg_cache_caches_same_object(self):
        first = gut_check._fg_cached(1, 2, 3)
        second = gut_check._fg_cached(1, 2, 3)
        self.assertIs(first, second)

    def test_tail_colors_cover_expected_range(self):
        self.assertEqual(set(gut_check._TAIL_COLORS), set(range(30, 81)))


if __name__ == "__main__":
    unittest.main()
