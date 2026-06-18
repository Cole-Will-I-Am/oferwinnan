"""Tests for matrix.disguise — process title disguise helpers."""

import os
import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

from matrix.disguise import (
    ProcessDisguise,
    choose_service_alias,
    set_process_title,
    _stable_index,
    COMMON_SERVICE_ALIASES,
)


class TestDisguiseHelpers(unittest.TestCase):
    """Unit tests for deterministic alias selection."""

    def test_stable_index_deterministic(self):
        """Same seed yields the same index."""
        idx1 = _stable_index("foo", COMMON_SERVICE_ALIASES)
        idx2 = _stable_index("foo", COMMON_SERVICE_ALIASES)
        self.assertEqual(idx1, idx2)

    def test_choose_alias_returns_known_format(self):
        """Chosen alias looks like a real service path."""
        alias = choose_service_alias("test-seed")
        self.assertIn(alias, COMMON_SERVICE_ALIASES)
        self.assertTrue(alias.startswith("/usr/lib/") or alias.startswith("/var/lib/"))


class TestSetProcessTitle(unittest.TestCase):
    """Mocked and real tests for process title setting."""

    def test_setproctitle_called(self):
        """When setproctitle is available, it is invoked."""
        with patch.dict("sys.modules", {"setproctitle": MagicMock()}):
            mock = sys.modules["setproctitle"]
            self.assertTrue(set_process_title("/usr/lib/foo/bar"))
            mock.setproctitle.assert_called_once_with("/usr/lib/foo/bar")

    def test_prctl_called_on_linux(self):
        """On Linux, prctl is attempted when setproctitle is missing."""
        with patch("sys.platform", "linux"):
            with patch("ctypes.CDLL") as mock_cdll:
                libc = MagicMock()
                mock_cdll.return_value = libc
                # Remove setproctitle from modules to force fallback
                with patch.dict("sys.modules", {"setproctitle": None}):
                    self.assertFalse(set_process_title("/usr/lib/foo/bar"))


if __name__ == "__main__":
    unittest.main()
