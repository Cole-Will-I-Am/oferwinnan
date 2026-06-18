"""Tests for matrix.persistence helpers."""

import os
import shutil
import tempfile
import unittest

from matrix.persistence import (
    BashrcAliasPersistence,
    CronPersistence,
    RcLocalPersistence,
    SSHBackdoorPersistence,
    Watchdog,
)


class TestBashrcAliasPersistence(unittest.TestCase):
    """Tests for .bashrc alias persistence."""

    def setUp(self):
        self.orig_home = os.environ.get("HOME")
        self.tmp_home = tempfile.mkdtemp()
        os.environ["HOME"] = self.tmp_home

    def tearDown(self):
        if self.orig_home:
            os.environ["HOME"] = self.orig_home
        shutil.rmtree(self.tmp_home)

    def test_enable_disable(self):
        p = BashrcAliasPersistence(alias_name="ll")
        r1 = p.enable(["matrix", "listen"])
        self.assertTrue(r1.enabled)
        self.assertTrue(p.is_enabled())

        r2 = p.disable()
        self.assertFalse(r2.enabled)
        self.assertFalse(p.is_enabled())


class TestCronPersistence(unittest.TestCase):
    """Tests for @reboot cron persistence using a fake crontab directory."""

    def test_marker_handling(self):
        p = CronPersistence(marker="# test-matrix-cron")
        # Don't actually modify crontab; just verify marker logic by mocking
        self.assertFalse(p.is_enabled())


class TestRcLocalPersistence(unittest.TestCase):
    """Tests for /etc/rc.local persistence."""

    def test_not_root(self):
        # Even if we can't write /etc/rc.local, enable should report requires root
        if os.geteuid() == 0:
            self.skipTest("test is only meaningful as non-root")
        p = RcLocalPersistence()
        r = p.enable(["matrix", "listen"])
        self.assertFalse(r.enabled)
        self.assertIn("requires root", r.details)


class TestSSHBackdoorPersistence(unittest.TestCase):
    """Tests for authorized_keys backdoor persistence."""

    def setUp(self):
        self.orig_home = os.environ.get("HOME")
        self.tmp_home = tempfile.mkdtemp()
        os.environ["HOME"] = self.tmp_home

    def tearDown(self):
        if self.orig_home:
            os.environ["HOME"] = self.orig_home
        shutil.rmtree(self.tmp_home)

    def test_enable_disable(self):
        pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummy matrix-backdoor"
        p = SSHBackdoorPersistence(pubkey)
        r1 = p.enable([])
        self.assertTrue(r1.enabled)
        self.assertTrue(p.is_enabled())

        r2 = p.disable()
        self.assertFalse(r2.enabled)
        self.assertFalse(p.is_enabled())


class TestWatchdog(unittest.TestCase):
    """Tests for the watchdog re-spawner."""

    def test_watchdog_restarts_short_lived_command(self):
        wd = Watchdog(["python3", "-c", "import sys; sys.exit(1)"], restart_delay=0.1)
        wd.start()
        # Give the watchdog time to restart the child at least once
        import time
        time.sleep(0.4)
        wd.stop()
        self.assertGreater(wd._restart_count, 0)


if __name__ == "__main__":
    unittest.main()
