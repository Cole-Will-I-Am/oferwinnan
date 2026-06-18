"""Tests for traffic mimicry profiles and polymorphism helpers."""

import unittest

from matrix.transport_negotiator import (
    SlackProfile,
    TeamsProfile,
    DiscordProfile,
    DoHProfile,
    GrpcProfile,
    CloudSyncProfile,
    WebAPIProfile,
    PlainProfile,
    pad_frame,
    strip_padding,
    _derive_buckets,
    PADDING_BUCKETS,
)


class TestTrafficProfiles(unittest.TestCase):
    """Round-trip tests for all TrafficProfile implementations."""

    def _round_trip(self, profile, payload):
        wrapped = profile.wrap_outgoing(payload)
        unwrapped = profile.unwrap_incoming(wrapped)
        self.assertEqual(unwrapped, payload)

    def test_plain_profile(self):
        self._round_trip(PlainProfile(), b"hello")

    def test_cloud_sync(self):
        self._round_trip(CloudSyncProfile(), b"sync data")

    def test_web_api(self):
        self._round_trip(WebAPIProfile(channel="ops"), b"api data")

    def test_slack(self):
        self._round_trip(SlackProfile(channel="general"), b"slack data")

    def test_teams(self):
        self._round_trip(TeamsProfile(channel="General"), b"teams data")

    def test_discord(self):
        self._round_trip(DiscordProfile(), b"discord data")

    def test_doh(self):
        self._round_trip(DoHProfile(), b"doh data")

    def test_grpc(self):
        self._round_trip(GrpcProfile(), b"grpc data")


class TestPolymorphicPadding(unittest.TestCase):
    """Tests for deterministic but session-unique padding buckets."""

    def test_default_buckets(self):
        data = b"x" * 50
        padded = pad_frame(data)
        self.assertGreaterEqual(len(padded), 128)
        self.assertEqual(strip_padding(padded, 50), data)

    def test_derived_buckets_differ(self):
        b1 = _derive_buckets("seed-a")
        b2 = _derive_buckets("seed-b")
        self.assertNotEqual(b1, b2)
        self.assertEqual(len(b1), len(PADDING_BUCKETS))

    def test_derived_buckets_stable(self):
        b1 = _derive_buckets("seed-a")
        b2 = _derive_buckets("seed-a")
        self.assertEqual(b1, b2)


if __name__ == "__main__":
    unittest.main()
