"""Tests for matrix.transport_icmp — ICMP tunnel transport backend."""

import struct
import unittest
from unittest.mock import patch

from matrix.transport_icmp import (
    ICMPBackend,
    ICMPListener,
    ICMPError,
    _build_icmp_echo,
    _parse_icmp_packet,
    _icmp_checksum,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
)


class TestICMPFraming(unittest.TestCase):
    """Unit tests for ICMP packet construction and parsing."""

    def test_checksum_validates(self):
        """Checksum round-trips correctly."""
        pkt = _build_icmp_echo(0x1234, 7, b"payload")
        typ, code, cksum, icmp_id, seq = struct.unpack("!BBHHH", pkt[:8])
        self.assertEqual(typ, ICMP_ECHO_REQUEST)
        recalc = _icmp_checksum(pkt[:2] + b"\x00\x00" + pkt[4:])
        self.assertEqual(cksum, recalc)

    def test_parse_rejects_real_icmp(self):
        """Packets without the magic cookie are ignored."""
        header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, 0, 1, 2)
        cksum = _icmp_checksum(header + b"real ping payload")
        header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, cksum, 1, 2)
        self.assertIsNone(_parse_icmp_packet(header + b"real ping payload"))

    def test_parse_accepts_our_packet(self):
        """Our own echo request/reply parses and preserves payload."""
        pkt = _build_icmp_echo(42, 99, b"hello icmp")
        parsed = _parse_icmp_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], ICMP_ECHO_REQUEST)
        self.assertEqual(parsed["id"], 42)
        self.assertEqual(parsed["seq"], 99)
        self.assertEqual(parsed["payload"], b"hello icmp")

    def test_reply_type_round_trip(self):
        """A reply with flipped type and recalculated checksum still parses."""
        pkt = bytearray(_build_icmp_echo(42, 99, b"reply"))
        pkt[0] = ICMP_ECHO_REPLY
        pkt[2:4] = b"\x00\x00"
        cksum = _icmp_checksum(bytes(pkt[:2]) + b"\x00\x00" + bytes(pkt[4:]))
        pkt[2:4] = struct.pack("!H", cksum)
        parsed = _parse_icmp_packet(bytes(pkt))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], ICMP_ECHO_REPLY)
        self.assertEqual(parsed["payload"], b"reply")

    def test_permission_error(self):
        """Constructing a backend without raw socket permission raises."""
        with patch("socket.socket", side_effect=PermissionError("no")):
            with self.assertRaises(ICMPError):
                ICMPBackend.connect("1.2.3.4", "node-a")


class TestICMPFunctional(unittest.TestCase):
    """Functional tests require a second host or non-loopback setup."""

    @unittest.skip("Requires two hosts or non-loopback ICMP; loopback kernel auto-replies")
    def test_round_trip(self):
        """Placeholder: full client/server ICMP round trip."""
        pass


if __name__ == "__main__":
    unittest.main()
