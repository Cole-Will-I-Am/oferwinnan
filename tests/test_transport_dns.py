"""Tests for matrix.transport_dns — DNS tunnel transport backend."""

import time
import unittest

from matrix.transport_dns import DNSBackend, DNSListener, DNSError


class TestDNSTransport(unittest.TestCase):
    """Functional tests for DNSBackend + DNSListener loopback."""

    def _start_listener(self, on_backend=None):
        listener = DNSListener(domain="t.example", host="127.0.0.1", port=0)
        listener.start(on_backend or (lambda backend: None))
        self._port = listener._sock.getsockname()[1]
        return listener

    def test_small_round_trip(self):
        """Client sends a small payload and receives a reply over DNS."""
        received = []

        def on_backend(backend):
            data = backend.recv_bytes(5)
            received.append(data)
            backend.send_bytes(b"world")

        listener = self._start_listener(on_backend)
        try:
            time.sleep(0.1)
            client = DNSBackend.connect(
                "127.0.0.1", "t.example", "node-a", "node-b", port=self._port
            )
            client.send_bytes(b"hello")
            resp = client.recv_bytes(5)
            self.assertEqual(resp, b"world")
            self.assertEqual(received, [b"hello"])
            client.close()
        finally:
            listener.stop()

    def test_large_round_trip(self):
        """Client sends a multi-chunk payload and gets the same data back."""
        payload = b"A" * 500

        def on_backend(backend):
            data = backend.recv_bytes(len(payload))
            backend.send_bytes(data + b"OK")

        listener = self._start_listener(on_backend)
        try:
            time.sleep(0.1)
            client = DNSBackend.connect(
                "127.0.0.1", "t.example", "node-a", "node-b", port=self._port
            )
            client.send_bytes(payload)
            resp = client.recv_bytes(len(payload) + 2)
            self.assertEqual(resp, payload + b"OK")
            client.close()
        finally:
            listener.stop()

    def test_closed_backend_raises(self):
        """Operations on a closed backend raise DNSError."""
        listener = self._start_listener()
        try:
            time.sleep(0.1)
            client = DNSBackend.connect(
                "127.0.0.1", "t.example", "node-a", "node-b", port=self._port
            )
            client.close()
            with self.assertRaises(DNSError):
                client.send_bytes(b"x")
        finally:
            listener.stop()


if __name__ == "__main__":
    unittest.main()
