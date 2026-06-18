"""Tests for remote tasking over the Matrix jump channel."""

import time
import unittest

from matrix.device_discovery import Device, Transport
from matrix.session_jumper import JumpNode


class TestRemoteTasking(unittest.TestCase):
    """Functional tests for JumpNode.run_task / _handle_task_request."""

    def setUp(self):
        self.server = JumpNode(
            node_name="server",
            listen_port=0,
            auth_token="secret",
        )
        self.server.start()
        self.port = self.server.listener._server_sock.getsockname()[1]
        time.sleep(0.2)

        self.client = JumpNode(
            node_name="client",
            listen_port=0,
            auth_token="secret",
        )
        self.client.start()
        time.sleep(0.1)

    def tearDown(self):
        self.client.stop()
        self.server.stop()

    def test_simple_echo(self):
        """A simple echo command returns output and exit code 0."""
        target = Device(
            device_id="server",
            name="server",
            address="127.0.0.1",
            transport=Transport.WIFI,
            port=self.port,
            last_seen=time.time(),
        )
        result = self.client.run_task(target, "echo hello world")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["output"].strip(), "hello world")

    def test_exit_code(self):
        """A failing command reports a non-zero exit code."""
        target = Device(
            device_id="server",
            name="server",
            address="127.0.0.1",
            transport=Transport.WIFI,
            port=self.port,
            last_seen=time.time(),
        )
        result = self.client.run_task(target, "exit 7")
        self.assertEqual(result["exit_code"], 7)


if __name__ == "__main__":
    unittest.main()
