"""CLI behavior and safety tests."""

import unittest
from unittest.mock import patch

from matrix.cli import _maybe_restore_files, main
from matrix.session_jumper import JumpSession


class TestCLI(unittest.TestCase):
    def _session_with_file(self) -> JumpSession:
        return JumpSession(
            session_id="s1",
            source_device="src",
            files={"hello.txt": "aGVsbG8="},
        )

    def test_maybe_restore_files_never(self):
        session = self._session_with_file()
        with patch("matrix.cli.restore_session") as mock_restore:
            _maybe_restore_files(session, "never")
            mock_restore.assert_not_called()

    def test_maybe_restore_files_ask_non_interactive(self):
        session = self._session_with_file()
        with patch("matrix.cli.restore_session") as mock_restore, \
                patch("matrix.cli.sys.stdin.isatty", return_value=False), \
                patch("builtins.input") as mock_input:
            _maybe_restore_files(session, "ask")
            mock_input.assert_not_called()
            mock_restore.assert_not_called()

    def test_maybe_restore_files_ask_interactive_yes(self):
        session = self._session_with_file()
        with patch("matrix.cli.restore_session") as mock_restore, \
                patch("matrix.cli.sys.stdin.isatty", return_value=True), \
                patch("builtins.input", return_value="y"):
            _maybe_restore_files(session, "ask")
            mock_restore.assert_called_once_with(session, restore_files=True)

    def test_listen_restore_files_parsed(self):
        with patch("matrix.cli.cmd_listen") as mock_cmd, \
                patch("sys.argv", ["matrix", "listen", "--restore-files", "never"]):
            main()
            mock_cmd.assert_called_once()
            args = mock_cmd.call_args.args[0]
            self.assertEqual(args.restore_files, "never")


if __name__ == "__main__":
    unittest.main()
