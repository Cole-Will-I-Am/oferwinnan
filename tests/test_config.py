"""Tests for matrix.config — configuration loading and defaults."""

import os
import tempfile
import unittest


class TestEnvHelper(unittest.TestCase):
    """Test the _env() helper directly."""

    def test_env_returns_default_when_unset(self):
        from matrix.config import _env
        sentinel = object()
        result = _env("MATRIX_TEST_NONEXISTENT_VAR_XYZ", sentinel)
        self.assertIs(result, sentinel)

    def test_env_reads_string(self):
        from matrix.config import _env
        os.environ["MATRIX_TEST_STR"] = "hello"
        try:
            self.assertEqual(_env("MATRIX_TEST_STR", "default"), "hello")
        finally:
            del os.environ["MATRIX_TEST_STR"]

    def test_env_casts_int(self):
        from matrix.config import _env
        os.environ["MATRIX_TEST_INT"] = "42"
        try:
            result = _env("MATRIX_TEST_INT", 0, int)
            self.assertEqual(result, 42)
            self.assertIsInstance(result, int)
        finally:
            del os.environ["MATRIX_TEST_INT"]

    def test_env_casts_float(self):
        from matrix.config import _env
        os.environ["MATRIX_TEST_FLOAT"] = "3.14"
        try:
            result = _env("MATRIX_TEST_FLOAT", 0.0, float)
            self.assertAlmostEqual(result, 3.14)
        finally:
            del os.environ["MATRIX_TEST_FLOAT"]

    def test_env_casts_bool_true(self):
        from matrix.config import _env
        for val in ("1", "true", "yes", "True", "YES"):
            os.environ["MATRIX_TEST_BOOL"] = val
            try:
                self.assertTrue(_env("MATRIX_TEST_BOOL", False, bool), f"Failed for {val!r}")
            finally:
                del os.environ["MATRIX_TEST_BOOL"]

    def test_env_casts_bool_false(self):
        from matrix.config import _env
        for val in ("0", "false", "no", "other"):
            os.environ["MATRIX_TEST_BOOL"] = val
            try:
                self.assertFalse(_env("MATRIX_TEST_BOOL", True, bool), f"Failed for {val!r}")
            finally:
                del os.environ["MATRIX_TEST_BOOL"]


class TestMatrixConfig(unittest.TestCase):
    """Test MatrixConfig defaults and immutability."""

    def test_default_values(self):
        from matrix.config import MatrixConfig
        cfg = MatrixConfig()
        self.assertEqual(cfg.port, 47701)
        self.assertEqual(cfg.discovery_port, 47700)
        self.assertEqual(cfg.multicast_group, "239.255.77.88")
        self.assertEqual(cfg.ws_path, "/jump/ws")
        self.assertEqual(cfg.ws_port, 8443)
        self.assertEqual(cfg.chunk_size, 65536)
        self.assertEqual(cfg.max_payload, 16777216)
        self.assertEqual(cfg.max_file_size, 10485760)
        self.assertEqual(cfg.llm_backend, "ollama")
        self.assertEqual(cfg.llm_endpoint, "http://127.0.0.1:11434")
        self.assertEqual(cfg.llm_action_budget, 5)

    def test_frozen_immutability(self):
        from matrix.config import MatrixConfig
        cfg = MatrixConfig()
        with self.assertRaises(AttributeError):
            cfg.port = 9999

    def test_global_config_instance(self):
        from matrix.config import config, MatrixConfig
        self.assertIsInstance(config, MatrixConfig)


class TestLoadDotenv(unittest.TestCase):
    """Test .env file loading."""

    def test_load_dotenv_parses_file(self):
        from matrix.config import _load_dotenv
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False,
                                         dir=".") as f:
            f.write("MATRIX_TEST_DOTENV_VAR=from_dotenv\n")
            f.write("# this is a comment\n")
            f.write("\n")
            f.write("MATRIX_TEST_QUOTED='quoted_val'\n")
            dotenv_path = f.name

        try:
            # Remove vars if set, to allow setdefault to work
            os.environ.pop("MATRIX_TEST_DOTENV_VAR", None)
            os.environ.pop("MATRIX_TEST_QUOTED", None)

            # Temporarily rename the file to .env in cwd
            os.rename(dotenv_path, ".env")
            _load_dotenv()

            self.assertEqual(os.environ.get("MATRIX_TEST_DOTENV_VAR"), "from_dotenv")
            self.assertEqual(os.environ.get("MATRIX_TEST_QUOTED"), "quoted_val")
        finally:
            os.environ.pop("MATRIX_TEST_DOTENV_VAR", None)
            os.environ.pop("MATRIX_TEST_QUOTED", None)
            try:
                os.remove(".env")
            except FileNotFoundError:
                pass

    def test_load_dotenv_does_not_override(self):
        from matrix.config import _load_dotenv
        os.environ["MATRIX_TEST_EXISTING"] = "original"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False,
                                         dir=".") as f:
            f.write("MATRIX_TEST_EXISTING=overridden\n")
            dotenv_path = f.name

        try:
            os.rename(dotenv_path, ".env")
            _load_dotenv()
            # setdefault should preserve the existing value
            self.assertEqual(os.environ["MATRIX_TEST_EXISTING"], "original")
        finally:
            os.environ.pop("MATRIX_TEST_EXISTING", None)
            try:
                os.remove(".env")
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    unittest.main()
