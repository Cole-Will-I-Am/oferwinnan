"""Shared pytest fixtures.

Some tests write or delete cwd-relative files (notably ``.env`` in
``test_config.py``). Without isolation those operations clobber the real
working directory — running the suite from the repo root has deleted the
live ``/root/Matrix/.env``. This autouse fixture runs every test inside a
throwaway temporary directory so cwd-relative file operations can never
touch the real tree, then restores the original cwd afterward.
"""

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _isolate_cwd():
    previous = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="matrix-test-") as scratch:
        os.chdir(scratch)
        try:
            yield
        finally:
            os.chdir(previous)
