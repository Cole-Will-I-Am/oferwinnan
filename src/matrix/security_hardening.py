"""Reserved security hardening module.

This module is intentionally inert. Security fixes are applied directly in
jump_protocol.py so importing this package cannot partially monkeypatch runtime
behavior.
"""


def apply_security_hardening():
    """No-op compatibility hook."""
    return None
