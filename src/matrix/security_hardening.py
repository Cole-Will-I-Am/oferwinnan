"""Security hardening patches for Matrix jump protocol defaults."""

import json


def apply_security_hardening():
    """Patch jump protocol defaults once per interpreter."""
    import matrix.jump_protocol as jp

    if getattr(jp, "_SECURITY_HARDENED", False):
        return

    def client_handshake(backend, node_id: str, auth_token: str = None,
                         connection_id: str = None):
        backend