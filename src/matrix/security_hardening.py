"""Security hardening patches for Matrix jump protocol defaults."""

import json


def apply_security_hardening():
    """Patch jump protocol defaults once per interpreter."""
    import matrix.jump_protocol as jp

    if getattr(jp, "_SECURITY_HARDENED", False):
        return

    original_listener_init = jp.JumpListener.__init__

    def hardened_listener_init(self, host="127.0.0.1", port=47701,
                               auth_validator=None, on_connection=None,
                               max_connections=64):