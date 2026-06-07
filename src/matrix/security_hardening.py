"""Security hardening patches for Matrix jump protocol defaults.

This module is intentionally small and imported by the package initializer. It
keeps compatibility with the existing public API while tightening two risky
paths:

* listeners bind to localhost by default and cannot bind wildcard addresses
  without authentication; and
* bearer tokens are validated only after X25519 key agreement, inside the
  encrypted JumpConnection channel.
"""

import json
import uuid


def apply_security_hardening():
    """Patch jump_protocol with safer listener and authentication defaults."""
    from . import jump_protocol as jp

    if getattr(jp, "_SECURITY_HARDENED", False):
        return

    original_listener_init = jp.JumpListener.__init__

    def hardened