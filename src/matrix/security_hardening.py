"""Runtime security hardening for Matrix jump protocol defaults."""

import json
import uuid


def apply_security_hardening():
    from . import jump_protocol as jp
    if getattr(jp, "_SECURITY_HARDENED", False):
        return

    old_listener_init = jp.JumpListener.__init__

    def listener_init(self, host="127.0.0.1", port=47701, auth_validator=None,
                      on