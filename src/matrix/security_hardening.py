"""Security hardening patches for Matrix jump protocol defaults."""


def apply_security_hardening():
    """Patch unsafe listener defaults once per interpreter."""
    import matrix.jump_protocol as jp
    if getattr(jp, "_SECURITY_HARDENED", False):
        return
    original_init = jp.JumpListener.__init__

    def hardened_init(self, host="127.0.0.1", port=47701, auth_validator=None,
                      on_connection=None, max_connections=64):
        if host in ("0.0.0.0", "::", "") and auth_validator is None:
            raise jp