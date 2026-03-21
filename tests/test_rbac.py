"""Tests for rbac.py — Role-Based Access Control."""

import threading
import time
import unittest

from matrix.rbac import (
    Role,
    Permission,
    PermissionSet,
    Identity,
    RBACManager,
    AuthorizationError,
    _hash_token,
)


# ── Role and Permission Enums ────────────────────────────────────────────────

class TestRoleEnum(unittest.TestCase):
    def test_role_values(self):
        self.assertEqual(Role.ADMIN.value, "admin")
        self.assertEqual(Role.OPERATOR.value, "operator")
        self.assertEqual(Role.VIEWER.value, "viewer")

    def test_role_count(self):
        self.assertEqual(len(Role), 3)


class TestPermissionEnum(unittest.TestCase):
    def test_permission_values(self):
        expected = {
            "jump", "discover", "upgrade", "manage_nodes",
            "terminate", "sync_data", "relay", "view_status", "manage_roles",
        }
        actual = {p.value for p in Permission}
        self.assertEqual(actual, expected)

    def test_permission_count(self):
        self.assertEqual(len(Permission), 9)


# ── PermissionSet ─────────────────────────────────────────────────────────────

class TestPermissionSet(unittest.TestCase):
    def test_admin_has_all_permissions(self):
        ps = PermissionSet.for_role(Role.ADMIN)
        for perm in Permission:
            self.assertIn(perm, ps,
                          f"ADMIN should have {perm.value}")

    def test_operator_has_no_manage_roles_or_nodes(self):
        ps = PermissionSet.for_role(Role.OPERATOR)
        self.assertNotIn(Permission.MANAGE_ROLES, ps)
        self.assertNotIn(Permission.MANAGE_NODES, ps)

    def test_operator_has_operational_perms(self):
        ps = PermissionSet.for_role(Role.OPERATOR)
        for perm in (Permission.JUMP, Permission.DISCOVER, Permission.UPGRADE,
                     Permission.TERMINATE, Permission.SYNC_DATA,
                     Permission.RELAY, Permission.VIEW_STATUS):
            self.assertTrue(ps.has(perm),
                            f"OPERATOR should have {perm.value}")

    def test_viewer_only_view_and_discover(self):
        ps = PermissionSet.for_role(Role.VIEWER)
        self.assertTrue(ps.has(Permission.VIEW_STATUS))
        self.assertTrue(ps.has(Permission.DISCOVER))
        # Must NOT have other permissions
        self.assertFalse(ps.has(Permission.JUMP))
        self.assertFalse(ps.has(Permission.UPGRADE))
        self.assertFalse(ps.has(Permission.MANAGE_NODES))
        self.assertFalse(ps.has(Permission.MANAGE_ROLES))
        self.assertFalse(ps.has(Permission.TERMINATE))

    def test_custom_permission_set(self):
        ps = PermissionSet.custom(Permission.JUMP, Permission.RELAY)
        self.assertTrue(ps.has(Permission.JUMP))
        self.assertTrue(ps.has(Permission.RELAY))
        self.assertFalse(ps.has(Permission.DISCOVER))

    def test_union_operator(self):
        a = PermissionSet.custom(Permission.JUMP)
        b = PermissionSet.custom(Permission.RELAY)
        merged = a | b
        self.assertTrue(merged.has(Permission.JUMP))
        self.assertTrue(merged.has(Permission.RELAY))

    def test_intersection_operator(self):
        a = PermissionSet.custom(Permission.JUMP, Permission.RELAY)
        b = PermissionSet.custom(Permission.RELAY, Permission.DISCOVER)
        common = a & b
        self.assertTrue(common.has(Permission.RELAY))
        self.assertFalse(common.has(Permission.JUMP))
        self.assertFalse(common.has(Permission.DISCOVER))

    def test_contains_dunder(self):
        ps = PermissionSet.custom(Permission.UPGRADE)
        self.assertIn(Permission.UPGRADE, ps)
        self.assertNotIn(Permission.JUMP, ps)

    def test_has_method(self):
        ps = PermissionSet.custom(Permission.SYNC_DATA)
        self.assertTrue(ps.has(Permission.SYNC_DATA))
        self.assertFalse(ps.has(Permission.TERMINATE))


# ── Identity ──────────────────────────────────────────────────────────────────

class TestIdentity(unittest.TestCase):
    def setUp(self):
        self.identity = Identity(
            identity_id="id-1",
            node_id="node-a",
            role=Role.OPERATOR,
            auth_token_hash="fakehash",
            created_at=time.time(),
        )

    def test_creation(self):
        self.assertEqual(self.identity.identity_id, "id-1")
        self.assertEqual(self.identity.node_id, "node-a")
        self.assertEqual(self.identity.role, Role.OPERATOR)

    def test_effective_permissions_defaults_to_role(self):
        perms = self.identity.effective_permissions
        expected = PermissionSet.for_role(Role.OPERATOR)
        self.assertEqual(perms.permissions, expected.permissions)

    def test_effective_permissions_custom_override(self):
        custom = PermissionSet.custom(Permission.JUMP)
        self.identity.custom_permissions = custom
        self.assertEqual(self.identity.effective_permissions.permissions,
                         custom.permissions)

    def test_is_expired_false_when_no_expiry(self):
        self.assertFalse(self.identity.is_expired)

    def test_is_expired_false_when_future(self):
        self.identity.expires_at = time.time() + 3600
        self.assertFalse(self.identity.is_expired)

    def test_is_expired_true_when_past(self):
        self.identity.expires_at = time.time() - 1
        self.assertTrue(self.identity.is_expired)


# ── Token Hashing ─────────────────────────────────────────────────────────────

class TestTokenHashing(unittest.TestCase):
    def test_hash_is_deterministic(self):
        h1 = _hash_token("secret-token")
        h2 = _hash_token("secret-token")
        self.assertEqual(h1, h2)

    def test_different_tokens_different_hashes(self):
        h1 = _hash_token("token-a")
        h2 = _hash_token("token-b")
        self.assertNotEqual(h1, h2)

    def test_hash_is_hex_sha256(self):
        h = _hash_token("test")
        self.assertEqual(len(h), 64)  # SHA-256 hex = 64 chars


# ── RBACManager ───────────────────────────────────────────────────────────────

class TestRBACManager(unittest.TestCase):
    def setUp(self):
        self.mgr = RBACManager()
        self.token = "my-secret-token"
        self.identity = self.mgr.register_identity(
            identity_id="op-1",
            node_id="node-a",
            role=Role.OPERATOR,
            auth_token=self.token,
        )

    def tearDown(self):
        pass  # manager is garbage-collected

    # -- Registration --

    def test_register_identity_returns_identity(self):
        self.assertEqual(self.identity.identity_id, "op-1")
        self.assertEqual(self.identity.role, Role.OPERATOR)

    def test_register_stores_hashed_token(self):
        """Raw token must never be stored — only its hash."""
        self.assertNotEqual(self.identity.auth_token_hash, self.token)
        self.assertEqual(self.identity.auth_token_hash,
                         _hash_token(self.token))

    def test_remove_identity(self):
        self.mgr.remove_identity("op-1")
        self.assertIsNone(self.mgr.get_identity("op-1"))
        self.assertEqual(self.mgr.identity_count, 0)

    def test_remove_nonexistent_is_safe(self):
        self.mgr.remove_identity("no-such-id")  # should not raise

    # -- Permission Checks --

    def test_check_permission_valid(self):
        self.assertTrue(
            self.mgr.check_permission(self.token, Permission.JUMP))

    def test_check_permission_invalid_token(self):
        self.assertFalse(
            self.mgr.check_permission("wrong-token", Permission.JUMP))

    def test_check_permission_denied_for_role(self):
        """Operator should not have MANAGE_ROLES."""
        self.assertFalse(
            self.mgr.check_permission(self.token, Permission.MANAGE_ROLES))

    def test_require_permission_passes(self):
        # Should not raise
        self.mgr.require_permission(self.token, Permission.JUMP)

    def test_require_permission_raises(self):
        with self.assertRaises(AuthorizationError):
            self.mgr.require_permission(self.token, Permission.MANAGE_ROLES)

    def test_require_permission_invalid_token_raises(self):
        with self.assertRaises(AuthorizationError):
            self.mgr.require_permission("bad-token", Permission.JUMP)

    # -- Node Policies --

    def test_add_node_policy_overrides_defaults(self):
        """Per-node policy should override the identity-level permissions."""
        restricted = PermissionSet.custom(Permission.VIEW_STATUS)
        self.mgr.add_node_policy("op-1", "secure-node", restricted)

        # On the specific node: only VIEW_STATUS allowed
        self.assertTrue(
            self.mgr.check_permission(self.token, Permission.VIEW_STATUS,
                                       target_node_id="secure-node"))
        self.assertFalse(
            self.mgr.check_permission(self.token, Permission.JUMP,
                                       target_node_id="secure-node"))
        # On other nodes: normal operator permissions still apply
        self.assertTrue(
            self.mgr.check_permission(self.token, Permission.JUMP,
                                       target_node_id="other-node"))

    def test_add_node_policy_unknown_identity_raises(self):
        with self.assertRaises(AuthorizationError):
            self.mgr.add_node_policy(
                "no-such-id", "node-x",
                PermissionSet.custom(Permission.JUMP))

    def test_remove_node_policy(self):
        restricted = PermissionSet.custom(Permission.VIEW_STATUS)
        self.mgr.add_node_policy("op-1", "secure-node", restricted)
        # Before removal: restricted
        self.assertFalse(
            self.mgr.check_permission(self.token, Permission.JUMP,
                                       target_node_id="secure-node"))
        # After removal: back to default
        self.mgr.remove_node_policy("op-1", "secure-node")
        self.assertTrue(
            self.mgr.check_permission(self.token, Permission.JUMP,
                                       target_node_id="secure-node"))

    # -- Auth Validator --

    def test_make_auth_validator(self):
        validator = self.mgr.make_auth_validator(Permission.JUMP)
        self.assertTrue(validator(self.token))
        self.assertFalse(validator("wrong-token"))

    def test_make_auth_validator_with_node(self):
        restricted = PermissionSet.custom(Permission.VIEW_STATUS)
        self.mgr.add_node_policy("op-1", "locked-node", restricted)

        validator = self.mgr.make_auth_validator(
            Permission.JUMP, target_node_id="locked-node")
        self.assertFalse(validator(self.token))

    # -- Expired Identity --

    def test_expired_identity_rejected(self):
        expired_token = "expired-token"
        self.mgr.register_identity(
            identity_id="exp-1",
            node_id="node-b",
            role=Role.ADMIN,
            auth_token=expired_token,
            expires_at=time.time() - 1,  # already expired
        )
        self.assertFalse(
            self.mgr.check_permission(expired_token, Permission.JUMP))

    # -- Queries --

    def test_list_identities(self):
        ids = self.mgr.list_identities()
        self.assertEqual(len(ids), 1)
        self.assertEqual(ids[0].identity_id, "op-1")

    def test_identity_count(self):
        self.assertEqual(self.mgr.identity_count, 1)
        self.mgr.register_identity("id-2", "n2", Role.VIEWER, "token2")
        self.assertEqual(self.mgr.identity_count, 2)

    def test_get_identity(self):
        ident = self.mgr.get_identity("op-1")
        self.assertIsNotNone(ident)
        self.assertEqual(ident.role, Role.OPERATOR)

    def test_get_identity_missing(self):
        self.assertIsNone(self.mgr.get_identity("nope"))


# ── Thread Safety ─────────────────────────────────────────────────────────────

class TestRBACThreadSafety(unittest.TestCase):
    def test_concurrent_permission_checks(self):
        """Hammer check_permission from multiple threads."""
        mgr = RBACManager()
        tokens = []
        for i in range(10):
            tok = f"token-{i}"
            tokens.append(tok)
            mgr.register_identity(f"id-{i}", f"node-{i}", Role.OPERATOR, tok)

        errors = []
        results = []

        def checker(token):
            try:
                for _ in range(50):
                    r = mgr.check_permission(token, Permission.JUMP)
                    results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=checker, args=(t,))
                   for t in tokens]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertTrue(all(results))


if __name__ == "__main__":
    unittest.main()
