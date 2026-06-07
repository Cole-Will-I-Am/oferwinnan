"""
Role-Based Access Control — Segmented permissions per node or operation.

Provides a role hierarchy (ADMIN > OPERATOR > VIEWER) with granular
per-operation and per-node permission policies.  Thread-safe and
designed to integrate with JumpListener's auth_validator callback.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, FrozenSet, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "Role",
    "Permission",
    "PermissionSet",
    "Identity",
    "AccessPolicy",
    "RBACManager",
    "AuthorizationError",
]


# -- Roles and Permissions ----------------------------------------------------

class Role(Enum):
    """Hierarchical roles with decreasing privilege."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(Enum):
    """Granular operation permissions."""
    JUMP = "jump"
    DISCOVER = "discover"
    UPGRADE = "upgrade"
    MANAGE_NODES = "manage_nodes"
    TERMINATE = "terminate"
    SYNC_DATA = "sync_data"
    RELAY = "relay"
    VIEW_STATUS = "view_status"
    MANAGE_ROLES = "manage_roles"


# -- Default permission sets per role -----------------------------------------

_ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.OPERATOR: frozenset({
        Permission.JUMP,
        Permission.DISCOVER,
        Permission.UPGRADE,
        Permission.TERMINATE,
        Permission.SYNC_DATA,
        Permission.RELAY,
        Permission.VIEW_STATUS,
    }),
    Role.VIEWER: frozenset({
        Permission.VIEW_STATUS,
        Permission.DISCOVER,
    }),
}


@dataclass(slots=True)
class PermissionSet:
    """Immutable set of permissions with role-based factory."""

    permissions: FrozenSet[Permission]

    @classmethod
    def for_role(cls, role: Role) -> PermissionSet:
        """Return the default permission set for *role*."""
        return cls(permissions=_ROLE_PERMISSIONS[role])

    @classmethod
    def custom(cls, *perms: Permission) -> PermissionSet:
        """Build a custom permission set."""
        return cls(permissions=frozenset(perms))

    def has(self, perm: Permission) -> bool:
        return perm in self.permissions

    def __contains__(self, perm: Permission) -> bool:
        return perm in self.permissions

    def __or__(self, other: PermissionSet) -> PermissionSet:
        return PermissionSet(self.permissions | other.permissions)

    def __and__(self, other: PermissionSet) -> PermissionSet:
        return PermissionSet(self.permissions & other.permissions)


# -- Identity and Policy ------------------------------------------------------

@dataclass(slots=True)
class Identity:
    """A registered identity (node or operator) with role and permissions."""

    identity_id: str
    node_id: str
    role: Role
    auth_token_hash: str
    custom_permissions: Optional[PermissionSet] = None
    created_at: float = 0.0
    expires_at: Optional[float] = None

    @property
    def effective_permissions(self) -> PermissionSet:
        """Custom permissions if set, otherwise defaults for role."""
        if self.custom_permissions is not None:
            return self.custom_permissions
        return PermissionSet.for_role(self.role)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


@dataclass(slots=True)
class AccessPolicy:
    """Binds a permission set to a specific target node for an identity."""

    identity_id: str
    target_node_id: str
    permissions: PermissionSet


# -- Errors --------------------------------------------------------------------

class AuthorizationError(Exception):
    """Raised when a permission check fails."""


# -- RBAC Manager --------------------------------------------------------------

def _hash_token(token: str) -> str:
    """SHA-256 hash of an auth token (never store raw tokens)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RBACManager:
    """Thread-safe central authority for role-based access control.

    Identities are registered with a role and auth token.  Permission checks
    use constant-time comparison on hashed tokens to prevent timing attacks.
    Per-node access policies can override the identity-level permissions.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._identities: Dict[str, Identity] = {}          # id -> Identity
        self._token_index: Dict[str, str] = {}               # hash -> id
        self._policies: Dict[str, List[AccessPolicy]] = {}   # id -> policies

    # -- Registration ----------------------------------------------------------

    def register_identity(
        self,
        identity_id: str,
        node_id: str,
        role: Role,
        auth_token: str,
        custom_permissions: Optional[PermissionSet] = None,
        expires_at: Optional[float] = None,
    ) -> Identity:
        """Register a new identity.  Stores only the hashed token.

        If *identity_id* already exists, the old token hash is removed
        from the index before the new one is inserted (token rotation).
        """
        token_hash = _hash_token(auth_token)
        identity = Identity(
            identity_id=identity_id,
            node_id=node_id,
            role=role,
            auth_token_hash=token_hash,
            custom_permissions=custom_permissions,
            created_at=time.time(),
            expires_at=expires_at,
        )
        with self._lock:
            # Remove old token hash on re-registration (token rotation)
            old = self._identities.get(identity_id)
            if old is not None:
                self._token_index.pop(old.auth_token_hash, None)
            self._identities[identity_id] = identity
            self._token_index[token_hash] = identity_id
            self._policies.setdefault(identity_id, [])
        logger.info("registered identity %s (role=%s, node=%s)",
                     identity_id, role.value, node_id)
        return identity

    def remove_identity(self, identity_id: str) -> None:
        """Remove an identity and its policies."""
        with self._lock:
            identity = self._identities.pop(identity_id, None)
            if identity is not None:
                self._token_index.pop(identity.auth_token_hash, None)
            self._policies.pop(identity_id, None)

    # -- Policy ----------------------------------------------------------------

    def add_node_policy(
        self,
        identity_id: str,
        target_node_id: str,
        permissions: PermissionSet,
    ) -> None:
        """Add a per-node permission override for *identity_id*."""
        policy = AccessPolicy(
            identity_id=identity_id,
            target_node_id=target_node_id,
            permissions=permissions,
        )
        with self._lock:
            if identity_id not in self._identities:
                raise AuthorizationError(f"unknown identity: {identity_id}")
            self._policies.setdefault(identity_id, []).append(policy)

    def remove_node_policy(
        self,
        identity_id: str,
        target_node_id: str,
    ) -> None:
        """Remove per-node policies for *identity_id* targeting *target_node_id*."""
        with self._lock:
            policies = self._policies.get(identity_id, [])
            self._policies[identity_id] = [
                p for p in policies if p.target_node_id != target_node_id
            ]

    # -- Lookup ----------------------------------------------------------------

    def _resolve_token(self, auth_token: str) -> Optional[Identity]:
        """Resolve an auth token to an identity using constant-time comparison."""
        token_hash = _hash_token(auth_token)
        with self._lock:
            # Walk all hashes with constant-time comparison
            matched_id: Optional[str] = None
            for stored_hash, ident_id in self._token_index.items():
                if hmac.compare_digest(stored_hash, token_hash):
                    matched_id = ident_id
            if matched_id is None:
                return None
            identity = self._identities.get(matched_id)
            if identity is not None and identity.is_expired:
                logger.warning("expired identity %s", matched_id)
                return None
            return identity

    def _get_effective_perms(
        self,
        identity: Identity,
        target_node_id: Optional[str],
    ) -> PermissionSet:
        """Return effective permissions, checking node-specific policies first."""
        if target_node_id is not None:
            with self._lock:
                policies = self._policies.get(identity.identity_id, [])
                for policy in policies:
                    if policy.target_node_id == target_node_id:
                        return policy.permissions
        return identity.effective_permissions

    # -- Permission Checks -----------------------------------------------------

    def check_permission(
        self,
        auth_token: str,
        permission: Permission,
        target_node_id: Optional[str] = None,
    ) -> bool:
        """Return True if *auth_token* holder has *permission*."""
        identity = self._resolve_token(auth_token)
        if identity is None:
            return False
        perms = self._get_effective_perms(identity, target_node_id)
        return perms.has(permission)

    def require_permission(
        self,
        auth_token: str,
        permission: Permission,
        target_node_id: Optional[str] = None,
    ) -> None:
        """Raise AuthorizationError if *auth_token* lacks *permission*."""
        if not self.check_permission(auth_token, permission, target_node_id):
            raise AuthorizationError(
                f"permission denied: {permission.value}"
                + (f" on node {target_node_id}" if target_node_id else "")
            )

    # -- JumpListener Integration ----------------------------------------------

    def make_auth_validator(
        self,
        required_permission: Permission,
        target_node_id: Optional[str] = None,
    ) -> Callable[[str], bool]:
        """Return a closure suitable for JumpListener's auth_validator."""
        def validator(token: str) -> bool:
            return self.check_permission(token, required_permission, target_node_id)
        return validator

    # -- Queries ---------------------------------------------------------------

    def get_identity(self, identity_id: str) -> Optional[Identity]:
        with self._lock:
            return self._identities.get(identity_id)

    def list_identities(self) -> List[Identity]:
        with self._lock:
            return list(self._identities.values())

    @property
    def identity_count(self) -> int:
        with self._lock:
            return len(self._identities)
