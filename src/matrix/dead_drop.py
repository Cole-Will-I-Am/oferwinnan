"""
Dead Drop — Backup transport channels via cloud storage.

Implements the TransportBackend protocol over cloud storage (S3, GCS,
Azure Blob) or local filesystem.  Nodes communicate by writing encrypted
blobs to each other's "mailbox" paths and polling for new messages.

Designed as a fallback transport when direct connections are unavailable.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os
import shutil
import struct
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote as urlquote
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

__all__ = [
    "DeadDropBackend",
    "DeadDropConfig",
    "CloudProvider",
    "CloudStorageAdapter",
    "S3DeadDrop",
    "FileSystemDeadDrop",
    "DeadDropError",
]


# -- Errors --------------------------------------------------------------------

class DeadDropError(Exception):
    """Raised on dead-drop transport failure."""


# -- Configuration -------------------------------------------------------------

class CloudProvider(Enum):
    S3 = "s3"
    GCS = "gcs"
    AZURE = "azure"
    FILESYSTEM = "filesystem"


@dataclass(slots=True)
class DeadDropConfig:
    """Configuration for a dead-drop transport channel."""

    provider: CloudProvider
    bucket_name: str = ""
    prefix: str = "matrix-drops"
    base_path: str = ""            # for FILESYSTEM provider
    poll_interval: float = 2.0
    ttl: float = 300.0
    credentials: dict = field(default_factory=dict)


# -- Cloud Storage Adapter (Abstract) -----------------------------------------

class CloudStorageAdapter(ABC):
    """Abstract interface for cloud storage operations."""

    @abstractmethod
    def write(self, path: str, data: bytes) -> None:
        """Write data to storage at *path*."""

    @abstractmethod
    def read(self, path: str) -> bytes:
        """Read data from *path*."""

    @abstractmethod
    def list_objects(self, prefix: str) -> List[str]:
        """List object keys under *prefix*, sorted by name (oldest first)."""

    @abstractmethod
    def delete(self, path: str) -> None:
        """Delete the object at *path*."""


# -- FileSystem Adapter --------------------------------------------------------

class FileSystemDeadDrop(CloudStorageAdapter):
    """Cloud storage adapter backed by the local filesystem.

    Perfect for testing and air-gapped networks where nodes share a
    mounted volume or directory.
    """

    def __init__(self, base_path: str) -> None:
        self._base = Path(base_path).resolve()
        self._base.mkdir(parents=True, exist_ok=True)

    def _safe_resolve(self, path: str) -> Path:
        """Resolve *path* within base and reject traversal escapes."""
        full = (self._base / path).resolve()
        if not str(full).startswith(str(self._base)):
            raise DeadDropError(f"path traversal blocked: {path}")
        return full

    def write(self, path: str, data: bytes) -> None:
        full = self._safe_resolve(path)
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data)

    def read(self, path: str) -> bytes:
        full = self._safe_resolve(path)
        if not full.exists():
            raise DeadDropError(f"not found: {path}")
        return full.read_bytes()

    def list_objects(self, prefix: str) -> List[str]:
        target = self._safe_resolve(prefix)
        if not target.exists():
            return []
        items = []
        for p in target.iterdir():
            if p.is_file():
                items.append(str(p.relative_to(self._base)))
        items.sort()
        return items

    def delete(self, path: str) -> None:
        full = self._safe_resolve(path)
        if full.exists():
            full.unlink()


# -- S3 Adapter ----------------------------------------------------------------

class S3DeadDrop(CloudStorageAdapter):
    """S3-compatible storage adapter using urllib + AWS Signature V4.

    No boto3 dependency.  Supports any S3-compatible endpoint
    (AWS, MinIO, DigitalOcean Spaces, etc.).
    """

    def __init__(
        self,
        bucket: str,
        region: str = "us-east-1",
        access_key: str = "",
        secret_key: str = "",
        endpoint: str = "",
    ) -> None:
        self._bucket = bucket
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._endpoint = endpoint or f"https://{bucket}.s3.{region}.amazonaws.com"
        self._service = "s3"

    def _sign_v4(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        payload: bytes = b"",
    ) -> Dict[str, str]:
        """Generate AWS Signature V4 headers."""
        now = datetime.datetime.now(datetime.UTC)
        datestamp = now.strftime("%Y%m%d")
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")

        headers["x-amz-date"] = amz_date
        payload_hash = hashlib.sha256(payload).hexdigest()
        headers["x-amz-content-sha256"] = payload_hash

        # Canonical request
        canonical_uri = urlquote(path, safe="/")
        canonical_querystring = ""
        signed_header_keys = sorted(headers.keys())
        canonical_headers = "".join(
            f"{k.lower()}:{headers[k].strip()}\n" for k in signed_header_keys
        )
        signed_headers = ";".join(k.lower() for k in signed_header_keys)
        canonical_request = (
            f"{method}\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        # String to sign
        credential_scope = f"{datestamp}/{self._region}/{self._service}/aws4_request"
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            + hashlib.sha256(canonical_request.encode()).hexdigest()
        )

        # Signing key
        def _hmac_sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()

        k_date = _hmac_sign(f"AWS4{self._secret_key}".encode(), datestamp)
        k_region = _hmac_sign(k_date, self._region)
        k_service = _hmac_sign(k_region, self._service)
        k_signing = _hmac_sign(k_service, "aws4_request")

        signature = hmac.new(
            k_signing, string_to_sign.encode(), hashlib.sha256
        ).hexdigest()

        headers["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self._access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return headers

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[bytes] = None,
    ) -> bytes:
        url = f"{self._endpoint}/{path}"
        headers = {"Host": self._endpoint.split("//", 1)[-1].split("/")[0]}
        if data is not None:
            headers["Content-Length"] = str(len(data))

        headers = self._sign_v4(method, f"/{path}", headers, data or b"")
        req = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(req, timeout=30) as resp:
                return resp.read()
        except URLError as exc:
            raise DeadDropError(f"S3 {method} {path} failed: {exc}") from exc

    def write(self, path: str, data: bytes) -> None:
        self._request("PUT", path, data)

    def read(self, path: str) -> bytes:
        return self._request("GET", path)

    def list_objects(self, prefix: str) -> List[str]:
        # Use list-type=2 API
        import xml.etree.ElementTree as ET
        url = f"{self._endpoint}/?list-type=2&prefix={urlquote(prefix, safe='')}"
        headers = {"Host": self._endpoint.split("//", 1)[-1].split("/")[0]}
        headers = self._sign_v4("GET", "/", headers)
        req = Request(url, headers=headers, method="GET")
        try:
            with urlopen(req, timeout=30) as resp:
                body = resp.read()
            root = ET.fromstring(body)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            keys = []
            for content in root.findall(".//s3:Contents/s3:Key", ns):
                if content.text:
                    keys.append(content.text)
            # Fallback: try without namespace
            if not keys:
                for content in root.iter():
                    if content.tag.endswith("Key") and content.text:
                        keys.append(content.text)
            keys.sort()
            return keys
        except (URLError, ET.ParseError) as exc:
            raise DeadDropError(f"S3 list failed: {exc}") from exc

    def delete(self, path: str) -> None:
        self._request("DELETE", path)


# -- Dead Drop Transport Backend -----------------------------------------------

class DeadDropBackend:
    """TransportBackend implementation over cloud storage dead-drops.

    Each node has a mailbox:
        {prefix}/{node_id}/inbox/   — incoming messages
        {prefix}/{node_id}/outbox/  — sent messages (optional tracking)

    To send to node B, node A writes to B's inbox.
    To receive, a node polls its own inbox.
    """

    def __init__(
        self,
        config: DeadDropConfig,
        local_node_id: str,
        remote_node_id: str,
        adapter: Optional[CloudStorageAdapter] = None,
    ) -> None:
        self._config = config
        self._local_id = local_node_id
        self._remote_id = remote_node_id
        self._prefix = config.prefix

        # Create adapter
        if adapter is not None:
            self._adapter = adapter
        elif config.provider == CloudProvider.FILESYSTEM:
            self._adapter = FileSystemDeadDrop(config.base_path)
        elif config.provider == CloudProvider.S3:
            self._adapter = S3DeadDrop(
                bucket=config.bucket_name,
                region=config.credentials.get("region", "us-east-1"),
                access_key=config.credentials.get("access_key", ""),
                secret_key=config.credentials.get("secret_key", ""),
                endpoint=config.credentials.get("endpoint", ""),
            )
        else:
            raise DeadDropError(f"unsupported provider: {config.provider.value}")

        # Receive buffer
        self._recv_buffer = bytearray()
        self._recv_lock = threading.Lock()
        self._connected = True

        # Background poller
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_running = False
        self._start_poller()

    def _inbox_path(self, node_id: str) -> str:
        return f"{self._prefix}/{node_id}/inbox"

    def _start_poller(self) -> None:
        self._poll_running = True
        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="dead-drop-poller",
        )
        self._poll_thread.start()

    def _poll_loop(self) -> None:
        while self._poll_running:
            try:
                self._poll_inbox()
            except Exception as exc:
                logger.debug("dead-drop poll error: %s", exc)
            time.sleep(self._config.poll_interval)

    def _poll_inbox(self) -> None:
        """Check inbox for new messages and buffer them."""
        inbox = self._inbox_path(self._local_id)
        try:
            objects = self._adapter.list_objects(inbox)
        except DeadDropError:
            return

        now = time.time()
        for obj_key in objects:
            try:
                data = self._adapter.read(obj_key)
                with self._recv_lock:
                    self._recv_buffer.extend(data)
                self._adapter.delete(obj_key)
            except DeadDropError as exc:
                logger.debug("failed to read dead-drop message: %s", exc)

    # -- TransportBackend Protocol ---------------------------------------------

    def send_bytes(self, data: bytes) -> None:
        """Write data to the remote node's inbox."""
        if not self._connected:
            raise DeadDropError("transport closed")
        msg_id = f"{time.time():.6f}_{uuid.uuid4().hex[:8]}"
        path = f"{self._inbox_path(self._remote_id)}/{msg_id}.bin"
        self._adapter.write(path, data)

    def recv_bytes(self, n: int) -> bytes:
        """Read exactly n bytes from the receive buffer, blocking until available."""
        if not self._connected:
            raise DeadDropError("transport closed")
        deadline = time.time() + 60.0  # 60s timeout
        while time.time() < deadline:
            with self._recv_lock:
                if len(self._recv_buffer) >= n:
                    result = bytes(self._recv_buffer[:n])
                    del self._recv_buffer[:n]
                    return result
            if not self._connected:
                raise DeadDropError("transport closed")
            time.sleep(0.1)
        raise DeadDropError(f"recv timeout waiting for {n} bytes")

    def close(self) -> None:
        """Stop polling and close the transport."""
        self._connected = False
        self._poll_running = False
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5.0)

    @property
    def peer_address(self) -> str:
        return f"dead-drop:{self._remote_id}"

    @property
    def transport_name(self) -> str:
        return "dead-drop"

    @property
    def is_connected(self) -> bool:
        return self._connected
