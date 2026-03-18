#!/usr/bin/env python3
"""
Jump CLI — Command-line interface for cross-device jumping.

Usage:
    python jump_cli.py listen [--port PORT] [--token TOKEN]
    python jump_cli.py discover [--timeout SECONDS]
    python jump_cli.py jump <target> [--files FILE ...] [--token TOKEN]
    python jump_cli.py send-file <target> <filepath> [--token TOKEN]
"""

import argparse
import json
import os
import signal
import socket
import sys
import time
import uuid

from device_discovery import Device, Transport, DiscoveryManager
from session_jumper import (
    JumpNode, JumpSession, capture_session, restore_session, JumpError,
)


def cmd_listen(args):
    """Start a jump listener, waiting for incoming sessions."""
    def on_session(session: JumpSession):
        print(f"\n[RECEIVED] Session '{session.session_id}' from {session.source_device}")
        print(f"  Timestamp: {time.ctime(session.timestamp)}")
        print(f"  Source CWD: {session.cwd}")
        print(f"  Files: {len(session.files)}")
        print(f"  Metadata: {json.dumps(session.metadata, indent=2)}")
        if session.files:
            restore = input("  Restore files to current directory? [y/N] ").strip().lower()
            if restore == "y":
                restore_session(session, restore_files=True)
                print("  Files restored.")

    node = JumpNode(
        node_name=args.name or socket.gethostname(),
        listen_port=args.port,
        auth_token=args.token,
        on_session_received=on_session,
    )
    node.start()
    print(f"Jump node '{node.node_name}' listening on port {args.port}")
    print(f"Node ID: {node.discovery.node_id}")
    if args.token:
        print("Authentication: enabled")
    print("Waiting for incoming jumps... (Ctrl+C to stop)\n")

    try:
        while True:
            devices = node.discover_targets()
            if devices:
                print(f"\r[{time.strftime('%H:%M:%S')}] "
                      f"Nearby devices: {len(devices)}", end="", flush=True)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nShutting down...")
        node.stop()


def cmd_discover(args):
    """Scan for nearby devices on WiFi and Bluetooth."""
    print("Scanning for nearby devices...")
    dm = DiscoveryManager(listen_port=args.port)
    dm.start()

    deadline = time.time() + args.timeout
    seen = set()
    try:
        while time.time() < deadline:
            devices = dm.get_all_devices()
            for dev in devices:
                if dev.device_id not in seen:
                    seen.add(dev.device_id)
                    print(f"  [{dev.transport.value.upper():9s}] "
                          f"{dev.name:20s}  {dev.address}:{dev.port}  "
                          f"caps={dev.capabilities}")
            remaining = int(deadline - time.time())
            print(f"\r  Scanning... {remaining}s remaining, "
                  f"{len(seen)} device(s) found", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    dm.stop()
    print(f"\n\nDiscovery complete. Found {len(seen)} device(s).")
    return list(seen)


def cmd_jump(args):
    """Jump to a target device, transferring current session."""
    node = JumpNode(
        listen_port=args.port,
        auth_token=args.token,
    )
    node.start()
    print(f"Resolving target '{args.target}'...")

    # Allow target to be an IP:port or a discovered device name
    target = _resolve_target(args.target, node, timeout=5)
    if not target:
        print(f"Error: Could not find device '{args.target}'")
        print("Tip: Use 'jump_cli.py discover' to find nearby devices,")
        print("     or specify an IP:PORT directly (e.g. 192.168.1.50:47701)")
        node.stop()
        sys.exit(1)

    print(f"Jumping to {target.name} ({target.address}:{target.port})...")

    files = args.files or []
    metadata = {"jump_reason": args.reason} if args.reason else {}

    try:
        success = node.jump(
            target=target,
            include_env=not args.no_env,
            include_files=files,
            extra_metadata=metadata,
        )
        if success:
            print("Jump successful! Session transferred.")
        else:
            print("Jump completed but receiver reported an issue.")
    except JumpError as e:
        print(f"Jump failed: {e}")
        sys.exit(1)
    finally:
        node.stop()


def cmd_status(args):
    """Show the status of this node."""
    print(f"Hostname: {socket.gethostname()}")
    print(f"Node ID:  {uuid.uuid4().hex[:16]}")
    print(f"Platform: {sys.platform}")
    print(f"CWD:      {os.getcwd()}")

    # Quick network check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"Local IP: {local_ip}")
    except OSError:
        print("Local IP: unavailable")

    # Bluetooth check
    try:
        import bluetooth  # noqa: F401
        print("Bluetooth: available")
    except ImportError:
        print("Bluetooth: not available (install PyBluez for BT support)")


def _resolve_target(target_str: str, node: JumpNode,
                    timeout: float = 5) -> Device | None:
    """Resolve a target string to a Device. Accepts IP:PORT or device name."""
    # Direct IP:PORT
    if ":" in target_str:
        parts = target_str.rsplit(":", 1)
        try:
            port = int(parts[1])
            return Device(
                device_id="direct",
                name=target_str,
                address=parts[0],
                transport=Transport.WIFI,
                port=port,
                last_seen=time.time(),
            )
        except ValueError:
            pass

    # Search via discovery
    deadline = time.time() + timeout
    while time.time() < deadline:
        for dev in node.discover_targets():
            if (dev.name.lower() == target_str.lower() or
                    dev.device_id == target_str or
                    dev.address == target_str):
                return dev
        time.sleep(0.5)
    return None


def main():
    parser = argparse.ArgumentParser(
        prog="jump",
        description="Cross-device session jumping via Bluetooth and WiFi",
    )
    parser.add_argument("--port", type=int, default=47701,
                        help="Listen/connect port (default: 47701)")
    parser.add_argument("--token", type=str, default=None,
                        help="Authentication token for secure jumps")
    parser.add_argument("--name", type=str, default=None,
                        help="Node name (default: hostname)")

    sub = parser.add_subparsers(dest="command", required=True)

    # listen
    p_listen = sub.add_parser("listen", help="Listen for incoming jumps")

    # discover
    p_discover = sub.add_parser("discover", help="Discover nearby devices")
    p_discover.add_argument("--timeout", type=int, default=10,
                            help="Scan duration in seconds (default: 10)")

    # jump
    p_jump = sub.add_parser("jump", help="Jump to a target device")
    p_jump.add_argument("target", help="Target device (IP:PORT or name)")
    p_jump.add_argument("--files", nargs="*", help="Files to include")
    p_jump.add_argument("--no-env", action="store_true",
                        help="Don't transfer environment variables")
    p_jump.add_argument("--reason", type=str, help="Jump reason metadata")

    # status
    p_status = sub.add_parser("status", help="Show node status")

    args = parser.parse_args()

    commands = {
        "listen": cmd_listen,
        "discover": cmd_discover,
        "jump": cmd_jump,
        "status": cmd_status,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
