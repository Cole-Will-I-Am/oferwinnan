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
import logging
import os
import socket
import sys
import time

from matrix.device_discovery import Device, Transport, DiscoveryManager
from matrix.session_jumper import (
    JumpNode, JumpSession, restore_session, JumpError,
    MultiJumpStrategy, MultiJumpResult, TargetResult,
)

logger = logging.getLogger(__name__)


def cmd_listen(args):
    """Start a jump listener, waiting for incoming sessions."""
    def on_session(session: JumpSession):
        logger.info(f"\n[RECEIVED] Session '{session.session_id}' from {session.source_device}")
        logger.info(f"  Timestamp: {time.ctime(session.timestamp)}")
        logger.info(f"  Source CWD: {session.cwd}")
        logger.info(f"  Files: {len(session.files)}")
        logger.info(f"  Metadata: {json.dumps(session.metadata, indent=2)}")
        if session.files:
            restore = input("  Restore files to current directory? [y/N] ").strip().lower()
            if restore == "y":
                restore_session(session, restore_files=True)
                logger.info("  Files restored.")

    node = JumpNode(
        node_name=args.name or socket.gethostname(),
        listen_port=args.port,
        auth_token=args.token,
        on_session_received=on_session,
    )
    node.start()
    logger.info(f"Jump node '{node.node_name}' listening on port {args.port}")
    logger.info(f"Node ID: {node.discovery.node_id}")
    if args.token:
        logger.info("Authentication: enabled")
    logger.info("Waiting for incoming jumps... (Ctrl+C to stop)\n")

    try:
        while True:
            devices = node.discover_targets()
            if devices:
                logger.info(f"[{time.strftime('%H:%M:%S')}] Nearby devices: {len(devices)}")
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        node.stop()


def cmd_discover(args):
    """Scan for nearby devices on WiFi and Bluetooth."""
    logger.info("Scanning for nearby devices...")
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
                    logger.info(f"  [{dev.transport.value.upper():9s}] {dev.name:20s}  {dev.address}:{dev.port}  caps={dev.capabilities}")
            remaining = int(deadline - time.time())
            logger.info(f"  Scanning... {remaining}s remaining, {len(seen)} device(s) found")
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    dm.stop()
    logger.info(f"\n\nDiscovery complete. Found {len(seen)} device(s).")
    return list(seen)


def cmd_jump(args):
    """Jump to a target device, transferring current session."""
    node = JumpNode(
        listen_port=args.port,
        auth_token=args.token,
    )
    node.start()
    logger.info(f"Resolving target '{args.target}'...")

    # Allow target to be an IP:port or a discovered device name
    target = _resolve_target(args.target, node, timeout=5)
    if not target:
        logger.error(f"Error: Could not find device '{args.target}'")
        logger.info("Tip: Use 'jump_cli.py discover' to find nearby devices,")
        logger.info("     or specify an IP:PORT directly (e.g. 192.168.1.50:47701)")
        node.stop()
        sys.exit(1)

    logger.info(f"Jumping to {target.name} ({target.address}:{target.port})...")

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
            logger.info("Jump successful! Session transferred.")
        else:
            logger.warning("Jump completed but receiver reported an issue.")
    except JumpError as e:
        logger.error(f"Jump failed: {e}")
        sys.exit(1)
    finally:
        node.stop()


def cmd_multiply(args):
    """Multiply/duplicate the session to multiple targets simultaneously."""
    node = JumpNode(
        listen_port=args.port,
        auth_token=args.token,
    )
    node.start()

    strategy = MultiJumpStrategy(args.strategy)

    # Resolve targets
    if args.all:
        logger.info("Discovering all nearby devices...")
        time.sleep(min(args.discovery_timeout, 10))
        targets = node.discover_targets()
        if not targets:
            logger.error("No devices found on the network.")
            node.stop()
            sys.exit(1)
        logger.info(f"Found {len(targets)} device(s)")
    elif args.targets:
        targets = []
        for t in args.targets:
            dev = _resolve_target(t, node, timeout=5)
            if dev:
                targets.append(dev)
            else:
                logger.warning(f"Could not resolve target '{t}', skipping")
        if not targets:
            logger.error("No valid targets resolved.")
            node.stop()
            sys.exit(1)
    else:
        logger.error("Specify --targets or --all")
        node.stop()
        sys.exit(1)

    logger.info(f"Strategy: {strategy.value.upper()}")
    logger.info(f"Targets:  {len(targets)}")
    for dev in targets:
        logger.info(f"  - {dev.name} ({dev.address}:{dev.port})")

    files = args.files or []
    metadata = {"jump_reason": args.reason} if args.reason else {}

    def on_progress(tr: TargetResult, done: int, total: int):
        status = "OK" if tr.success else f"FAIL ({tr.error})"
        retries = f" (retries: {tr.retries})" if tr.retries else ""
        logger.info(
            f"  [{done}/{total}] {tr.device.name}: {status} "
            f"({tr.elapsed:.2f}s){retries}"
        )

    try:
        result = node.multi_jump(
            targets=targets,
            strategy=strategy,
            include_env=not args.no_env,
            include_files=files,
            extra_metadata=metadata,
            max_retries=args.retries,
            on_progress=on_progress,
        )
        logger.info(f"\n{result.summary()}")
        if not result.any_ok:
            sys.exit(1)
    except JumpError as e:
        logger.error(f"Multiply failed: {e}")
        sys.exit(1)
    finally:
        node.stop()


def cmd_status(args):
    """Show the status of this node."""
    discovery = DiscoveryManager(node_name=args.name or socket.gethostname(), listen_port=args.port)
    logger.info(f"Hostname: {socket.gethostname()}")
    logger.info(f"Node ID:  {discovery.node_id}")
    logger.info(f"Platform: {sys.platform}")
    logger.info(f"CWD:      {os.getcwd()}")

    # Quick network check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        logger.info(f"Local IP: {local_ip}")
    except OSError:
        logger.warning("Local IP: unavailable")

    # Bluetooth check
    try:
        import bluetooth  # noqa: F401
        logger.info("Bluetooth: available")
    except ImportError:
        logger.info("Bluetooth: not available (install PyBluez for BT support)")


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
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(
        prog="matrix",
        description="Cross-device session jumping via Bluetooth and WiFi",
    )
    parser.add_argument("--port", type=int, default=47701,
                        help="Listen/connect port (default: 47701)",
                        metavar="PORT")
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

    # multiply (multi-target jump)
    p_multi = sub.add_parser("multiply",
                             help="Duplicate session to multiple targets")
    p_multi.add_argument("--targets", nargs="*",
                         help="Target devices (IP:PORT or names)")
    p_multi.add_argument("--all", action="store_true",
                         help="Jump to all discovered devices")
    p_multi.add_argument("--strategy", default="broadcast",
                         choices=["broadcast", "mirror", "race", "cascade"],
                         help="Dispatch strategy (default: broadcast)")
    p_multi.add_argument("--files", nargs="*", help="Files to include")
    p_multi.add_argument("--no-env", action="store_true",
                         help="Don't transfer environment variables")
    p_multi.add_argument("--reason", type=str, help="Jump reason metadata")
    p_multi.add_argument("--retries", type=int, default=0,
                         help="Per-target retry count (default: 0)")
    p_multi.add_argument("--discovery-timeout", type=int, default=5,
                         help="Seconds to wait for device discovery (default: 5)")

    # status
    p_status = sub.add_parser("status", help="Show node status")

    # rain
    p_rain = sub.add_parser("rain", help="Matrix digital rain")
    p_rain.add_argument("--instrumented", action="store_true",
                        help="Show live mirror_blend stats overlay")

    # config
    p_config = sub.add_parser("config", help="Show loaded configuration")

    args = parser.parse_args()

    # Validate port range
    if not (1 <= args.port <= 65535):
        parser.error(f"Port must be between 1 and 65535, got {args.port}")

    # Clamp discovery timeout if present
    if hasattr(args, "timeout") and args.timeout is not None:
        args.timeout = max(1, min(args.timeout, 300))
    if hasattr(args, "discovery_timeout") and args.discovery_timeout is not None:
        args.discovery_timeout = max(1, min(args.discovery_timeout, 300))

    commands = {
        "listen": cmd_listen,
        "discover": cmd_discover,
        "jump": cmd_jump,
        "multiply": cmd_multiply,
        "status": cmd_status,
        "rain": cmd_rain,
        "config": cmd_config,
    }
    commands[args.command](args)


def cmd_rain(args):
    """Launch the Matrix digital rain."""
    if not sys.stdout.isatty():
        logger.error("rain requires a real terminal.")
        sys.exit(1)
    from matrix.gut_check import MatrixRain, InstrumentedRain
    if args.instrumented:
        engine = InstrumentedRain()
    else:
        engine = MatrixRain()
    engine.run()


def cmd_config(args):
    """Show the current loaded configuration."""
    from matrix.config import config
    from dataclasses import fields
    for f in fields(config):
        value = getattr(config, f.name)
        if f.name == "auth_token" and value:
            value = value[:4] + "****"
        logger.info(f"  {f.name:25s} = {value}")


if __name__ == "__main__":
    main()
