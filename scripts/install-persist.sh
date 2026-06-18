#!/usr/bin/env bash
# Install Matrix persistence using the preferred Linux mechanisms.
# Usage: sudo ./scripts/install-persist.sh [command]

set -euo pipefail

COMMAND="${1:-matrix listen}"

if command -v matrix >/dev/null 2>&1; then
    :
else
    echo "matrix command not found in PATH; install the package first (pip install -e .)" >&2
    exit 1
fi

if [[ $EUID -eq 0 ]]; then
    echo "Installing persistence as root: systemd-system, cron, rc-local"
    matrix persist enable systemd-system cron rc-local --command "$COMMAND"
else
    echo "Installing persistence as user: systemd-user, bashrc-alias"
    matrix persist enable systemd-user bashrc-alias --command "$COMMAND"
fi

echo ""
echo "Current persistence status:"
matrix persist status
