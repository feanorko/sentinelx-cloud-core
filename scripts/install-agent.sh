#!/usr/bin/env bash
set -euo pipefail

PREFIX="/opt/sentinelx-cloud-core"
CONFIG="/etc/sentinelx/config.yaml"
IDENTITY="/etc/sentinelx/identity.json"
SERVICE="sentinelx-core"
RUN_USER="sentinelx"
RUN_GROUP="sentinelx"
VENV=""
VENV_EXPLICIT=0
COMMAND_PRIVATE_KEY="/etc/sentinelx/keys/command-private.pem"
RESPONSE_PUBLIC_KEY="/etc/sentinelx/keys/response-public.pem"
INSTALL_DEPS=1
ENABLE=0
START=0
AUDIT_DIR="/var/log/sentinelx"

usage() {
  cat <<'EOF'
Usage: install-agent.sh [options]

Install this checkout as an independent SentinelX agent instance.

Options:
  --prefix PATH       Installation directory (default: /opt/sentinelx-cloud-core)
  --config PATH       Agent config path (default: /etc/sentinelx/config.yaml)
  --identity PATH     Agent identity path (default: /etc/sentinelx/identity.json)
  --service NAME      systemd unit name (default: sentinelx-core)
  --user NAME         Service user (default: sentinelx)
  --group NAME        Service group (default: sentinelx)
  --venv PATH         Python virtualenv path (default: PREFIX/venv)
  --command-private-key PATH  X25519 private key for decrypting commands
  --response-public-key PATH  X25519 public key for encrypting responses
  --no-deps           Do not install Python dependencies
  --enable            Enable the systemd service
  --start             Start the systemd service
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --service) SERVICE="$2"; shift 2 ;;
    --user) RUN_USER="$2"; shift 2 ;;
    --group) RUN_GROUP="$2"; shift 2 ;;
    --venv) VENV="$2"; VENV_EXPLICIT=1; shift 2 ;;
    --command-private-key) COMMAND_PRIVATE_KEY="$2"; shift 2 ;;
    --response-public-key) RESPONSE_PUBLIC_KEY="$2"; shift 2 ;;
    --no-deps) INSTALL_DEPS=0; shift ;;
    --enable) ENABLE=1; shift ;;
    --start) START=1; ENABLE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ $VENV_EXPLICIT -eq 0 ]]; then
  VENV="${PREFIX}/venv"
fi

if [[ "$(uname -s)" != "Linux" ]] || ! command -v systemctl >/dev/null 2>&1; then
  echo "This installer currently supports systemd Linux only." >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= 3.11 else 1)' || {
  echo "Python 3.11+ is required" >&2
  exit 1
}

getent group "$RUN_GROUP" >/dev/null || groupadd --system "$RUN_GROUP"
if ! getent passwd "$RUN_USER" >/dev/null; then
  useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin --gid "$RUN_GROUP" "$RUN_USER"
else
  usermod --gid "$RUN_GROUP" "$RUN_USER"
fi

mkdir -p "$PREFIX"
cp -a "$SRC_DIR/." "$PREFIX/"
rm -rf "$PREFIX/.git" "$PREFIX/venv"

python3 -m venv "$VENV"
if [[ $INSTALL_DEPS -eq 1 ]]; then
  "$VENV/bin/python" -m pip install --upgrade pip
  "$VENV/bin/pip" install "$PREFIX"
fi

chown -R "$RUN_USER:$RUN_GROUP" "$PREFIX"
chmod 0755 "$PREFIX"

if [[ ! -f "$IDENTITY" ]]; then
  echo "WARNING: identity file does not exist yet: $IDENTITY" >&2
  echo "Create/enroll the identity before starting this service." >&2
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "WARNING: config file does not exist yet: $CONFIG" >&2
fi

# Prepare host-local E2E audit files. The service account may append to the
# files, but it must not be able to remove/replace them or truncate history.
mkdir -p "$AUDIT_DIR"
touch "$AUDIT_DIR/crypto-wire-audit.jsonl" "$AUDIT_DIR/crypto-plaintext-audit.jsonl"
chown root:"$RUN_GROUP" "$AUDIT_DIR/crypto-wire-audit.jsonl" "$AUDIT_DIR/crypto-plaintext-audit.jsonl"
chmod 0620 "$AUDIT_DIR/crypto-wire-audit.jsonl" "$AUDIT_DIR/crypto-plaintext-audit.jsonl"
chown root:root "$AUDIT_DIR"
chmod 0755 "$AUDIT_DIR"
if command -v chattr >/dev/null 2>&1; then
  chattr +a "$AUDIT_DIR/crypto-wire-audit.jsonl" "$AUDIT_DIR/crypto-plaintext-audit.jsonl"
else
  echo "WARNING: chattr is unavailable; audit files cannot be made append-only." >&2
fi

UNIT="/etc/systemd/system/${SERVICE}.service"
cat > "$UNIT" <<EOF
[Unit]
Description=SentinelX Core agent (${SERVICE})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
ExecStart=${VENV}/bin/sentinelx-cloud-core --identity ${IDENTITY} --config ${CONFIG} --command-private-key ${COMMAND_PRIVATE_KEY} --response-public-key ${RESPONSE_PUBLIC_KEY}
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
LogsDirectory=sentinelx
ReadWritePaths=/var/log/sentinelx

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

if [[ $ENABLE -eq 1 ]]; then
  systemctl enable "$SERVICE"
fi
if [[ $START -eq 1 ]]; then
  systemctl restart "$SERVICE"
fi

echo "Installed SentinelX agent instance:"
echo "  prefix:   $PREFIX"
echo "  venv:     $VENV"
echo "  service:  $SERVICE"
echo "  user:     $RUN_USER"
echo "  config:   $CONFIG"
echo "  identity: $IDENTITY"
echo "  command private key: $COMMAND_PRIVATE_KEY"
echo "  response public key:  $RESPONSE_PUBLIC_KEY"
echo "  E2E audit: $AUDIT_DIR (append-only)"
