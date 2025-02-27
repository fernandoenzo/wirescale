#!/bin/sh

set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" 1>&2
  exec sudo sh "$0" "$@"
fi

PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install wirescale || true

UNIT='wirescaled'
SERVICE="$UNIT.service"
SOCKET="$UNIT.socket"

systemctl stop "$SERVICE" > /dev/null 2>&1 || true
systemctl stop "$SOCKET" > /dev/null 2>&1 || true
systemctl disable "$SERVICE" > /dev/null 2>&1 || true
systemctl disable "$SOCKET" > /dev/null 2>&1 || true
rm -rf "/etc/systemd/system/$SERVICE" > /dev/null 2>&1 || true
rm -rf "/etc/systemd/system/$SOCKET" > /dev/null 2>&1 || true
rm -rf "/etc/bash_completion.d/wirescale-completion" > /dev/null 2>&1 || true
systemctl daemon-reload

PYTHON_DIR=$(find /opt/pipx/venvs/wirescale/lib -name 'python*' -type d)
ln -s "$PYTHON_DIR/site-packages/wirescale/systemd/$SOCKET" "/etc/systemd/system/"
ln -s "$PYTHON_DIR/site-packages/wirescale/systemd/$SERVICE" "/etc/systemd/system/"
ln -s "$PYTHON_DIR/site-packages/wirescale/scripts/wirescale-completion" "/etc/bash_completion.d/"
systemctl daemon-reload

systemctl enable "$SOCKET" "$SERVICE"
systemctl start "$SERVICE"

echo "Success! Wirescale has been installed"
