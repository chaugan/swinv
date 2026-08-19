#!/bin/sh
# Runs as dpkg postrm and rpm %postun.
# Reload units so systemd forgets the removed ones. Inventory files under
# /var/lib/swinv are deliberately left alone: they are collected data, and
# deleting a fleet's inventory history on package removal would be hostile.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
