#!/bin/sh
# Runs as dpkg prerm ("remove"/"upgrade"/...) and rpm %preun (0 = remove, 1 = upgrade).
# Stop and disable the timer only on a real removal, never on an upgrade —
# disabling on upgrade would silently switch off a working daily inventory.
set -e

case "$1" in
    remove|purge|0)
        if [ -d /run/systemd/system ]; then
            systemctl --no-reload disable --now swinv.timer >/dev/null 2>&1 || true
            systemctl stop swinv.service >/dev/null 2>&1 || true
        fi
        ;;
esac

exit 0
