#!/bin/sh
# Runs as dpkg postinst ("configure") and as rpm %post (1 = install, 2 = upgrade).
set -e

# Only meaningful under systemd; a container or chroot may have none.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Detect a first install rather than an upgrade, across both packagers.
is_first_install() {
    case "$1" in
        configure)
            # dpkg passes the previously-configured version as $2; empty means new.
            [ -z "$2" ] && return 0 || return 1
            ;;
        1) return 0 ;;   # rpm install
        *) return 1 ;;
    esac
}

if is_first_install "$@"; then
    cat <<'MSG'
swinv is installed. The daily timer is shipped but NOT enabled, because a
scheduled filesystem-wide scan should be an explicit choice:

    systemctl enable --now swinv.timer

Run one scan now:

    swinv --out /var/lib/swinv

Documentation: man 8 swinv, /usr/share/doc/swinv/README.md
MSG
fi

exit 0
