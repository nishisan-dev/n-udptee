#!/bin/sh
# Never run the laboratory in the host mount/network namespace.
set -eu
if [ "${N_UDPTEE_LAB_ISOLATED:-}" != 1 ]; then
    if [ "$(id -u)" = 0 ]; then
        exec unshare --mount --net sh -c '
            mount --make-rprivate /
            mount -t tmpfs tmpfs /run
            mkdir -p /run/netns
            export N_UDPTEE_LAB_ISOLATED=1
            exec "$@"
        ' sh "$0" "$@"
    fi
    # Ambient capabilities survive exec without pretending to be uid 0. This
    # also lets tcpdump run without setgroups, denied in unprivileged userns.
    exec unshare --user --map-current-user --keep-caps --mount --net sh -c '
        mount --make-rprivate /
        mount -t tmpfs tmpfs /run
        mkdir -p /run/netns
        export N_UDPTEE_LAB_ISOLATED=1
        exec "$@"
    ' sh "$0" "$@"
fi
exec python3 "$(dirname "$0")/lab.py" "$@"
