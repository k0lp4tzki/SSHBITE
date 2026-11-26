#!/bin/sh
# Read-only snapshot of a lab host (spec 9.2): metadata and SHA-256 of everything under /etc, /root, /home.
# Run as root inside the host: docker exec <c> sh -s < lab/snapshot.sh  (or via the lab-control sshd).
LC_ALL=C; export LC_ALL
find /etc /root /home -xdev -printf '%p %m %U %G %s %T@\n' 2>/dev/null | sort
find /etc /root /home -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum
