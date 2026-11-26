#!/bin/sh
# Lab container start: the lab-control sshd (port 2200, test harness only) and the real sshd on 22.
mkdir -p /run/sshd
/usr/sbin/sshd -f /lab/ctl/sshd_config -E /run/labctl-sshd.log
exec /usr/sbin/sshd -D -e
