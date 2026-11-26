# SSHBITE test lab host (spec 9.2). One image per host, selected by build arg HOST.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_*
ARG HOST
# test-only keys (see lab/keys/README.md) and the lab helpers; nothing here is under /etc, /root or /home
COPY keys/ /lab/keys/
COPY image/lib.sh image/entrypoint.sh image/ctl_sshd_config /lab/image/
COPY seed/${HOST}/ /lab/seed/
RUN sh /lab/image/lib.sh common "${HOST}" && sh /lab/seed/setup.sh && sh /lab/image/lib.sh finish "${HOST}"
EXPOSE 22 2200
ENTRYPOINT ["/bin/sh", "/lab/image/entrypoint.sh"]
