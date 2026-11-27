. /lab/image/lib.sh
# r1: AlmaLinux 9 (spec 8.2). sshd reads both files, as on Debian; authorized_keys2 belongs to root (0600),
# so neither sshd nor SSHBITE (reading as alice) can read it: "unreadable by account" (spec 7.4).
printf 'AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n' >> /etc/ssh/sshd_config.d/lab.conf
mkuser alice; sshdir alice
put /home/alice/.ssh/authorized_keys alice 600
put /home/alice/.ssh/known_hosts alice 644
privkey k_alice /home/alice/.ssh/id_ed25519 alice 600
put /home/alice/.ssh/authorized_keys2 root 600
