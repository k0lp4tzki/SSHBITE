# SSHBITE documentation

| Page | Contents |
|---|---|
| [install.md](install.md) | Install with pip or Docker; create and deploy the audit key and account; sudoers; pin the entry host key; first scan and login |
| [configuration.md](configuration.md) | Every config key with its default and meaning; environment variables |
| [scanning.md](scanning.md) | What a scan does; crawl scope; seeds; `--ask-sudo-password`; host statuses; exit codes |
| [operations.md](operations.md) | systemd units for the UI and a nightly scan; Docker operation; UI logins; backup, restore, update |
| [cleanup.md](cleanup.md) | The cleanup workflow: findings → CSV worklist → remove → rescan → diff |
| [review.md](review.md) | Read-only review guide: what is sent to targets, `sshbite collector show`, what the allowlist lint guarantees |
| [side-effects.md](side-effects.md) | Logs, sudo "incident" mails, access times and monitoring alerts a scan causes – read before the first real scan |
| [compose.example.yaml](compose.example.yaml) | Docker Compose file for running SSHBITE |
| [systemd/](systemd/) | `sshbite-serve.service`, `sshbite-scan.service` + `.timer`, `sshbite-scan-docker.service` |
| [development.md](development.md) | Test lab, tests and CI |
