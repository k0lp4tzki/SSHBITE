<a id="sshbite-documentation"></a>

# SSHBITE-Dokumentation

| Seite | Inhalt |
|---|---|
| [install.md](install.md) | Installation mit Docker oder pip; Zielhosts vorbereiten (installierter Collector); Host-Key des Einstiegshosts festlegen; erster Scan; Aktualisierung; Deinstallation; Fehlerbehebung |
| [rollout.md](rollout.md) | Einrichtung mit einem Skript: `sshbite-rollout` prüft, plant, richtet Scanner-Rechner und Hosts ein und prüft das Ergebnis; frei wählbarer Name des Audit-Kontos; Scanner-Rechner zugleich Einstiegshost |
| [configuration.md](configuration.md) | Jeder Konfigurationsschlüssel mit Standardwert und Bedeutung; Umgebungsvariablen |
| [scanning.md](scanning.md) | Was ein Scan tut; Umfang des Crawls; Seeds; `--ask-sudo-password` (Legacy-Modus); Host-Status; Exit-Codes |
| [operations.md](operations.md) | systemd-Units für die Oberfläche und einen nächtlichen Scan; Reverse Proxy; Betrieb mit Docker; UI-Anmeldungen; Sicherung, Wiederherstellung, Aktualisierung |
| [cleanup.md](cleanup.md) | Der Ablauf zum Aufräumen: Befunde → CSV-Arbeitsliste → entfernen → erneut scannen → vergleichen |
| [review.md](review.md) | Anleitung zur Prüfung des Lesezugriffs: was an die Zielhosts geht, `sshbite collector show`, was die Allowlist-Prüfung garantiert |
| [side-effects.md](side-effects.md) | Logs, sudo-„Vorfall“-Mails, Zugriffszeiten und Monitoring-Alarme, die ein Scan auslöst – vor dem ersten echten Scan lesen |
| [compose.example.yaml](compose.example.yaml) | Docker-Compose-Datei für den Betrieb von SSHBITE |
| [systemd/](systemd/) | `sshbite-serve.service`, `sshbite-scan.service` + `.timer`, `sshbite-scan-docker.service` |
| [development.md](development.md) | Testumgebung, Tests und CI |
