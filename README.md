# SSHBITE
Durchsucht SSH-Verbindungen anhand der Schlüsseleinträge und zeigt sie als Heatmap

SSHBITE ist ein **nur lesendes Audit der SSH-Zugänge** für Linux/OpenSSH-Umgebungen – gebaut für das
Aufräumen nach einem Sicherheitsvorfall. Von einem geprüften Einstiegspunkt aus (einem Jump-Host mit
festgelegtem Host-Key) durchsucht es jeden Host, den es finden kann, und beantwortet:

- **Wer darf sich von wo nach wo verbinden?** Jede `authorized_keys`-Zeile wird mit den privaten
  Schlüsseln abgeglichen, die auf anderen Hosts gefunden wurden, und so zu einer Zugriffskante
  (`jump:ops → a2:root`). Schlüssel, deren privater Teil nirgends gefunden wurde, werden als
  *unbekannte Herkunft* markiert.
- **Welche Systeme halten einen Schlüssel?** Wo jeder öffentliche Schlüssel zugelassen ist (Host, Benutzer,
  Datei:Zeile, Optionen), wo sein privater Teil und `.pub`-Kopien liegen und welche Hosts welche anderen in
  `known_hosts` kennen.
- **Ist die Kryptografie aktuell?** ed25519 ist gut, RSA 2048 schwach, RSA unter 2048 und DSA kritisch
  (einstellbar), dazu Befunde wie Root-Schlüssel, unverschlüsselte oder lesbare private Schlüssel,
  geänderte Host-Keys und `PermitRootLogin yes`.

Eine Web-Oberfläche zeigt alles an einer Stelle: eine Heatmap der eingehenden und ausgehenden Zugriffe,
einen Verbindungsgraphen, Ansichten je Host, Schlüssel und Benutzer, Befunde mit CSV/JSON-Export und einen
Vergleich zwischen Scans, mit dem Sie das Aufräumen bestätigen.

SSHBITE ändert nichts auf den geprüften Systemen: Es führt ein festes, prüfbares Shell-Skript aus, das nur
liest (`sshbite collector show`), benutzt nur seinen eigenen Audit-Schlüssel und nie gefundene Schlüssel.
Es hinterlässt aber Log-Einträge und kann sudo-Mails und Monitoring-Alarme auslösen – lesen Sie
[docs/side-effects.md](docs/side-effects.md) vor dem ersten echten Scan. Alles bleibt lokal: eine
SQLite-Datenbank, eine Oberfläche auf `127.0.0.1` hinter einer Anmeldung, keine externen Dienste oder CDNs.

<a id="quick-start-docker"></a>

## Schnellstart (Docker)

Die vollständige Anleitung mit allen Prüfungen steht in [docs/install.md](docs/install.md). Kurzfassung
für den empfohlenen Modus `privilege.mode: installed`, alles als root auf dem Docker-Host:

1. **Image bauen** ([Schritt 1](docs/install.md#schritt-1-image-bauen)):
   ```sh
   git clone https://github.com/k0lp4tzki/SSHBITE.git && cd SSHBITE
   docker build -t sshbite:0.1.0 .
   ```
2. **Audit-Schlüssel erzeugen und Collector exportieren** ([Schritte 2 und 3](docs/install.md#schritt-2-audit-schlüssel-erzeugen)):
   ```sh
   install -d -m 700 /etc/sshbite
   ssh-keygen -t ed25519 -N '' -C "sshbite-audit $(date +%F)" -f /etc/sshbite/audit_ed25519
   mkdir sshbite-export
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/sshbite-export:/out" sshbite:0.1.0 \
     sshbite collector export /out --collector-path /usr/local/libexec/sshbite/sshbite-collect
   cd sshbite-export && sha256sum -c SHA256SUMS && cd ..
   ```
3. **Jeden Zielhost vorbereiten**: Collector, Gate, sudo-Regel und `authorized_keys`-Zeile installieren –
   [Zielhosts vorbereiten](docs/install.md#zielhosts-vorbereiten-installierter-collector). Bei Docker steht in
   `from="<SCANNER-IP>"` des Einstiegshosts die Adresse des Docker-Hosts, wie der Einstiegshost sie sieht.
4. **Host-Key des Einstiegshosts festlegen und Konfiguration schreiben**
   ([Anleitung](docs/install.md#host-key-festlegen-und-konfiguration-schreiben)).
   Vergleichen Sie vorher den Fingerabdruck auf dem Scanner-Rechner mit dem an der Konsole des Einstiegshosts:
   ```sh
   ssh-keygen -lf <(ssh-keyscan -t ed25519 -p 22 <ENTRY-HOST> 2>/dev/null)   # auf dem Scanner-Rechner
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub                          # an der Konsole des Einstiegshosts
   ```
   Nur wenn beide gleich sind, tragen Sie den Schlüssel ein:
   ```sh
   ssh-keyscan -t ed25519 -p 22 <ENTRY-HOST> 2>/dev/null | awk '!/^#/ {print $2" "$3}'
   cat > /etc/sshbite/sshbite.yaml <<'EOF'
   database: /data/sshbite.db
   entry:
     host: <ENTRY-HOST>
     port: 22
     host_keys: ["ssh-ed25519 <BASE64-FROM-KEYSCAN>"]
   audit:
     user: sshbite
     key_file: /etc/sshbite/audit_ed25519
   privilege:
     mode: installed
     collector_path: /usr/local/libexec/sshbite/sshbite-collect
   crawl:
     include: [<CIDR-OF-YOUR-ESTATE>]
   EOF
   chown -R 10001:10001 /etc/sshbite && chmod 700 /etc/sshbite && chmod 600 /etc/sshbite/*
   ```
5. **Starten, prüfen, Benutzer anlegen, scannen** ([Schritte 7 bis 10](docs/install.md#schritt-7-container-starten)):
   ```sh
   docker compose -f docs/compose.example.yaml up -d
   docker exec -it sshbite sshbite config validate --connect
   docker exec -it sshbite sshbite user add admin
   docker exec sshbite sshbite scan --label first
   ```
   `config validate --connect` muss mit
   `entry OK, pinned key matches, sudo: root (installed /usr/local/libexec/sshbite/sshbite-collect, collector B=… matches)`
   enden.
6. **Oberfläche öffnen:** `http://127.0.0.1:8722/` auf dem Scanner-Rechner, von anderswo über
   `ssh -L 8722:127.0.0.1:8722 <ADMIN>@<SCANNER>`. Für Zugriff über das Netz gehört ein Reverse Proxy mit
   TLS davor ([operations.md](docs/operations.md#hinter-einem-reverse-proxy-tls-am-proxy)).

Befehle, die ein Passwort abfragen, brauchen ein Terminal: `docker exec -it`, nie nur `-i`. Ohne Docker:
[Pfad C mit pip und systemd](docs/install.md#pfad-c-nativ-mit-pip-und-systemd). Aktualisierung,
Deinstallation und Fehlerbehebung: [install.md](docs/install.md#aktualisierung).

<a id="try-it-on-the-test-lab-test-material-only"></a>

## Ausprobieren in der Testumgebung (nur Testmaterial)

```sh
docker compose -f compose.lab.yaml up -d --build
docker compose -f compose.lab.yaml logs sshbite | grep 'LAB DEMO LOGIN'
```

Das startet eine Testumgebung (Lab) mit 14 SSH-Hosts – 13 Debian-Hosts, die die Lab-Demo durchsucht, und
`r1` (AlmaLinux 9) für Tests des installierten Collectors – sowie SSHBITE selbst. SSHBITE prüft den
Einstiegshost, legt den Benutzer `admin` an, führt einen Scan aus und startet die Oberfläche auf
`http://127.0.0.1:8722/`. Melden Sie sich als `admin` an, mit dem Passwort aus `SSHBITE_DEMO_PASSWORD`
(z. B. in `.env`) oder – wenn Sie keines gesetzt haben – mit dem zufälligen Passwort aus dem Log.

Das Passwort steht nur beim ersten Start im Log; das Volume `sshbite-lab-data` behält den Benutzer. Für ein
neues Passwort entfernen Sie das Lab mit `docker compose -f compose.lab.yaml down -v` und starten es neu.
`docker compose up` im Wurzelverzeichnis startet dieselbe Lab-Demo (`compose.yaml` bindet nur
`compose.lab.yaml` ein). Ausführlich: [Pfad A](docs/install.md#pfad-a-ausprobieren-in-der-testumgebung).

> **Verwenden Sie das Lab nie außerhalb eines Tests.** `compose.lab.yaml`, `lab/demo/` und vor allem
> **`lab/keys/*`** – private Host-Keys der Lab-Hosts und der **Audit-Schlüssel** des Labs, absichtlich
> eingecheckt – sind Testmaterial, das jeder kennt, der dieses Repository hat. Lassen Sie keinen dieser
> Schlüssel auf einem echten System zu, verwenden Sie die Lab-Konfiguration nicht weiter und betreiben Sie
> die Lab-Demo nicht auf einem Rechner, den andere erreichen. Für echte Systeme gelten die Schritte oben
> und [`docs/compose.example.yaml`](docs/compose.example.yaml).

<a id="documentation"></a>

## Dokumentation

| | |
|---|---|
| [Installation](docs/install.md) | Docker, pip, Zielhosts vorbereiten (installierter Collector), Host-Key festlegen, erster Scan, Aktualisierung, Deinstallation, Fehlerbehebung |
| [Konfiguration](docs/configuration.md) | jeder Konfigurationsschlüssel mit Standardwert und Bedeutung |
| [Scans ausführen](docs/scanning.md) | Crawl, Umfang, Seeds, sudo-Passwörter (Legacy-Modus), Host-Status, Exit-Codes |
| [Betrieb](docs/operations.md) | systemd-Units für Oberfläche und nächtlichen Scan, Reverse Proxy, Sicherung, Aktualisierung |
| [Aufräumen](docs/cleanup.md) | Befunde → Arbeitsliste → entfernen → erneut scannen → vergleichen |
| [Prüfung des Lesezugriffs](docs/review.md) | was an die Zielhosts geht und was die Allowlist-Prüfung garantiert |
| [Nebenwirkungen](docs/side-effects.md) | Logs, sudo-„Vorfall“-Mails, Zugriffszeiten, Monitoring-Alarme |
| [Entwicklung](docs/development.md) | Testumgebung, Tests, CI |
| [compose.example.yaml](docs/compose.example.yaml) | Compose-Datei für den Betrieb (Pfad B) |
| [systemd/](docs/systemd/) | Units für Oberfläche und nächtlichen Scan (Pfad C und Docker) |

<a id="commands"></a>

## Befehle

```text
sshbite [-c|--config PATH] [-v|-vv] [--version] BEFEHL ...
sshbite init-config
sshbite config validate [--connect]
sshbite scan [--max-depth 0-100] [--max-hosts 1-100000] [--concurrency 1-500] [--timeout 1-3600]
             [--no-crawl] [--ask-sudo-password] [--label TEXT] [--dry-run]
sshbite scans list [--json] | show ID|latest [--json] | delete ID [--json]
sshbite export --what findings|keys|edges|hosts|authorized [--scan ID|latest] [--format csv|json] [-o FILE]
               [--min-severity critical|high|medium|low|info] [--rule RULE ...] [--host GLOB] [--kind access|evidence]
sshbite diff A B [--format text|json]
sshbite hostkey list [--json] | accept ADDR[:PORT] | forget ADDR
sshbite user add|passwd NAME [--password-stdin] | remove NAME
sshbite db backup PATH
sshbite collector show | export DIR [--collector-path P]
sshbite serve [--bind ADDR] [--port N] [--tls-cert FILE --tls-key FILE] [--insecure-bind]
sshbite synth [--hosts 10-100000] [--seed N]
```

Ohne `-c` liest SSHBITE die Konfiguration aus `$SSHBITE_CONFIG`, sonst aus `/etc/sshbite/sshbite.yaml`.

Exit-Codes: 0 Scan fertig (auch mit `partial` oder nicht erreichbaren Hosts), 2 Konfigurationsfehler,
3 Fehler am Einstiegshost (nicht erreichbar, Host-Key fehlt oder weicht ab, Anmeldung gescheitert,
`sudo: FAILED`), 4 interner Fehler oder Abbruch mit Strg+C, 5 ein anderer Scan läuft noch.
