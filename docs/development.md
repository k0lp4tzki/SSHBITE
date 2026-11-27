<a id="development-test-lab-tests-and-ci"></a>

# Entwicklung: Testumgebung, Tests und CI

<a id="layout"></a>

## Aufbau

| Pfad | Inhalt |
|---|---|
| `sshbite/` | Das Python-Paket: CLI, Crawl, Transport, Collector-Skripte, Parser, Ableitung, DB, Web-API |
| `frontend/` | Die UI: Svelte 5 + TypeScript + Vite. `npm run build` schreibt nach `sshbite/web/static/` |
| `lab/` | Die Testumgebung (Lab) mit 14 Hosts (docker compose): 13 OpenSSH-Hosts mit Debian 12 – der Jump-Host und 12 Hosts dahinter – sowie der eigenständige AlmaLinux-9-Host r1 |
| `tests/` | `unit/`, `web/` (HTTP-API), `e2e/` (gegen die Testumgebung), `browser/` (Playwright) |
| `Dockerfile`, `compose.lab.yaml` | Das Image; `compose.lab.yaml` = die Testumgebung plus das Image, das sie scannt (nur Lab-Demo) |
| `.github/workflows/ci.yml` | CI |

<a id="set-up"></a>

## Einrichtung

```sh
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --no-deps -e .          # baut das Frontend (braucht Node 22)
```

`SSHBITE_SKIP_FRONTEND=1` überspringt den Frontend-Build. Während der Arbeit an der UI: `cd frontend && npm ci && npm run dev`
(Vite leitet `/api` an `sshbite serve` auf 127.0.0.1:8722 weiter).

Abhängigkeiten sind mit Hashes festgelegt: `requirements.lock` (Laufzeit und das Extra `test`, für Entwicklung
und CI), `requirements-runtime.lock` (nur Laufzeit, ohne pytest – das, was das Image und eine pip-Installation für
den echten Einsatz erhalten; dieselben Versionen) und `requirements-build.lock` (setuptools und wheel für den
Wheel-Build des Images), erzeugt mit
`uv pip compile … --generate-hashes --python-version 3.12` (der Befehl steht im Kopf jeder Datei).
npm verwendet `frontend/package-lock.json`.

<a id="the-test-lab"></a>

## Die Testumgebung

`lab/` enthält 13 echte OpenSSH-Server (Debian bookworm, OpenSSH 9.2) – einen Jump-Host und 12 Hosts dahinter –,
bestückt mit realistischen Altlasten: hostübergreifende Schlüssel, verwaiste Schlüssel, DSA/RSA-1024, Root-Schlüssel,
gehashte known_hosts. Dazu kommt r1 (AlmaLinux 9, siehe unten), insgesamt also 14 Hosts. Alle Schlüssel der
Testumgebung dienen nur zum Testen und sind eingecheckt (`lab/keys/README.md`).

```sh
lab/up.sh                     # docker compose (sonst podman, sonst als root: lab/local/up.sh); erzeugt lab/sshbite.lab.yaml
.venv/bin/sshbite -c lab/sshbite.lab.yaml config validate --connect
SSHBITE_SUDO_PASSWORD=labsudo .venv/bin/sshbite -c lab/sshbite.lab.yaml scan
.venv/bin/sshbite -c lab/sshbite.lab.yaml scans show latest
docker compose -f lab/compose.yaml down        # die Testumgebung entfernen
```

- `lab/sshbite.lab.yaml` ist nicht eingecheckt: `lab/up.sh` erzeugt die Datei bei jedem Lauf, und sie steht in
  `.gitignore`. Sie enthält den festgelegten Host-Key des Jump-Hosts und den Audit-Schlüssel der Testumgebung und
  setzt kein `privilege.mode`, nutzt also den Legacy-Modus `sudo`; das sudo-Passwort kommt aus
  `SSHBITE_SUDO_PASSWORD`.
- Der Jump-Host ist auf `127.0.0.1:2222` veröffentlicht. Läuft die Testumgebung anderswo, erzeugen Sie die Konfiguration
  mit `LAB_NO_START=1 LAB_ENTRY_HOST=<host> LAB_ENTRY_PORT=<port> lab/up.sh` und richten den e2e-Test mit
  `SSHBITE_LAB_ENTRY=<host>:<port>` darauf aus. Der Test muss die Adressen der Testumgebung (172.30.1-4.0/24) direkt
  erreichen.
- r1 (AlmaLinux 9, `lab/image/Dockerfile.el9`) liegt allein in `lab_r` (172.30.4.11, veröffentlicht auf
  `127.0.0.1:2223`) und wird von `tests/e2e/test_lab_installed.py` (i04, i06-i08) direkt gescannt; richten Sie den
  Test mit `SSHBITE_LAB_R1=<host>:<port>` darauf aus, falls er anderswo antwortet. Kein anderer Host der Testumgebung
  verweist auf ihn, daher ist er nicht Teil von `lab/expected.yaml`. `lab/local/up.sh` baut r1 nicht.
- `tests/e2e/test_lab_installed.py` prüft `privilege.mode: installed` gegen die Testumgebung. Den
  Installationsschritt des Betreibers (die Dateien von `sshbite collector export` auf jedem Host einrichten) erledigt
  dabei `lab/installed.sh apply` über das Lab-Control-sshd; `lab/installed.sh remove` stellt den vorherigen Zustand
  wieder her.
- `lab/race.sh start|count N|stop` (als root auf einem Host der Testumgebung über das Lab-Control ausgeführt) richtet
  den Symlink-Race aus review.md für Test i08 ein.
- Ohne docker oder podman baut `lab/local/up.sh` (root) dieselben Hosts mit Netzwerk-, Mount- und PID-Namespaces;
  `lab/local/down.sh` entfernt sie.
- `docker compose -f compose.lab.yaml up -d --build` im obersten Verzeichnis startet die Testumgebung **und** das
  SSHBITE-Image (`lab/demo/start.sh`): Es prüft den Einstiegshost, legt den UI-Benutzer `admin` an (Passwort aus
  `SSHBITE_DEMO_PASSWORD`, sonst ein zufälliges, das einmal im Log unter `LAB DEMO LOGIN` ausgegeben wird; das alte
  feste Demo-Passwort wird abgelehnt), führt einen Scan mit dem sudo-Passwort der Testumgebung in
  `SSHBITE_SUDO_PASSWORD` aus und stellt die UI unter http://127.0.0.1:8722/ bereit.

## Tests

```sh
.venv/bin/python -m pytest tests/unit tests/web    # Unit-Tests und die HTTP-API, keine Testumgebung nötig
.venv/bin/python -m pytest tests/e2e               # Spezifikation 9.3 gegen die laufende Testumgebung (startet sie, wenn möglich)
.venv/bin/pip install playwright==1.65.2 && .venv/bin/playwright install chromium
.venv/bin/python -m pytest tests/browser           # Browser-Prüfungen nach Spezifikation 9.4 (braucht das gebaute Frontend)
```

- Der e2e-Test erstellt vor und nach jedem Scan einen Snapshot von `/etc`, `/root` und `/home` jedes Hosts der
  Testumgebung (`lab/snapshot.sh`) und schlägt fehl, wenn sie nicht byte-identisch sind. Er ändert die Testumgebung
  nur zwischen Scans (`lab/labctl.sh`), über ein separates Lab-Control-sshd auf Port 2200, das außerhalb von
  `/etc/ssh` liegt, und setzt die Testumgebung am Ende zurück.
- `SSHBITE_EVIDENCE_DIR=<dir>` lässt den e2e-Test Konsolenmitschnitte, Exporte und Snapshot-Diffs aufbewahren.
- Die Erwartungen an die Testumgebung sind von Hand in `lab/expected.yaml` geschrieben (nach Spezifikation 9.3).
- `tests/fixtures/lab_scans.db` enthält die Scans 1–3 eines echten Laufs der Testumgebung; die Web- und Browser-Tests
  verwenden sie und brauchen daher keine laufende Testumgebung. Erzeugen Sie sie neu mit
  `pytest tests/e2e --basetemp=DIR` und kopieren Sie `DIR/e2e0/sshbite.db`.
- Führen Sie nach einer Änderung an `sshbite/collector/collect.sh` `python tools/update_collector_sha.py` aus, um
  dessen `B=`-Zeile zu aktualisieren.

## CI

`.github/workflows/ci.yml` läuft bei jedem Push auf `main` und bei jedem Pull Request:

| Job | Was er ausführt |
|---|---|
| `lint` | `ruff check .` (Konfiguration in `pyproject.toml`), `npm run check` (svelte-check), den Collector-Allowlist-Lint über `sshbite collector show`, `docker compose config` beider Compose-Dateien |
| `unit` | `pytest tests/unit tests/web`; schlägt fehl, wenn etwas übersprungen wurde |
| `e2e` | `lab/up.sh` (docker compose, 13 Hosts + r1), `pytest tests/e2e/test_lab.py tests/e2e/test_lab_installed.py`; schlägt fehl, wenn etwas übersprungen wurde; lädt die Mitschnitte hoch |
| `browser` | Playwright + Chromium, `pytest tests/browser`; schlägt fehl, wenn etwas übersprungen wurde |
| `image` | `docker build`; prüft uid 10001, `sshbite --version`, den Lint im Image; `docker compose up` von Testumgebung + Image: Das Image prüft den festgelegten Einstiegshost, scannt die Testumgebung (20 Zugriffskanten) und stellt die UI mit ihrer CSP bereit; ein nicht authentifizierter Schreibzugriff erhält 401 |

Um dieselben Schritte lokal auszuführen, verwenden Sie die Befehle aus den `run:`-Zeilen jedes Jobs in dieser
Reihenfolge; [`act`](https://github.com/nektos/act) führt den Workflow ebenfalls aus, wenn Docker verfügbar ist.
