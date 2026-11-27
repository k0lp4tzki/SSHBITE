<a id="running-scans"></a>

# Scans ausführen

```sh
sshbite scan [--max-depth N] [--max-hosts N] [--concurrency N] [--timeout S] [--no-crawl]
             [--ask-sudo-password] [--label TEXT] [--dry-run]
```

Stellen Sie mit Docker jedem Befehl `docker exec -it sshbite` voran (z. B.
`docker exec -it sshbite sshbite scan --ask-sudo-password`).

<a id="what-a-scan-does"></a>

## Was ein Scan tut

1. **Verbindet sich mit dem Einstiegshost** und prüft dessen Host-Key gegen `entry.host_keys`. Ein fehlender
   oder abweichender Schlüssel bricht den Scan ab (Exit-Code 3), bevor irgendetwas gesendet wird.
2. **Sammelt** den Einstiegshost ein: Es führt das feste, rein lesende Collector-Skript aus (`sshbite collector show`),
   wenn möglich mit sudo, und liest lokale Konten, `authorized_keys` mit ihren Optionen, die Schlüssel in
   `~/.ssh`, `known_hosts`, ssh-Client-Konfigurationen und die wirksamen `sshd`-Einstellungen. Private Schlüssel
   verlassen den Host nie – nur ihr Fingerprint, Typ, ihre Größe und ob sie verschlüsselt sind.
3. **Durchsucht** in der Breite, Tiefe für Tiefe. Die nächsten Hosts ergeben sich aus dem Inhalt der aktuellen Tiefe:
   - Einträge in `known_hosts` (im Klartext, und gehashte, die gegen jeden im Scan bekannten Namen und jede
     Adresse abgeglichen werden),
   - `HostName`, `Host` (ohne Wildcards) und `ProxyJump` in ssh-Konfigurationen,
   - wörtliche Namen/Adressen in `from="…"` von `authorized_keys`.
   Namen werden auf dem Einstiegshost aufgelöst. Jeder Verweis wird eingestuft: `queued` (wird gescannt),
   `alias` / `already` (bekannter Host), `excluded`, `out_of_scope`, `max_depth`, `max_hosts`,
   `unresolvable`. Nur zu `queued`-Hosts wird eine Verbindung aufgebaut.
4. **Erreicht jeden Host über den Einstiegshost** (ein auf dem Einstiegshost geöffneter SSH-Tunnel; dort läuft
   kein ssh-Client). Scheitert das mit einem Netzwerkfehler und ist `crawl.chain_fallback` eingeschaltet, versucht
   es den Weg, auf dem der Host entdeckt wurde, z. B. entry → b3 → c1, und prüft dabei auf jedem Hop den Host-Key.
5. **Leitet** Zugriffskanten (wer sich wo mit welchem Schlüssel anmelden kann), Indizkanten (known_hosts,
   ssh-Konfiguration), Befunde und die Heatmap-Kennzahlen **ab** und speichert den Scan.

Die Konsole zeigt den Fortschritt je Tiefe und eine Zusammenfassung:

```text
scan: entry 172.30.1.5:22, max depth 10, max hosts 1000, concurrency 20
depth 0: 0 queued, 0 running, 1 done
...
depth 3: 0 queued, 0 running, 12 done (1 partial, 1 unreachable)

scan 1 completed in 14 s
hosts:    13 connected; 11 ok, 1 partial, 1 unreachable, 1 excluded, 2 out_of_scope, 1 unresolvable
findings: 37 - 4 critical, 15 high, 15 medium, 2 low, 1 info
edges:    20 access (19 effective, 3 unknown origin); keys: 10
scan id:  1
UI:       http://127.0.0.1:8722/  (start it with `sshbite serve`)
```

Es läuft immer nur ein Scan gleichzeitig (ein zweiter endet mit Exit-Code 5). Die UI kann während eines Scans
geöffnet bleiben; sie zeigt den Fortschritt und übernimmt den neuen Scan, sobald er fertig ist.

<a id="before-the-first-real-scan"></a>

## Vor dem ersten echten Scan

- Lesen Sie [side-effects.md](side-effects.md) und informieren Sie die Personen, die sudo-Mails erhalten, die
  Auth-Logs beobachten oder IDS/EDR betreiben, dass ein Audit-Crawl bevorsteht und von welcher Adresse er kommt.
- `sshbite scan --dry-run` gibt den Einstiegshost, das Audit-Konto, den Umfang und jeden Seed aus, ohne eine
  Verbindung aufzubauen.
- `sshbite config validate --connect` prüft den festgelegten Host-Key und sudo auf dem Einstiegshost.
- Erwägen Sie zunächst `--max-depth 1`, um zu sehen, wohin der Einstiegshost führt.

<a id="scope-crawl-include-exclude"></a>

## Umfang des Crawls

Der Normalfall ist der Crawl allein vom Einstiegshost aus – eine Hostliste ist nicht nötig. Begrenzen Sie ihn mit:

| Einstellung | CLI | Wirkung |
|---|---|---|
| `crawl.max_depth` (10) | `--max-depth N` | Weiter entfernte Hosts werden als `max_depth` aufgeführt. |
| `crawl.max_hosts` (1000) | `--max-hosts N` | Weitere Hosts werden als `max_hosts` aufgeführt. |
| `crawl.include` | – | Wenn gesetzt, werden nur passende Hosts (CIDR oder Namens-Glob) gescannt; andere sind `out_of_scope`. Wenn leer, warnen `config validate` und `scan` (siehe unten). |
| `crawl.exclude` | – | Zu passenden Hosts wird nie eine Verbindung aufgebaut, sie werden nur als `excluded` aufgeführt. Exclude hat Vorrang vor include und vor Seeds. |
| – | `--no-crawl` | Nur den Einstiegshost und die Seeds scannen. |

Ohne `crawl.include` folgt der Crawl allem, worauf die eigenen Dateien der Zielhosts verweisen: Adressen **und Ports**
stammen aus known_hosts, `~/.ssh/config` und `from=`-Optionen der gescannten Hosts. Das ist die vom Auftraggeber
gewünschte Voreinstellung, aber nach einem Sicherheitsvorfall können diese Dateien untergeschoben sein. Deshalb geben
`config validate` und jeder `scan` aus:

```text
warning: crawl.include is empty: crawl targets and ports are taken from target data (known_hosts, ~/.ssh/config, from=) without restriction; set crawl.include to the networks and host names you mean to scan
```

Setzen Sie `crawl.include` auf Ihre Netze und Hostnamen-Muster, um den Crawl darauf zu begrenzen.

Jeder Verweis bleibt erhalten, ob gescannt oder nicht: Der Crawl-Baum in der UI (Scans → crawl tree) und
`sshbite scans show ID` führen jeden Host mit Tiefe, der Datei und Zeile, in der er entdeckt wurde, und seiner Route auf.

## Seeds

Seeds sind zusätzliche Hosts in Tiefe 0, neben dem Einstiegshost (siehe
[configuration.md](configuration.md#seeds)):

```yaml
seeds:
  hosts_file: /etc/sshbite/extra-hosts      # "host", "host:port" oder "[host]:port" pro Zeile
  cidrs: [10.20.0.0/24]                     # jede Adresse wird zuerst vom Einstiegshost per TCP geprüft
  ansible_inventories: [/etc/sshbite/inventory.ini]
```

Von Seeds aus wird wie von jedem anderen Host weiter durchsucht. CIDR-Adressen, die nicht innerhalb von 2 s auf dem
SSH-Port antworten, erhalten den Status `no_ssh`. Seed-Dateien liegen im Docker-Setup unter `/etc/sshbite`, damit
der Container sie lesen kann.

<a id="sudo-passwords"></a>

## Sudo-Passwörter

Dieser Abschnitt gilt nur für die Legacy-Modi (`privilege.mode: sudo` und `sudo-login`). Mit `NOPASSWD`-sudo ist
nichts nötig. Mit `privilege.mode: installed` wird nie ein sudo-Passwort gesendet:
`--ask-sudo-password` wird mit Exit-Code 2 abgelehnt und `SSHBITE_SUDO_PASSWORD` wird mit einer Warnung ignoriert;
ein Host, dessen sudo ein Passwort verlangt, wird `collector_error`
([install.md](install.md#fehlermeldungen-im-modus-installed)). Fragt sudo in den Legacy-Modi nach einem Passwort:

```sh
sshbite scan --ask-sudo-password             # fragt einmal nach, ohne Echo
docker exec -it sshbite sshbite scan --ask-sudo-password
```

`--ask-sudo-password` braucht ein Terminal: Ohne eines (eine Pipe, `docker exec -i` ohne `-t`) verweigert es den
Dienst, weil das Passwort sonst angezeigt werden könnte. Nicht interaktiv, z. B. aus einem Timer, funktioniert
`SSHBITE_SUDO_PASSWORD=… sshbite scan`, ist aber **nicht empfohlen** – der Wert ist in `/proc/<pid>/environ` sichtbar
und, wenn er an einen Container übergeben wird, in `docker inspect` (siehe
[operations.md](operations.md#das-sudo-passwort)). Dasselbe Passwort wird auf jedem Host versucht, der danach fragt,
sofern `privilege.password_scope` es nicht auf bestimmte Hosts begrenzt.
Ein kompromittierter Host kann eine sudo-Passwortabfrage nachahmen und das Passwort abgreifen: Verwenden Sie eines,
das nur das Audit-Konto hat, und ändern Sie es nach dem Scan. Es wird nur für die Dauer des Scans im Speicher
gehalten, aus der Umgebung entfernt, in Logs geschwärzt und nie in die Datenbank geschrieben. Ein Host, auf dem sudo
verweigert wird oder das Passwort falsch ist, wird ohne Rechte gescannt und als `partial` markiert, mit dem Grund
(z. B. `sudo: a password is required`). Brauchten Hosts ein Passwort und wurde keines angegeben, meldet die
Zusammenfassung:

```text
2 hosts need a sudo password: rerun with --ask-sudo-password
```

Beachten Sie, dass ein falsches Passwort auf jedem Host als fehlgeschlagener sudo-Versuch zählt (siehe
[side-effects.md](side-effects.md)).

<a id="host-statuses"></a>

## Host-Status

| Status | Bedeutung |
|---|---|
| `ok` | Vollständig eingesammelt. |
| `partial` | Ohne Root oder mit unlesbaren Teilen eingesammelt; die Gründe sind beim Host aufgeführt. |
| `output_limit` | Mehr Ausgabe als `limits.max_output_mb`; das Gelesene bleibt erhalten (zählt als partial). |
| `collector_error` | Der Collector ist nicht fertig geworden (keine Endmarke). |
| `unreachable` | Keine Route hat funktioniert; jede versuchte Route und ihr Fehler sind beim Host aufgeführt. |
| `timeout` | `limits.host_timeout` überschritten. |
| `auth_failed` | Der Audit-Schlüssel wurde nicht akzeptiert (Konto oder Schlüssel nicht verteilt). |
| `hostkey_mismatch` | Der Host-Key hat sich seit der ersten Speicherung geändert – kritischer Befund `host_key_changed`; auf dem Host wird keine Anmeldung durchgeführt. |
| `hostkey_unknown` | Strikter Modus: Der Schlüssel steht nicht in `hostkeys.known_hosts_file`. |
| `excluded`, `out_of_scope`, `max_depth`, `max_hosts`, `unresolvable`, `alias`, `no_ssh` | Gesehen, aber nie verbunden. |

**Ein Host-Key hat sich geändert.** Prüfen Sie den neuen Schlüssel auf einem unabhängigen Weg (Konsole), vertrauen
Sie ihm dann und scannen Sie erneut:

```sh
sshbite hostkey list
sshbite hostkey accept 10.1.2.3          # oder ADDR:PORT
sshbite hostkey forget 10.1.2.3          # alle gespeicherten Schlüssel verwerfen; der nächste Scan vertraut dem, was er sieht
```

**Viele Hosts `unreachable` mit „channel open failed“.** Der Einstiegshost verweigert dem Audit-Konto Tunnel:
Entfernen Sie dort `restrict`/`no-port-forwarding` aus seiner `authorized_keys`-Zeile oder erlauben Sie
`AllowTcpForwarding` (siehe [install.md](install.md#zielhosts-vorbereiten-installierter-collector)).

<a id="exit-codes"></a>

## Exit-Codes

| Code | Bedeutung |
|---|---|
| 0 | Scan fertig – auch wenn einige Hosts partial oder unreachable waren. |
| 2 | Konfigurationsfehler (Schema, Dateirechte, fehlende Dateien). |
| 3 | Fehler am Einstiegshost: nicht erreichbar, Host-Key nicht festgelegt oder abweichend, Authentifizierung fehlgeschlagen. Es wird nur eine Scan-Zeile als fehlgeschlagen/abgebrochen geschrieben. |
| 4 | Interner Fehler. |
| 5 | Ein anderer Scan läuft. |

<a id="after-the-scan"></a>

## Nach dem Scan

```sh
sshbite scans list                         # alle Scans
sshbite scans show latest                  # Hosts, Tiefe, entdeckt über, Route, Gründe
sshbite export --what findings --format csv -o findings.csv
sshbite diff 3 4                           # was neu, weggefallen oder geändert ist
sshbite scans delete 2
```

`export --what` ist eines von `findings`, `keys`, `edges`, `hosts`, `authorized`; Filter sind
`--min-severity`, `--rule` (wiederholbar), `--host GLOB` und `--kind access|evidence`. Die meisten Listenbefehle
akzeptieren `--json`.

Die UI (`sshbite serve`) zeigt dieselben Daten: Dashboard, Heatmap, Graph, Hosts, Schlüssel, Befunde und Diff.
Zum Testen der UI mit großen Datenmengen erzeugt `sshbite synth --hosts 2000 --seed 42` einen synthetischen Scan;
er ist überall als SYNTHETIC DATA gekennzeichnet.

Weiter: der Bereinigungsablauf in [cleanup.md](cleanup.md).
