<a id="install-and-set-up"></a>

# Installation und Einrichtung

Diese Anleitung beschreibt den Stand von SSHBITE 0.1.0. Jeder Befehl wurde in dieser Form ausgeführt; die
Ausgaben unter **Prüfung:** stammen aus diesen Läufen. Was nicht ausgeführt werden konnte, ist mit
„nicht getestet“ gekennzeichnet.

Inhalt: [Überblick](#überblick) · [Voraussetzungen](#voraussetzungen) ·
[Pfad A: Testumgebung](#pfad-a-ausprobieren-in-der-testumgebung) · [Pfad B: Docker](#pfad-b-docker) ·
[Zielhosts vorbereiten](#zielhosts-vorbereiten-installierter-collector) ·
[Host-Key festlegen und Konfiguration](#host-key-festlegen-und-konfiguration-schreiben) ·
[Pfad C: nativ](#pfad-c-nativ-mit-pip-und-systemd) ·
[Legacy-Modus](#legacy-modus-sudo-binsh--s-entspricht-vollem-root-zugriff) ·
[Aktualisierung](#aktualisierung) · [Deinstallation](#deinstallation) · [Fehlerbehebung](#fehlerbehebung) ·
[Anhang: Pfad B im Lab üben](#anhang-pfad-b-in-der-testumgebung-üben-nur-lab)

## Überblick

SSHBITE läuft auf einem Rechner, dem **Scanner-Rechner** (scanner machine). Er verbindet sich mit genau
einem **Einstiegshost** (entry host) – einem Jump-Host, dessen Host-Key Sie festgelegt haben – und erreicht
alle anderen Hosts über diesen Einstiegshost. Auf jedem **Zielhost** (target host) meldet sich SSHBITE als
**Audit-Konto** (audit account) `sshbite` mit einem eigenen **Audit-Schlüssel** (audit key) an und startet
dort den **installierten Collector** (installed collector), ein nur lesendes Skript.

Es gibt drei Wege:

| Pfad | Wofür | Dauer |
|---|---|---|
| **A** – [Ausprobieren in der Testumgebung](#pfad-a-ausprobieren-in-der-testumgebung) | SSHBITE mit Testmaterial ansehen, ohne echte Systeme | etwa 10 Minuten |
| **B** – [Docker](#pfad-b-docker) (empfohlen) | Betrieb auf einem Docker-Host | |
| **C** – [nativ mit pip und systemd](#pfad-c-nativ-mit-pip-und-systemd) | Betrieb ohne Docker | |

B und C teilen sich die Schritte [Zielhosts vorbereiten](#zielhosts-vorbereiten-installierter-collector)
und [Host-Key festlegen und Konfiguration schreiben](#host-key-festlegen-und-konfiguration-schreiben).

**Lesen Sie vor dem ersten echten Scan [side-effects.md](side-effects.md):** SSHBITE ändert nichts auf den
Zielhosts, hinterlässt dort aber Log-Einträge und kann sudo-Mails und Monitoring-Alarme auslösen.

## Voraussetzungen

**Scanner-Rechner**

- Linux; Root-Rechte (oder sudo) für `/etc/sshbite`.
- Pfad B: Docker Engine mit **Docker Compose v2.20 oder neuer** (die Lab-Dateien nutzen `include`).
  Prüfen Sie mit `docker compose version`.
- Pfad C: Python **3.12**, Node **22** mit npm, git. (Getestet mit Python 3.12.16 und Node 22.23.5.
  Python 3.13: siehe [Pfad C](#pfad-c-nativ-mit-pip-und-systemd).)
- `ssh-keygen`, `ssh-keyscan` (Paket openssh-client) und `sha256sum` – auch bei Docker auf dem Docker-Host,
  denn das Image enthält keinen SSH-Client.

**Netz**

- Der Scanner-Rechner erreicht den Einstiegshost auf TCP 22 (oder dem Port aus `entry.port`).
- Der Einstiegshost erreicht die übrigen Zielhosts per SSH.

**Jeder Zielhost**

- Linux mit OpenSSH, `sudo`, `visudo` und util-linux (`/usr/bin/setpriv`), siehe
  [Voraussetzung: util-linux](#voraussetzung-util-linux).
- Einmalig Root-Zugriff, um den Collector zu installieren.
- Getestet: Debian 12 (OpenSSH 9.2) und AlmaLinux 9 (OpenSSH 9.9). Nicht getestet: SELinux im Modus
  enforcing, OpenSSH älter als 8.7, Busybox-Systeme.

<a id="try-it-on-the-lab"></a>

## Pfad A: Ausprobieren in der Testumgebung

Die Testumgebung (Lab) besteht aus 14 SSH-Hosts in Containern: 13 Debian-Hosts, die die Lab-Demo
durchsucht, und `r1` (AlmaLinux 9) für Tests des installierten Collectors. Dazu kommt das echte
SSHBITE-Image. Es prüft den Einstiegshost, legt den UI-Benutzer `admin` an, führt einen Scan aus und
startet die Web-Oberfläche.

> **Alles im Lab ist Testmaterial:** die Konfiguration in `lab/demo/`, die Schlüssel in `lab/keys/`
> (auch private Host-Keys und der Audit-Schlüssel) und das sudo-Passwort `labsudo`. Verwenden Sie nichts
> davon für echte Systeme. Das Lab nutzt außerdem den [Legacy-Modus](#legacy-modus-sudo-binsh--s-entspricht-vollem-root-zugriff),
> nicht den empfohlenen installierten Collector.

Holen Sie das Repository und starten Sie das Lab. Der erste Start baut 15 Images und braucht Internetzugang.

```sh
git clone https://github.com/k0lp4tzki/SSHBITE.git && cd SSHBITE
docker compose -f compose.lab.yaml up -d --build
```

Suchen Sie das Passwort im Log:

```sh
docker compose -f compose.lab.yaml logs sshbite | grep 'LAB DEMO LOGIN'
```

**Prüfung:** Das Log des Dienstes `sshbite` enthält diese Zeilen (das Passwort ist zufällig):

```text
config OK: /etc/sshbite/sshbite.yaml
warning: config file /etc/sshbite/sshbite.yaml is group- or world-readable (chmod 600 recommended)
entry OK, pinned key matches, sudo: root
user admin added
## LAB DEMO LOGIN (shown only now):  user admin   password ReXwHfyJggLm5i5iqzvrlXRq
...
hosts:    13 connected; 11 ok, 1 partial, 1 unreachable, 1 excluded, 2 out_of_scope, 1 unresolvable
findings: 37 - 4 critical, 15 high, 15 medium, 2 low, 1 info
edges:    20 access (19 effective, 3 unknown origin); keys: 10
...
SSHBITE UI on http://0.0.0.0:8722/  (database /data/sshbite.db)
```

Die Warnung zu `group- or world-readable` gilt nur für das Lab: dort kommt die Konfiguration direkt aus dem
Git-Checkout.

Öffnen Sie `http://127.0.0.1:8722/` und melden Sie sich als `admin` mit dem Passwort aus dem Log an. Sie
sehen den Scan „lab demo“ mit **Dashboard**, **Heatmap**, **Hosts** und **Findings**.

- **Eigenes Passwort:** Setzen Sie vor dem Start `export SSHBITE_DEMO_PASSWORD='<PASSWORT>'`
  (mindestens 12 Zeichen) oder schreiben Sie die Variable in eine Datei `.env`. Dann steht kein Passwort im
  Log. Das früher veröffentlichte `sshbite-lab-demo` wird abgelehnt.
- **Keine Zeile `LAB DEMO LOGIN`:** Das Passwort steht nur beim ersten Start im Log, wenn es erzeugt und
  der Benutzer dabei angelegt wurde. Das Volume `sshbite-lab-data` behält den Benutzer. Für ein neues
  Passwort entfernen Sie das Lab mit `down -v` und starten es neu.

Beenden Sie den Versuch. Das gibt auch Port 8722 frei, den Pfad B braucht:

```sh
docker compose -f compose.lab.yaml down -v
```

Die Datei `compose.yaml` im Wurzelverzeichnis bindet nur `compose.lab.yaml` ein: Ein einfaches
`docker compose up` startet also immer das Lab, nie den Produktivbetrieb.

<a id="install-with-docker"></a>

## Pfad B: Docker

Das `Dockerfile` baut in drei Stufen: `node:22` baut die Oberfläche, eine Python-Stufe baut das Wheel, die
Laufzeitstufe `python:3.12-slim` installiert `requirements-runtime.lock` mit `--require-hashes` und das
Wheel. Das Image

- läuft als uid/gid **10001** (`sshbite`), nie als root;
- liest seine Konfiguration aus `/etc/sshbite/sshbite.yaml` (`SSHBITE_CONFIG`) und hält seine Daten in
  `/data`;
- setzt `SSHBITE_IN_CONTAINER=1`: `sshbite serve` hört im Container ohne `--bind` auf `0.0.0.0:8722`.
  Veröffentlichen Sie den Port nur auf `127.0.0.1`, denn die Oberfläche hat im Container kein TLS;
- startet `sshbite serve` und prüft seinen Zustand über `http://127.0.0.1:8722/` (HEALTHCHECK);
- enthält keinen SSH-Client: Schlüssel erzeugen und `ssh-keyscan` erledigen Sie auf dem Docker-Host.

Alle Befehle dieses Pfads laufen als root auf dem Docker-Host, im Wurzelverzeichnis des Repositorys.

### Schritt 1: Image bauen

```sh
git clone https://github.com/k0lp4tzki/SSHBITE.git && cd SSHBITE
docker build -t sshbite:0.1.0 .
```

**Prüfung:**

```sh
docker run --rm sshbite:0.1.0 sshbite --version
docker run --rm --entrypoint id sshbite:0.1.0
```

```text
sshbite, version 0.1.0
uid=10001(sshbite) gid=10001(sshbite) groups=10001(sshbite)
```

### Schritt 2: Audit-Schlüssel erzeugen

SSHBITE meldet sich auf jedem Host mit einem eigenen ed25519-Schlüssel an, der für nichts anderes benutzt
wird:

```sh
install -d -m 700 /etc/sshbite
ssh-keygen -t ed25519 -N '' -C "sshbite-audit $(date +%F)" -f /etc/sshbite/audit_ed25519
```

**Prüfung:** `ls -l /etc/sshbite` zeigt zwei Dateien: `audit_ed25519` mit `-rw-------` (0600) und
`audit_ed25519.pub` mit `-rw-r--r--`. `ssh-keygen` meldet vorher
`Your identification has been saved in /etc/sshbite/audit_ed25519` und den Fingerabdruck
`SHA256:… sshbite-audit <DATUM>`.

SSHBITE lehnt einen Schlüssel ab, der nicht den Modus 0600 hat. Mit einer Passphrase setzen Sie
`audit.key_passphrase_env` auf den Namen einer Umgebungsvariablen, die sie enthält
([configuration.md](configuration.md)).

<a id="export-and-checksums"></a>

### Schritt 3: Collector exportieren und Prüfsummen prüfen

Der Collector und seine Hilfsdateien werden aus dem Image in ein **neues, leeres** Verzeichnis
geschrieben. Legen Sie das Verzeichnis selbst an: Sonst erzeugt Docker es als root, und der Container kann
nicht hineinschreiben.

```sh
mkdir sshbite-export
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/sshbite-export:/out" sshbite:0.1.0 \
  sshbite collector export /out --collector-path /usr/local/libexec/sshbite/sshbite-collect
cd sshbite-export && sha256sum -c SHA256SUMS && cd ..
```

**Prüfung:** Der Export gibt die Prüfsummen aus, `sha256sum -c` meldet fünfmal `OK`:

```text
4000a6adde2ddcaed173b7db08fe71da264a58a458c5356c09ef2ee02d6aa91b  authorized_keys.sshbite
635132805a9f0905786495cfc6b1a1106a0d33b40507a3c67e73dda3558f751b  sshbite-collect
9168d8ef819703916aae627218026663fbcac4f42ef45d11dc648cdbcc071e29  sshbite-gate
99b2af5b9f622e5383068105d58734dfc19417efe0416597f4262a36f124be55  sshbite-resolve
8366ab2a63391d4ca748f6dc480d6d4b40e97342219d4a9269321e63b61ffaac  sudoers.d-sshbite
written to /out - verify with: cd /out && sha256sum -c SHA256SUMS
authorized_keys.sshbite: OK
sshbite-collect: OK
sshbite-gate: OK
sshbite-resolve: OK
sudoers.d-sshbite: OK
```

Die Prüfsummen gelten für SSHBITE 0.1.0 mit diesem Collector-Pfad. Bei einer anderen Version oder einem
anderen Pfad sehen sie anders aus.

| Datei | Inhalt |
|---|---|
| `sshbite-collect` | der Collector: `#!/bin/sh` und `collect.sh`, Byte für Byte derselbe Text, den `sshbite collector show` ausgibt |
| `sshbite-resolve` | die Namensauflösung: `#!/bin/sh` und `resolve.sh` |
| `sshbite-gate` | der erzwungene Befehl (forced command), etwa 50 Zeilen – lesen Sie ihn |
| `sudoers.d-sshbite` | die einzige sudo-Regel |
| `authorized_keys.sshbite` | die drei Varianten der Schlüsselzeile (A, B, C) |
| `SHA256SUMS` | die SHA-256-Prüfsummen der fünf Dateien |

`--collector-path` legt fest, wo der Collector auf den Zielhosts liegt; Gate und Resolve liegen immer
daneben. Ohne die Option nimmt der Export `privilege.collector_path` aus der Konfiguration oder, wenn es
noch keine gibt, `/usr/local/libexec/sshbite/sshbite-collect`. Lesen Sie die Dateien, bevor Sie sie
installieren.

### Schritt 4: Zielhosts vorbereiten

Bereiten Sie jeden Zielhost vor, wie unter
[Zielhosts vorbereiten](#zielhosts-vorbereiten-installierter-collector) beschrieben.

### Schritt 5: Host-Key festlegen und Konfiguration schreiben

Folgen Sie [Host-Key festlegen und Konfiguration schreiben](#host-key-festlegen-und-konfiguration-schreiben),
mit `database: /data/sshbite.db`.

### Schritt 6: Dateien dem Container-Benutzer geben

Der Container liest `/etc/sshbite` als uid 10001:

```sh
chown -R 10001:10001 /etc/sshbite && chmod 700 /etc/sshbite && chmod 600 /etc/sshbite/*
```

**Prüfung:** `ls -ln /etc/sshbite` zeigt drei Dateien mit dem Besitzer `10001 10001` und dem Modus 0600:

```text
-rw------- 1 10001 10001 419 Nov 27 08:59 audit_ed25519
-rw------- 1 10001 10001 106 Nov 27 08:59 audit_ed25519.pub
-rw------- 1 10001 10001 471 Nov 27 08:59 sshbite.yaml
```

### Schritt 7: Container starten

```sh
docker compose -f docs/compose.example.yaml up -d
```

[`compose.example.yaml`](compose.example.yaml) startet den Container `sshbite` mit dem Image
`sshbite:0.1.0`, dem Volume `sshbite-data` für `/data`, `/etc/sshbite` nur lesend und dem Port
`127.0.0.1:8722`. Der Container läuft schreibgeschützt, ohne Capabilities und mit
`no-new-privileges`. Kopieren Sie die Datei ruhig neben Ihre anderen Compose-Dateien; passen Sie dann
`build:` an oder entfernen Sie es.

**Prüfung:** Nach etwa einer Minute zeigt `docker ps` den Container `sshbite` als `(healthy)`. `docker logs
sshbite` zeigt:

```text
SSHBITE UI on http://0.0.0.0:8722/  (database /data/sshbite.db)
no UI user yet - create one with `sshbite user add NAME`
```

<a id="check"></a>

### Schritt 8: Verbindung prüfen

```sh
docker exec -it sshbite sshbite config validate --connect
```

**Prüfung:**

```text
config OK: /etc/sshbite/sshbite.yaml
entry OK, pinned key matches, sudo: root (installed /usr/local/libexec/sshbite/sshbite-collect, collector B=386f9faea780 matches)
```

`--connect` verbindet sich mit dem Einstiegshost, prüft den festgelegten Host-Key, führt die Probe und den
Collector aus und liest dessen erste Zeile. Das hinterlässt dort einen sudo-Log-Eintrag. Schlägt etwas
fehl, lautet die Zeile `sudo: FAILED - <MELDUNG>`, und der Befehl endet mit Exit-Code 3 – siehe
[Fehlermeldungen im Modus installed](#fehlermeldungen-im-modus-installed).

### Schritt 9: UI-Benutzer anlegen

```sh
docker exec -it sshbite sshbite user add admin
```

Das Passwort wird zweimal abgefragt und braucht mindestens 12 Zeichen. Die Abfrage braucht ein Terminal:
Verwenden Sie `-it`. In Skripten geht stattdessen
`printf '%s\n' "$PW" | docker exec -i sshbite sshbite user add admin --password-stdin`.

**Prüfung:** Die Ausgabe ist `user admin added`.

<a id="first-scan-and-first-login"></a>

### Schritt 10: Erster Scan

```sh
docker exec sshbite sshbite scan --label first
docker exec sshbite sshbite scans list
```

**Prüfung:** Der Scan endet mit einer Zusammenfassung und Exit-Code 0, `scans list` zeigt ihn als
`completed`. Im Testlauf gegen das Lab (13 Hosts, Modus installed) sah das so aus:

```text
scan: entry 172.30.1.5:22, max depth 10, max hosts 1000, concurrency 20
...
scan 1 completed in 22 s
hosts:    14 connected; 13 ok, 1 unreachable, 2 out_of_scope, 1 unresolvable
findings: 36 - 4 critical, 16 high, 13 medium, 2 low, 1 info
edges:    21 access (20 effective, 4 unknown origin); keys: 11
scan id:  1
UI:       http://127.0.0.1:8722/  (start it with `sshbite serve`)
  id  started               status     hosts  findings  label
   1  2026-11-27T09:04:16Z  completed     14        36  first
```

Ihr Scan zeigt Ihre Hosts. Ein Host mit dem Status `collector_error` ist nicht richtig vorbereitet, siehe
[Fehlerbehebung](#fehlerbehebung).

### Schritt 11: Oberfläche öffnen

Öffnen Sie auf dem Scanner-Rechner `http://127.0.0.1:8722/` und melden Sie sich mit dem Benutzer aus
Schritt 9 an. Von einem Arbeitsplatz aus öffnen Sie einen SSH-Tunnel und dann dieselbe Adresse:

```sh
ssh -L 8722:127.0.0.1:8722 <ADMIN>@<SCANNER>
```

`<ADMIN>` ist Ihr Konto auf dem Scanner-Rechner, `<SCANNER>` dessen Name oder Adresse. Für den Zugriff
über das Netz mit TLS siehe [operations.md](operations.md#hinter-einem-reverse-proxy-tls-am-proxy).

**Prüfung:** Die Oberfläche zeigt den Scan `first`; unter **Heatmap** und **Hosts** stehen Ihre Hosts.

Ohne Compose startet derselbe Container so (nicht getestet; die Optionen entsprechen
`compose.example.yaml`):

```sh
docker run -d --name sshbite --restart unless-stopped \
  -v sshbite-data:/data -v /etc/sshbite:/etc/sshbite:ro \
  -p 127.0.0.1:8722:8722 --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true sshbite:0.1.0
```

<a id="privileges-installed-collector-recommended"></a>
<a id="prepare-every-target-host-installed-mode-run-as-root"></a>
<a id="the-audit-key-and-account"></a>
<a id="install-on-every-host-as-root"></a>

## Zielhosts vorbereiten (installierter Collector)

Diese Schritte gelten für Pfad B und C und für **jeden** Zielhost, auch den Einstiegshost. Sie richten
`privilege.mode: installed` ein, den empfohlenen Modus. Verteilen Sie die Dateien am besten mit Ihrem
Konfigurationsmanagement; die Befehle unten zeigen, was es tun muss.

<a id="why"></a>

### Warum der installierte Collector

Ohne root kann der Collector fremde `~/.ssh` und `/etc/shadow` nicht lesen. Der alte Weg – eine
sudo-Regel für `/bin/sh -s` – **entspricht vollem Root-Zugriff** für jeden, der den Audit-Schlüssel hat,
denn die Shell führt aus, was auf stdin ankommt. Mit `privilege.mode: installed` ist das nicht so:

- Der Collector liegt auf jedem Host als Datei `sshbite-collect`, die root gehört. Die einzige sudo-Regel
  des Audit-Kontos erlaubt genau diese Datei, ohne Argumente.
- Der Audit-Schlüssel darf nur ein festes Gate (`sshbite-gate`) starten (`command=` in
  `authorized_keys`). Das Gate vergleicht den angeforderten Befehl wörtlich mit drei Zeichenketten und
  lehnt alles andere ab.
- SSHBITE schickt kein Skript an eine Shell, sendet nie ein sudo-Passwort und fällt nicht auf einen
  Scan ohne Rechte zurück.

Wer den Audit-Schlüssel hat (und sich von einer erlaubten Adresse verbindet), kann damit nur die Probe
ausführen, den installierten, nur lesenden Collector als root starten, Namen auflösen und – auf dem
Einstiegshost – zu SSH-Ports weiterleiten. Er kann keine Shell öffnen, keinen eigenen Befehl ausführen,
kein Skript an eine Shell geben, keine Root-Dateien außerhalb des Inventars lesen und nichts schreiben.
Es bleibt: Der Schlüssel verrät das Inventar (siehe
[review.md](review.md#restrisiko-der-audit-schlüssel-verrät-das-inventar)).

Die drei Befehle, die SSHBITE in diesem Modus sendet (P = `privilege.collector_path`, jeder auf einem
eigenen exec-Kanal; `sshbite collector show` gibt sie aus):

| Schritt | Befehl | stdin |
|---|---|---|
| Probe | `sudo -n -l P` | leer |
| Collector | `sudo -n P` | leer |
| Namensauflösung | `<Verzeichnis von P>/sshbite-resolve` | die Namen, einer pro Zeile (nur Daten) |

### Dateien auf den Zielhost bringen

Kopieren Sie das Export-Verzeichnis und den öffentlichen Audit-Schlüssel auf den Zielhost:

```sh
scp -r sshbite-export /etc/sshbite/audit_ed25519.pub root@<HOST>:/root/
```

`<HOST>` ist der Zielhost. Alle weiteren Befehle dieses Abschnitts laufen **auf dem Zielhost als root**.

### Collector, Gate und sudo-Regel installieren

```sh
cd /root/sshbite-export && sha256sum -c SHA256SUMS
id sshbite || useradd -m -s /bin/sh sshbite; passwd -l sshbite     # keine Gruppe sudo/wheel
usermod -s /bin/sh sshbite                  # auch für ein schon vorhandenes Konto: Shell /bin/sh
install -d -m 0755 -o root -g root /usr/local/libexec/sshbite
install -m 0755 -o root -g root sshbite-collect sshbite-resolve sshbite-gate /usr/local/libexec/sshbite/
install -m 0440 -o root -g root sudoers.d-sshbite /etc/sudoers.d/sshbite && visudo -cf /etc/sudoers.d/sshbite
chown root:root /home/sshbite && chmod 0755 /home/sshbite
install -d -m 0755 -o root -g root /home/sshbite/.ssh
```

- **Entfernen Sie jede andere sudoers-Regel für `sshbite`**, zum Beispiel `NOPASSWD: ALL` oder
  `/bin/sh -s` aus dem Legacy-Modus. Sonst entspricht der Schlüssel weiter vollem Root-Zugriff.
- Home und `.ssh` gehören root: Das Konto kann seine eigenen Schlüssel nicht ändern.
- Gab es das Konto `sshbite` schon vorher, arbeiten Sie zusätzlich
  [Ein bereits vorhandenes Konto sshbite](#ein-bereits-vorhandenes-konto-sshbite) durch: `useradd` lässt ein
  vorhandenes Konto, wie es ist.
- Der Kontoname `sshbite` und der Pfad `/home/sshbite` sind in den exportierten Dateien fest eingetragen.
  Behalten Sie `audit.user: sshbite`.

### Die authorized_keys-Zeile schreiben

Schreiben Sie **eine** der drei Varianten nach `/home/sshbite/.ssh/authorized_keys`. Welche Variante
gilt, steht unter [Die authorized_keys-Varianten](#die-authorized_keys-varianten).

(A) Einstiegshost:

```sh
printf 'restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="%s",command="/usr/local/libexec/sshbite/sshbite-gate" %s\n' '<SCANNER-IP>' "$(cat /root/audit_ed25519.pub)" > /home/sshbite/.ssh/authorized_keys
```

(B) jeder andere Zielhost:

```sh
printf 'restrict,from="%s",command="/usr/local/libexec/sshbite/sshbite-gate" %s\n' '<ENTRY-HOST-IP>' "$(cat /root/audit_ed25519.pub)" > /home/sshbite/.ssh/authorized_keys
```

(C) Zwischenstation bei `crawl.chain_fallback`:

```sh
printf 'restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="%s",command="/usr/local/libexec/sshbite/sshbite-gate" %s\n' '<PREVIOUS-HOP-IP>' "$(cat /root/audit_ed25519.pub)" > /home/sshbite/.ssh/authorized_keys
```

Dann:

```sh
chown root:root /home/sshbite/.ssh/authorized_keys && chmod 0644 /home/sshbite/.ssh/authorized_keys
```

- `<SCANNER-IP>`: die Adresse, mit der der Einstiegshost den Scanner-Rechner sieht. **Bei Docker ist das
  die Adresse des Docker-Hosts**, denn der Container verbindet sich über die NAT des Docker-Hosts. Ein CIDR
  ist erlaubt, mehrere Einträge trennen Sie mit Komma (`from="192.0.2.10,192.0.2.11"`).
- `<ENTRY-HOST-IP>`: die Adresse des Einstiegshosts *im Netz dieses Zielhosts*.
- `<PREVIOUS-HOP-IP>`: die Adresse der vorherigen Zwischenstation.

**Nur Einstiegshost und Hosts der Variante C:** Fügen Sie in `/etc/ssh/sshd_config` am Ende diesen Block
ein. Er verbietet Weiterleitungen auf Unix-Sockets, die `authorized_keys` nicht abdecken kann:

```text
Match User sshbite
    AllowTcpForwarding local
    AllowStreamLocalForwarding no
```

Prüfen und laden Sie sshd neu. Der Dienst heißt auf Debian `ssh`, auf RHEL und AlmaLinux `sshd`:

```sh
sshd -t && systemctl reload ssh      # RHEL/AlmaLinux: systemctl reload sshd
```

Steht in `sshd_config` eine Zeile `AllowUsers` oder `AllowGroups`, nehmen Sie `sshbite` dort auf.

**Prüfung** (auf dem Zielhost, als root):

```sh
sudo -l -U sshbite
stat -c '%U %a %n' /usr /usr/local /usr/local/libexec /usr/local/libexec/sshbite/*
command -v setpriv
```

Ausgabe auf dem Einstiegshost des Lab-Testlaufs (Debian 12):

```text
User sshbite may run the following commands on jump:
    (root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
root 755 /usr
root 755 /usr/local
root 755 /usr/local/libexec
root 755 /usr/local/libexec/sshbite/sshbite-collect
root 755 /usr/local/libexec/sshbite/sshbite-gate
root 755 /usr/local/libexec/sshbite/sshbite-resolve
/usr/bin/setpriv
```

- `sha256sum -c` meldet fünfmal `OK`, `visudo -cf` meldet `/etc/sudoers.d/sshbite: parsed OK`.
- `sudo -l -U sshbite` listet **nur** `(root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""`.
- `stat` zeigt überall `root` und keine Schreibrechte für Gruppe oder andere (`755`): Die sudo-Regel ist
  nur sicher, wenn die Datei und jedes Verzeichnis darüber root gehören.
- `command -v setpriv` gibt `/usr/bin/setpriv` aus.

<a id="the-authorized_keys-variants"></a>

### Die authorized_keys-Varianten

`authorized_keys.sshbite` aus dem Export enthält die drei Varianten:

```text
# (A) entry host: login only from the scanner, forwarding only to SSH ports (add permitopen="*:<PORT>" per extra SSH port)
restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="<SCANNER-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>
# (B) every other host: login only from the entry host, no forwarding
restrict,from="<ENTRY-HOST-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>
# (C) only for crawl.chain_fallback: intermediate hops, from = previous hop; no remote listener as in (A)
restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="<PREVIOUS-HOP-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>
```

- **A** gilt für den Einstiegshost. Er erlaubt Anmeldung nur vom Scanner-Rechner und Weiterleitung nur zu
  SSH-Ports. Für jeden weiteren SSH-Port ergänzen Sie `permitopen="*:<PORT>"`.
- **B** gilt für jeden anderen Zielhost: Anmeldung nur vom Einstiegshost, keine Weiterleitung.
- **C** gilt für Hosts, über die SSHBITE Hosts erreicht, die der Einstiegshost nicht erreicht
  (`crawl.chain_fallback`). Ein über eine solche Zwischenstation erreichter Host braucht in `from=` deren
  Adresse. Zeigt ein Scan einen Host als `auth_failed` mit einer Route über eine Zwischenstation, prüfen Sie
  das `from=` dieses Hosts.
- Einstiegshost und C-Hosts brauchen für dieses Konto `AllowTcpForwarding yes` oder `local` – der
  `Match`-Block oben setzt `local`.
- **Weiterleitung auf dem Zielhost (`ssh -R`):** A und C erlauben Weiterleitung nur *zu* SSH-Ports
  (`-L`, so durchsucht SSHBITE das Netz). `permitlisten="localhost:22"` lehnt jeden TCP-Listener ab, den der
  Schlüsselinhaber anfordert: `authorized_keys` kennt hier kein `none` (sshd verwirft dann die ganze
  Zeile), und `localhost:22` ist der Port von sshd selbst, kann also nie geöffnet werden (geprüft auf
  Debian 12 / OpenSSH 9.2 und AlmaLinux 9 / OpenSSH 9.9). Für Listener auf einem Unix-Socket
  (`ssh -R /tmp/x.sock:…`) hat OpenSSH keine `authorized_keys`-Option; das schließt der `Match`-Block
  (`AllowStreamLocalForwarding no`, im Lab auf beiden Systemen geprüft: Unix- und TCP-Listener abgelehnt,
  `-L` zu Port 22 und der Collector funktionieren).

SSHBITE blendet den Audit-Schlüssel in seinen eigenen Ergebnissen aus (`rules.ignore_audit_key: true`):
Seine `authorized_keys`-Zeilen erscheinen nicht als Zugriffskanten (access edges) oder Befunde (findings).

<a id="an-account-sshbite-that-existed-before"></a>

### Ein bereits vorhandenes Konto sshbite

Nach einem Sicherheitsvorfall versteckt sich in einem alten Konto `sshbite` gern ein übrig gebliebener
Schlüssel oder eine Gruppe. Die Installation oben macht Home und `.ssh` zu Dateien von root und ersetzt
`authorized_keys`, lässt aber alle anderen Dateien, die Gruppen und die Login-Shell, wie sie waren. Prüfen
Sie jeden Punkt und entfernen Sie, was übrig ist (als root):

```sh
getent passwd sshbite | cut -d: -f7       # muss /bin/sh ausgeben (usermod -s /bin/sh sshbite oben)
id sshbite                                # nur die eigene Gruppe – kein sudo, wheel, admin, adm, docker, lxd, ...
gpasswd -d sshbite wheel                  # für jede weitere Gruppe, die id zeigt (hier: wheel)
ls -la ~sshbite ~sshbite/.ssh             # was liegt dort
ls -A ~sshbite/.ssh                       # muss genau authorized_keys ausgeben
rm -i ~sshbite/.ssh/authorized_keys2      # und jede andere Datei in .ssh (alte Schlüssel, rc, environment, config)
crontab -l -u sshbite; ps -u sshbite      # keine Cron-Jobs, keine laufenden Prozesse des Kontos
sshd -T | grep -Ei 'authorizedkeysfile|acceptenv|permituserenvironment'
```

- **`authorized_keys2` und andere Dateien in `.ssh`:** sshd liest standardmäßig auch
  `.ssh/authorized_keys2` (Debian: `AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2`). Eine
  Schlüsselzeile dort hat kein `command=` und kein `from=`: Sie meldet sich in einer normalen Shell als
  `sshbite` an, und dieses Konto darf den Collector als root starten. In `.ssh` darf nur
  `authorized_keys` liegen.
- **Gruppen:** Eine Gruppe wie `sudo` oder `wheel` bringt sudo-Regeln für alle Mitglieder zurück;
  `sudo -l -U sshbite` darf weiterhin nur den Collector auflisten. Andere Gruppen (`docker`, `lxd`, `disk`,
  `adm`) geben root oder für root lesbare Daten ohne sudo.
- **Andere Dateien im Home** (`.profile`, `.bashrc`, …): Sie werden nicht ausgeführt – der erzwungene
  Befehl läuft über `/bin/sh -c`, das keine Startdatei liest, und `restrict` verhindert `~/.ssh/rc`.
  Entfernen Sie sie, wenn Sie ein sauberes Home wollen; das Konto kann sie nicht mehr ändern (das Home
  gehört root).
- **`sshd -T`**, die erwartete Ausgabe:

  ```text
  authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
  acceptenv LANG
  acceptenv LC_*
  permituserenvironment no
  ```

  `authorizedkeysfile` nennt die Dateien, die sshd für jedes Konto liest – jede davon muss in `~sshbite`
  fehlen, außer `authorized_keys` (oder dem Pfad, den Sie stattdessen nutzen). `acceptenv` darf nur
  Locale-Variablen nennen (`LANG`, `LC_*`, auf RHEL auch `LANGUAGE` und `XMODIFIERS`) oder nichts; nie
  `*`, `PATH`, `LD_*` oder `BASH_ENV`. `permituserenvironment` muss `no` sein, sonst würde
  `~/.ssh/environment` gelesen.

<a id="prerequisite-util-linux"></a>

### Voraussetzung: util-linux

Der Collector ist ein POSIX-`sh`-Skript und braucht die üblichen Basiswerkzeuge (`stat`, `head`, `awk`,
`getent`, `ssh-keygen`, `sshd`). Dateien in Benutzer-Homes (`~/.ssh` und jeden Pfad aus
`AuthorizedKeysFile`) liest er als deren Besitzer, mit `setpriv` aus util-linux (`/usr/bin/setpriv`, auf
Debian ab 10 und RHEL/EL ab 8 Teil des Basissystems). So bringt ein Benutzer, der eine Datei gegen einen
Symlink tauscht, nichts in den Scan, was er nicht selbst lesen dürfte
([review.md](review.md#dateien-in-home-verzeichnissen-werden-als-ihr-besitzer-gelesen)). Stellen Sie sicher, dass
`util-linux` auf jedem Host installiert ist. Das gilt für jeden `privilege.mode`.

Ohne `setpriv` liest der Collector **nicht** ersatzweise als root: Er liest dann nichts in Benutzer-Homes,
und der Host erscheint als `partial` mit dem Grund `setpriv (util-linux) missing: files in user homes not
read`. Host-Keys, sshd-Einstellungen und die Zusammenfassung von shadow werden trotzdem gesammelt.
Installieren Sie util-linux und scannen Sie erneut.

Eine Datei in einem Home, die ihr Besitzer nicht lesen kann – etwa eine `authorized_keys2`, die root gehört
und den Modus 0600 hat –, erscheint am Host als `unreadable by account: PATH`; der Host bleibt `ok`. sshd
liest authorized_keys ebenfalls als der Benutzer, die Schlüssel in so einer Datei wirken also nicht.
Korrigieren Sie den Besitzer oder entfernen Sie die Datei.

<a id="not-tested"></a>

### Nicht getestet

Das Lab prüft diesen Modus auf Debian 12 (OpenSSH 9.2, sudo 1.9.13, util-linux 2.38) und auf
AlmaLinux 9.9 (RHEL-kompatibel; OpenSSH 9.9, sudo 1.9.17, util-linux 2.37). Nicht getestet: SELinux im
Modus enforcing (die Lab-Container erzwingen es nicht), OpenSSH älter als 8.7 und Busybox-Systeme.

<a id="further-hardening-not-implemented"></a>

Weitere Härtung (nicht umgesetzt): den Collector nur mit CAP_DAC_READ_SEARCH statt als root laufen lassen.

<a id="pin-the-entry-host-key"></a>
<a id="config"></a>

## Host-Key festlegen und Konfiguration schreiben

SSHBITE scannt nur, wenn der Einstiegshost einen Host-Key vorzeigt, der in `entry.host_keys` steht
(festgelegter Host-Key, „pinnen“). Holen Sie den Schlüssel über das Netz und vergleichen Sie seinen
Fingerabdruck mit dem, den Sie **an der Konsole des Einstiegshosts** ablesen – nicht über denselben
Netzweg.

Auf dem Scanner-Rechner:

```sh
ssh-keyscan -t ed25519 -p 22 <ENTRY-HOST> 2>/dev/null | awk '!/^#/ {print $2" "$3}'
ssh-keygen -lf <(ssh-keyscan -t ed25519 -p 22 <ENTRY-HOST> 2>/dev/null)
```

An der Konsole des Einstiegshosts (oder über Ihr Out-of-Band-Management):

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

`<ENTRY-HOST>` ist der Name oder die Adresse des Einstiegshosts, wie der Scanner-Rechner ihn erreicht.
Der zweite Befehl braucht bash (`<(…)`). `awk '!/^#/ …'` überspringt die Kommentarzeile
`# <ENTRY-HOST>:22 SSH-2.0-OpenSSH_…`, die neuere `ssh-keyscan`-Versionen (z. B. OpenSSH 10.0) auf stdout
ausgeben, und schneidet den Hostnamen ab.

**Prüfung:** Beide Fingerabdrücke sind gleich. Im Lab:

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID/sbq+Iimhi7je22+U9y15jJ/37+NCH06PcVShHSmh/
256 SHA256:ynTb0gWnV8EppDctYzEhTtbjMnfZ2636k864CRGdTDg jump (ED25519)
```

Schreiben Sie dann die Konfiguration. Setzen Sie den Schlüssel aus der ersten Zeile **ohne Hostnamen**
ein, also als `"ssh-ed25519 <BASE64>"`. Eine Zeile mit Hostnamen davor lehnt SSHBITE ab
(`error: …: entry.host_keys[0]: not an OpenSSH public key line …`, Exit-Code 2):

```sh
cat > /etc/sshbite/sshbite.yaml <<'EOF'
database: /data/sshbite.db          # Pfad C: /var/lib/sshbite/sshbite.db
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
  include: [<CIDR-OF-YOUR-ESTATE>]   # leer = keine Einschränkung (mit Warnung)
EOF
```

- `<BASE64-FROM-KEYSCAN>`: die lange Zeichenkette aus der ersten Zeile der Ausgabe von `ssh-keyscan`.
- `<CIDR-OF-YOUR-ESTATE>`: die Netze, die SSHBITE durchsuchen darf, durch Komma getrennt, z. B.
  `[10.20.0.0/16, 192.0.2.0/24]`.
- `database:` – bei Docker (Pfad B) **muss** hier `/data/sshbite.db` stehen; bei Pfad C
  `/var/lib/sshbite/sshbite.db`.

Alle anderen Schlüssel haben Standardwerte, siehe [configuration.md](configuration.md).
`sshbite init-config` gibt eine vollständige, kommentierte Beispielkonfiguration aus. Sie dient nur als
Nachschlagewerk: Unverändert ist sie nicht gültig.

Jeder aufgeführte Schlüssel passt: Sie können den ed25519- und den ecdsa-Schlüssel zugleich festlegen, oder
bei einem Schlüsselwechsel den alten und den neuen. Bei einer Abweichung bricht der Scan mit Exit-Code 3
ab:

```text
error: ENTRY HOST KEY MISMATCH – scan aborted
  offered by jump:22: ssh-ed25519 SHA256:ynTb0gWnV8EppDctYzEhTtbjMnfZ2636k864CRGdTDg
  pinned: ssh-ed25519 SHA256:A3ZcCoVAi6MU3LodydM/OT0egxdhDBAMGsPlXEwcOCA
```

Die Host-Keys aller anderen Hosts werden beim ersten Kontakt vertraut (trust on first use) oder gegen eine
known_hosts-Datei geprüft, siehe `hostkeys` in [configuration.md](configuration.md#hostkeys).

**Prüfung:** Pfad B Schritt 8 ([Verbindung prüfen](#schritt-8-verbindung-prüfen)) oder Pfad C
(`config validate --connect`).

<a id="install-with-pip"></a>

## Pfad C: Nativ mit pip und systemd

SSHBITE läuft hier direkt auf dem Scanner-Rechner, als eigenes Systemkonto `sshbite-app`. Die Installation
aus dem Git-Checkout baut die Oberfläche mit `npm ci` und `npm run build`: **Node 22 mit npm ist dafür
nötig.** Das Repository enthält kein fertiges Wheel; Sie können aber auf einem Rechner mit Node eines
bauen (unten) und es ohne Node installieren.

> **Testumfang:** Die Installation mit pip, `sshbite --version`, `collector export`, `config validate
> --connect`, `user add`, `scan` und `serve` wurden mit Python 3.12 und Node 22 als normaler Benutzer
> ausgeführt. **Nicht getestet:** das Anlegen des Kontos `sshbite-app` mit `useradd`, die Rechte unter
> `sudo -u sshbite-app` und die systemd-Units.

Als root:

```sh
useradd --system --home-dir /var/lib/sshbite --shell /usr/sbin/nologin sshbite-app
install -d -m 0700 -o sshbite-app -g sshbite-app /var/lib/sshbite
git clone https://github.com/k0lp4tzki/SSHBITE.git /opt/sshbite-src && cd /opt/sshbite-src
python3.12 -m venv /opt/sshbite
/opt/sshbite/bin/pip install --require-hashes -r requirements-runtime.lock
/opt/sshbite/bin/pip install --no-deps .          # baut die Oberfläche: npm ci + npm run build (Node 22)
ln -s /opt/sshbite/bin/sshbite /usr/local/bin/sshbite
sshbite --version
```

**Prüfung:** Die letzte Zeile der zweiten pip-Installation ist `Successfully installed sshbite-0.1.0`,
`sshbite --version` gibt `sshbite, version 0.1.0` aus.

Mit Python 3.13 (3.13.18) liefen die Installation, `sshbite --version` und `config validate --connect`
ebenfalls fehlerfrei. Die Testsuite von SSHBITE läuft in der CI aber nur mit Python 3.12; nehmen Sie 3.12,
wenn Sie die Wahl haben.

Weiter wie bei Pfad B, mit diesen Unterschieden:

1. Audit-Schlüssel: [Pfad B Schritt 2](#schritt-2-audit-schlüssel-erzeugen), unverändert.
2. Collector exportieren – ohne Docker:

   ```sh
   mkdir sshbite-export
   sshbite collector export sshbite-export --collector-path /usr/local/libexec/sshbite/sshbite-collect
   cd sshbite-export && sha256sum -c SHA256SUMS && cd ..
   ```

   **Prüfung:** wie in [Pfad B Schritt 3](#schritt-3-collector-exportieren-und-prüfsummen-prüfen), mit
   `written to sshbite-export - verify with: cd sshbite-export && sha256sum -c SHA256SUMS`.
3. [Zielhosts vorbereiten](#zielhosts-vorbereiten-installierter-collector).
4. [Host-Key festlegen und Konfiguration schreiben](#host-key-festlegen-und-konfiguration-schreiben), mit
   `database: /var/lib/sshbite/sshbite.db`.
5. Dateien dem Konto geben, prüfen, Benutzer anlegen, scannen und die Oberfläche als Dienst starten:

   ```sh
   chown -R sshbite-app:sshbite-app /etc/sshbite && chmod 700 /etc/sshbite && chmod 600 /etc/sshbite/*
   sudo -u sshbite-app sshbite config validate --connect
   sudo -u sshbite-app sshbite user add admin
   sudo -u sshbite-app sshbite scan --label first
   cp docs/systemd/sshbite-serve.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now sshbite-serve.service
   ```

   Führen Sie jeden `sshbite`-Befehl als `sshbite-app` aus, damit die Datenbank diesem Konto gehört.
   SSHBITE legt die Datenbank mit dem Modus 0600 und ihr Verzeichnis mit 0700 an.

**Prüfung:** `config validate --connect` und `scan` geben dieselben Zeilen aus wie bei Pfad B
(Schritte 8 und 10). `journalctl -u sshbite-serve.service` zeigt
`SSHBITE UI on http://127.0.0.1:8722/  (database /var/lib/sshbite/sshbite.db)` (diese Zeile wurde ohne
systemd beobachtet). Die Oberfläche öffnen Sie wie in [Pfad B Schritt 11](#schritt-11-oberfläche-öffnen).
Den nächtlichen Scan richten Sie nach [operations.md](operations.md#nächtlicher-scan-mit-einem-systemd-timer)
ein.

Ein Wheel einmal bauen und anderswo ohne Node installieren:

```sh
/opt/sshbite/bin/pip wheel --no-deps -w dist .          # dist/sshbite-0.1.0-py3-none-any.whl
/opt/sshbite/bin/pip install --no-deps dist/sshbite-0.1.0-py3-none-any.whl   # nach requirements-runtime.lock wie oben
```

<a id="legacy-sudo-binsh--s-equivalent-to-full-root"></a>
<a id="sudoers"></a>

## Legacy-Modus: sudo /bin/sh -s (entspricht vollem Root-Zugriff)

**Warnung: Diese Einrichtung entspricht vollem Root-Zugriff für jeden, der den Audit-Schlüssel hat.**
Nutzen Sie sie nur, wo Sie keine Dateien auf den Hosts installieren können; ziehen Sie
[den installierten Collector](#zielhosts-vorbereiten-installierter-collector) vor. Die Lab-Demo
(Pfad A) läuft in diesem Modus.

Ohne root kann der Collector fremde `~/.ssh` und `/etc/shadow` nicht lesen; der Host ist dann `partial`.
Die Befehle, die SSHBITE mit sudo ausführt, stehen fest (siehe `sshbite collector show`). sudo wird immer
mit absolutem Pfad aufgerufen – `/usr/bin/sudo`, oder `/bin/sudo` nur, wo es `/usr/bin/sudo` nicht gibt
(entschieden durch ein festes `test -x` auf dem Host, nie durch den `PATH` des Audit-Kontos); die Tabelle
kürzt das zu `sudo`:

| `privilege.mode` | Probe | Collector |
|---|---|---|
| `sudo` (Standard) | `sudo -n /bin/true` | `sudo -n /bin/sh -s` |
| `sudo-login` | `sudo -n -i /bin/true` | `sudo -n -i /bin/sh -s` |
| (mit sudo-Passwort) | `sudo -S -k -p '' /bin/true` | `sudo -S -k -p '' /bin/sh -s` |
| `none` | – | `/bin/sh -s` (ohne Rechte) |

### Konto und Schlüssel im Legacy-Modus

Legen Sie auf jedem Zielhost, auch dem Einstiegshost, das Konto mit dem öffentlichen Audit-Schlüssel an –
mit Ihrem Konfigurationsmanagement oder von Hand:

```sh
useradd --create-home --shell /bin/sh sshbite
install -d -m 0700 -o sshbite -g sshbite ~sshbite/.ssh
printf 'restrict %s\n' "$(cat audit_ed25519.pub)" > ~sshbite/.ssh/authorized_keys
chown sshbite:sshbite ~sshbite/.ssh/authorized_keys; chmod 600 ~sshbite/.ssh/authorized_keys
```

Das Konto braucht eine POSIX-Shell (`/bin/sh`): SSHBITE schickt sein Collector-Skript auf stdin an
`/bin/sh -s`. `restrict` passt auf jedem Host: Es schaltet pty, Agent, X11 und Port-Weiterleitung ab.
**Auf dem Einstiegshost und auf Zwischenstationen** öffnet SSHBITE `direct-tcpip`-Kanäle zum nächsten
Host; verwenden Sie dort `restrict,port-forwarding` (oder keine Optionen) statt `restrict`, und sshd muss
für dieses Konto `AllowTcpForwarding yes` (oder `local`) erlauben.

Schränken Sie den Schlüssel mit `from="<ENTRY-HOST-IP>,<SCANNER-IP>"` ein. Mit `crawl.chain_fallback`
kann ein Host auch über den Host erreicht werden, der ihn gefunden hat – nehmen Sie diese
Zwischenstationen auf oder setzen Sie `chain_fallback: false`. Steht in `sshd_config` eine Zeile
`AllowUsers` oder `AllowGroups`, nehmen Sie `sshbite` dort auf.

### Die sudo-Regel im Legacy-Modus

Schreiben Sie dies nach `/etc/sudoers.d/sshbite` (Modus 0440, prüfen mit
`visudo -cf /etc/sudoers.d/sshbite`):

```text
# SSHBITE audit account: root for the read-only collector, no password, no lecture
Defaults:sshbite !lecture
sshbite ALL=(root) NOPASSWD: /bin/true, /bin/sh -s
```

Diese Zeile gilt für `privilege.mode: sudo`. Bei `sudo-login` startet sudo die Login-Shell von root mit dem
Befehl als `-c`-Argument; das lässt sich mit einer Befehlsliste nicht sauber ausdrücken – verwenden Sie
dort `NOPASSWD: ALL`.

Seien Sie sich im Klaren, was das gewährt: `/bin/sh -s` führt als root aus, was auf stdin ankommt. Die
Zeile **entspricht also vollem Root-Zugriff** für jeden, der den Audit-Schlüssel hat. Die Beschränkung auf
diese zwei Befehle dokumentiert nur die Absicht und hält andere Befehle aus dem sudo-Log. Schützen Sie den
Audit-Schlüssel entsprechend (Modus 0600, ein eigener Rechner, Einschränkung mit `from=`). Was SSHBITE
sendet, steht fest und ist prüfbar: [review.md](review.md).

### Konfiguration und Scan im Legacy-Modus

In der Konfiguration aus [Host-Key festlegen und Konfiguration schreiben](#host-key-festlegen-und-konfiguration-schreiben)
setzen Sie `privilege.mode: sudo` (oder `sudo-login`, `none`) und lassen `collector_path` weg. Die Prüfung
mit `config validate --connect` endet dann mit der kurzen Zeile:

```text
entry OK, pinned key matches, sudo: root
```

Verlangt Ihre Richtlinie ein sudo-Passwort, lassen Sie `NOPASSWD:` weg und scannen mit
`--ask-sudo-password` ([scanning.md](scanning.md#sudo-passwörter)). Die Abfrage braucht ein Terminal, bei
Docker also `docker exec -it`:

```sh
docker exec -it sshbite sshbite scan --ask-sudo-password      # Pfad C: sudo -u sshbite-app sshbite scan --ask-sudo-password
```

Mit den Debian-Standard-sudoers schickt sudo dann bei jedem Scan pro Host eine Mail
*„SECURITY information“*, weil die erste, nicht interaktive Probe abgelehnt wird
([side-effects.md](side-effects.md#die-incident-mail-bei-verweigertem-sudo)). Wo `sshbite` gar keine
sudo-Regel hat, wird der Host ohne Rechte gescannt und als `partial` markiert. Geben Sie dem Audit-Konto ein
eigenes Passwort, das nirgends sonst gilt, und wechseln Sie es nach dem Scan: Ein kompromittierter Host
kann eine sudo-Abfrage vortäuschen und es abgreifen ([operations.md](operations.md#das-sudo-passwort)).

<a id="switching-from-mode-sudo-or-from-a-hand-made-gate"></a>

### Wechsel vom Modus sudo (oder von einem selbst gebauten Gate)

1. Installieren Sie die Dateien auf allen Hosts (neues Gate, neue sudoers-Datei, neue `authorized_keys`;
   entfernen Sie die alten sudoers-Regeln), wie unter
   [Zielhosts vorbereiten](#zielhosts-vorbereiten-installierter-collector) beschrieben.
2. Setzen Sie erst dann `privilege.mode: installed` in der Konfiguration.

Scannen Sie nicht zwischen den beiden Schritten: Das neue Gate lehnt die Befehle der alten Modi mit Exit-Code
126 ab; ein Scan im Modus `sudo` gegen einen schon umgestellten Host endet mit
`no collector output: sshbite-gate: denied …`.

<a id="update"></a>
<a id="after-an-sshbite-update"></a>

## Aktualisierung

1. **Sichern** Sie die Datenbank (sicher im laufenden Betrieb):

   ```sh
   install -d -m 700 /var/backups/sshbite
   docker exec sshbite sshbite db backup /data/backup-$(date +%F).db
   docker cp sshbite:/data/backup-$(date +%F).db /var/backups/sshbite/
   docker exec sshbite rm /data/backup-$(date +%F).db
   ```

   Pfad C: `sudo -u sshbite-app sshbite db backup /var/lib/sshbite/backup-$(date +%F).db` (das Konto muss
   das Ziel schreiben dürfen, daher `/var/lib/sshbite`).

   **Prüfung:** `backup written to /data/backup-2026-11-27.db` (mit dem heutigen Datum).

2. **Neue Version bauen und starten.** Im Repository:

   ```sh
   git pull
   docker build -t sshbite:<NEW-VERSION> .
   ```

   Tragen Sie `<NEW-VERSION>` (die Version aus `pyproject.toml`, z. B. `0.2.0`) in der Zeile `image:` von
   `docs/compose.example.yaml` (oder Ihrer Kopie) ein und starten Sie neu:

   ```sh
   docker compose -f docs/compose.example.yaml up -d
   ```

   Pfad C: in `/opt/sshbite-src` `git pull`, dann die beiden `pip install`-Zeilen aus
   [Pfad C](#pfad-c-nativ-mit-pip-und-systemd) und `systemctl restart sshbite-serve.service`.

   Der erste Start der neuen Version stellt die Datenbank automatisch um. Vorher schreibt er eine Kopie
   neben die Datenbank, benannt nach der neuen Version, z. B. `/data/sshbite.db.pre-0.2.0`. Ohne anstehende
   Umstellung wird nichts geschrieben. Zurück zur alten Version: siehe
   [operations.md](operations.md#aktualisierung).

3. **Collector neu verteilen.** Exportieren Sie in ein neues, leeres Verzeichnis
   ([Pfad B Schritt 3](#schritt-3-collector-exportieren-und-prüfsummen-prüfen), mit dem neuen Image-Tag)
   und vergleichen Sie mit dem alten Export:

   ```sh
   diff sshbite-export/SHA256SUMS sshbite-export-<NEW-VERSION>/SHA256SUMS
   ```

   Hat sich `sshbite-collect` geändert, installieren Sie auf jedem Zielhost die neue Datei (und Gate,
   Resolve oder sudoers-Datei, falls auch deren Prüfsumme anders ist):

   ```sh
   cd /root/sshbite-export && sha256sum -c SHA256SUMS
   install -m 0755 -o root -g root sshbite-collect /usr/local/libexec/sshbite/
   ```

   Bis dahin meldet jeder Host `installed collector version differs from this SSHBITE …` und erscheint als
   `collector_error`.

4. **Prüfen und scannen:**

   ```sh
   docker exec -it sshbite sshbite config validate --connect
   docker exec sshbite sshbite scan --label after-update
   ```

   **Prüfung:** dieselben Zeilen wie in [Pfad B Schritt 8](#schritt-8-verbindung-prüfen), mit der neuen
   Collector-Prüfsumme `B=…`.

<a id="uninstall"></a>

## Deinstallation

Sichern Sie vorher die Datenbank, wenn Sie die Ergebnisse behalten wollen ([Aktualisierung](#aktualisierung),
Schritt 1).

**Scanner-Rechner, Pfad B** (im Repository, als root):

```sh
docker compose -f docs/compose.example.yaml down -v      # Container und Volume sshbite-data mit der Datenbank
docker image rm sshbite:0.1.0
rm -r /etc/sshbite
```

Ohne `-v` bleibt das Volume `sshbite-data` mit der Datenbank erhalten.

**Scanner-Rechner, Pfad C** (als root; nicht getestet):

```sh
systemctl disable --now sshbite-serve.service sshbite-scan.timer
rm /etc/systemd/system/sshbite-*.service /etc/systemd/system/sshbite-scan.timer
systemctl daemon-reload
rm -r /opt/sshbite /opt/sshbite-src /usr/local/bin/sshbite /var/lib/sshbite /etc/sshbite
userdel sshbite-app
```

**Jeder Zielhost** (als root):

```sh
rm /etc/sudoers.d/sshbite
rm -r /usr/local/libexec/sshbite
rm /home/sshbite/.ssh/authorized_keys
userdel -r sshbite             # nur, wenn das Konto allein für SSHBITE angelegt wurde ...
rm -r /home/sshbite            # ... dann auch das Home: es gehört root, userdel -r lässt es stehen
rm -r /root/sshbite-export /root/audit_ed25519.pub
```

Entfernen Sie auf dem Einstiegshost und den C-Hosts den Block `Match User sshbite` aus
`/etc/ssh/sshd_config` und laden Sie sshd neu (`sshd -t && systemctl reload ssh`, auf RHEL/AlmaLinux
`sshd`). Nehmen Sie `sshbite` aus `AllowUsers`/`AllowGroups`, falls Sie es dort eingetragen haben.

**Prüfung** auf dem Zielhost: Direkt nach den drei `rm`-Befehlen meldet `sudo -l -U sshbite`

```text
User sshbite is not allowed to run sudo on a1.
```

`userdel -r sshbite` meldet dabei `userdel: /home/sshbite not owned by sshbite, not removing` – deshalb das
`rm -r /home/sshbite`. Danach meldet `id sshbite` `id: 'sshbite': no such user`. Der nächste Scan zeigt
den Host als `auth_failed`.

**Testumgebung:** `docker compose -f compose.lab.yaml down -v`; das Entwickler-Lab aus `lab/up.sh` mit
`docker compose -f lab/compose.yaml down -v`.

<a id="troubleshooting"></a>

## Fehlerbehebung

| Symptom | Ursache | Abhilfe |
|---|---|---|
| `internal error: PermissionError: [Errno 13] Permission denied: '/out/sshbite-collect'`, Exit-Code 4, bei `collector export` | Docker hat das Export-Verzeichnis als root angelegt, der Container läuft mit Ihrer uid. | Verzeichnis vorher mit `mkdir sshbite-export` anlegen ([Schritt 3](#schritt-3-collector-exportieren-und-prüfsummen-prüfen)). |
| `error: export directory is not empty: …`, Exit-Code 2 | Das Export-Verzeichnis ist nicht leer. | Ein neues, leeres Verzeichnis nehmen. |
| `subsystem request failed on channel 0` und `scp: Connection closed` beim Kopieren auf den Zielhost | Neuere `scp` übertragen per SFTP; der sshd des Zielhosts bietet kein SFTP-Subsystem an. | `scp -O` (altes SCP-Protokoll) verwenden, oder die Dateien mit Ihrem Konfigurationsmanagement verteilen. |
| `error: audit.key_file: /etc/sshbite/audit_ed25519: mode is 0644, must be 0600 (chmod 600 /etc/sshbite/audit_ed25519)`, Exit-Code 2 | Der Audit-Schlüssel hat nicht den Modus 0600 oder gehört nicht dem Konto, das SSHBITE ausführt (10001 bei Docker, `sshbite-app` bei Pfad C). | [Pfad B Schritt 6](#schritt-6-dateien-dem-container-benutzer-geben) bzw. `chown` aus Pfad C wiederholen. |
| `error: ENTRY HOST KEY MISMATCH – scan aborted`, Exit-Code 3 | Der Einstiegshost zeigt einen anderen Host-Key als festgelegt. | Nicht einfach übernehmen: Fingerabdruck an der Konsole prüfen ([Host-Key festlegen](#host-key-festlegen-und-konfiguration-schreiben)). |
| `error: entry.host_keys: missing - pin the entry host key (scan aborts without it)` | Kein Host-Key festgelegt. | [Host-Key festlegen](#host-key-festlegen-und-konfiguration-schreiben). |
| `sudo: FAILED - …`, Exit-Code 3, bei `config validate --connect` | Der Einstiegshost ist nicht richtig vorbereitet. | Meldung in [Fehlermeldungen im Modus installed](#fehlermeldungen-im-modus-installed) nachschlagen. |
| `error: entry <ENTRY-HOST>:22 authentication failed: authentication failed: Permission denied for user sshbite on host <ENTRY-HOST>`, Exit-Code 3 | Das Audit-Konto lehnt den Schlüssel ab: falsche `from=`-Adresse, `authorized_keys` fehlt oder hat falschen Besitzer/Modus. | Bei Docker steht in `from=` die Adresse des Docker-Hosts; `authorized_keys` root:root 0644. |
| Container startet immer neu, oder `internal error: OSError: [Errno 30] Read-only file system: '/var/lib/sshbite'`, Exit-Code 4 | `database:` steht nicht auf `/data/sshbite.db`; der Container darf außerhalb von `/data` nicht schreiben. | `database: /data/sshbite.db` eintragen, `docker compose -f docs/compose.example.yaml up -d`. |
| Docker meldet beim Start, dass Port 8722 schon belegt ist (`port is already allocated`; nicht beobachtet) | Die Lab-Demo (Pfad A) oder ein anderer Dienst nutzt `127.0.0.1:8722`. | `docker compose -f compose.lab.yaml down -v`. |
| `error: privilege.mode installed never sends a sudo password - remove --ask-sudo-password`, Exit-Code 2 | Im Modus installed sendet SSHBITE kein sudo-Passwort. | Ohne die Option scannen: `docker exec sshbite sshbite scan`. |
| `Error: refusing to read the password: stdin is not a terminal, so the password could be echoed or logged. …` | Passwortabfrage ohne Terminal. | `docker exec -it` statt `-i`, oder `--password-stdin`. |
| `Error: the password must have at least 12 characters` | Passwort kürzer als 12 Zeichen. | Längeres Passwort wählen. |
| Lab: keine Zeile `LAB DEMO LOGIN` im Log | Der Benutzer `admin` existiert aus einem früheren Start (Volume `sshbite-lab-data`). | `docker compose -f compose.lab.yaml down -v`, dann neu starten. |
| Lab: Container `sshbite` startet immer neu (aus `lab/demo/start.sh` abgeleitet, nicht beobachtet) | `SSHBITE_DEMO_PASSWORD` ist kürzer als 12 Zeichen oder `sshbite-lab-demo`. | Variable entfernen oder ein Passwort mit mindestens 12 Zeichen setzen. |
| Host `partial`, Grund `setpriv (util-linux) missing: files in user homes not read` | util-linux fehlt auf dem Zielhost. | util-linux installieren ([Voraussetzung](#voraussetzung-util-linux)). |
| Host `collector_error` | Zielhost nicht oder unvollständig vorbereitet, oder alter Collector nach einer Aktualisierung. | Meldung am Host (Oberfläche **Hosts** oder `sshbite scans show latest`) in der Tabelle unten nachschlagen. |
| `docker compose -f compose.lab.yaml …` lehnt den Schlüssel `include` ab (nicht beobachtet) | Docker Compose älter als v2.20 kennt `include` nicht. | Docker Compose auf v2.20 oder neuer aktualisieren (`docker compose version`). |
| `frontend/ is not built and npm is not available: install Node 22 or build it first` (Pfad C) | npm fehlt beim `pip install`. | Node 22 mit npm installieren. |

<a id="error-messages"></a>

### Fehlermeldungen im Modus installed

Im Modus installed fällt ein Host nie auf `partial`/`unprivileged` zurück. Stimmt etwas nicht, ist er
`collector_error` – in der Oberfläche und in `sshbite scans show` – mit einer dieser Meldungen
(P = der Collector-Pfad, `<l>` = die erste Zeile von stderr):

| Meldung | Bedeutung und Abhilfe |
|---|---|
| `privilege.mode installed: refused by sshbite-gate on this host: <l>` | Das Gate hat den Befehl abgelehnt: `privilege.collector_path` weicht vom Pfad ab, für den das Gate exportiert wurde, oder ein altes Gate ist installiert. Mit dem richtigen Pfad exportieren und das neue Gate installieren. |
| `privilege.mode installed: sudo asks for a password - the sudoers rule for P must be NOPASSWD` | sudo will ein Passwort. Entweder fehlt der Regel `NOPASSWD:`, oder `/etc/sudoers.d/sshbite` fehlt ganz – sudo antwortet in beiden Fällen gleich. `sudoers.d-sshbite` installieren und mit `sudo -l -U sshbite` prüfen. |
| `privilege.mode installed: collector not installed at P` | Die sudo-Regel gibt es, die Datei nicht. `sshbite-collect` unter P installieren. |
| `privilege.mode installed: sudo does not allow P for this account (sudo -n -l exit <rc>: <l>)` | sudo hat Regeln für `sshbite`, aber keine für P (`<l>` ist dann oft leer). `sudoers.d-sshbite` installieren und die anderen Regeln entfernen. |
| `privilege.mode installed: installed collector version differs from this SSHBITE (expected B=<x>, host has B=<y>) - run 'sshbite collector export' and reinstall sshbite-collect` | Auf dem Host liegt der Collector einer anderen SSHBITE-Version. Siehe [Aktualisierung](#aktualisierung), Schritt 3. |
| `no collector output: <l>` | Der Collector hat nichts Verwertbares ausgegeben; `<l>` sagt, warum. |

## Anhang: Pfad B in der Testumgebung üben (nur Lab)

Dieser Anhang gilt **nur für die Testumgebung**. Für echte Systeme gilt Pfad B oben unverändert.

Im Lab steht der Einstiegshost `jump` auf `172.30.1.5` im Docker-Netz `lab_a`. Damit der Container aus
`compose.example.yaml` ihn erreicht, muss er an dieses Netz angeschlossen werden; das ist der einzige
Unterschied zur Produktionsdatei. Der Ablauf, mit dem diese Anleitung geprüft wurde:

1. Lab-Hosts starten ohne die Lab-Demo (sonst ist Port 8722 belegt): `sh lab/up.sh` (startet
   `docker compose -f lab/compose.yaml up -d --build --wait`).
2. Pfad B Schritte 1–3 unverändert.
3. Den Einstiegshost `jump` nach [Zielhosts vorbereiten](#zielhosts-vorbereiten-installierter-collector)
   von Hand vorbereiten (Variante A, Root-Shell im Container: `docker exec -u 0 -it sshbite-lab-jump-1 sh`).
   In `from=` steht die Adresse des SSHBITE-Containers im Netz `lab_a`. Der Lab-Container hat kein systemd:
   statt `systemctl reload ssh` lädt `kill -HUP 1` die sshd-Konfiguration neu. Die übrigen Hosts bringt
   `lab/installed.sh apply` in denselben Zustand; die Varianten und `from=`-Adressen je Host stehen in
   `tests/e2e/test_lab_installed.py` (Tabelle `AK`).
4. In der Konfiguration: `entry.host: 172.30.1.5`, der Host-Key von `jump`,
   `crawl.include: [172.30.1.0/24, 172.30.2.0/24, 172.30.3.0/24]`.
5. Den Container zusätzlich an `lab_a` anschließen, z. B. mit einer zweiten Compose-Datei
   `lab-netz.yaml`:

   ```yaml
   # nur Testumgebung: SSHBITE an das Lab-Netz lab_a anschließen
   services:
     sshbite:
       networks: [lab_a]
   networks:
     lab_a:
       name: sshbite-lab_lab_a
       external: true
   ```

   ```sh
   docker compose -f docs/compose.example.yaml -f lab-netz.yaml up -d
   ```

So geprüft wurde: die Produktionsdatei `compose.example.yaml` unverändert bis auf zwei Dinge – den
Anschluss an `lab_a` mit fester Adresse und `/etc/sshbite` aus einem Volume statt vom Docker-Host. Die
`docker exec`-Befehle liefen in einem zweiten Container desselben Images mit denselben Volumes. Die
Datei `lab-netz.yaml` in genau dieser Form wurde nicht ausgeführt (nicht getestet).
