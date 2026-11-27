<a id="rollout"></a>

# Einrichtung mit einem Skript: sshbite-rollout

`tools/rollout/sshbite-rollout` erledigt die Schritte aus [install.md](install.md) in einem Durchgang: Es
prüft die Voraussetzungen, zeigt, was es ändern würde, richtet den Scanner-Rechner und alle Hosts ein und
prüft das Ergebnis. Es läuft als root auf dem Scanner-Rechner, aus einem Checkout dieses Repositorys.

Inhalt: [Kurzfassung](#kurzfassung) · [Was das Skript tut](#was-das-skript-tut) ·
[rollout.conf](#rolloutconf) · [rollout.hosts](#rollouthosts) ·
[Scanner-Rechner und Einstiegshost auf einem Rechner](#scanner-rechner-und-einstiegshost-auf-einem-rechner) ·
[Der Name des Audit-Kontos](#der-name-des-audit-kontos) · [Wo das Skript anhält](#wo-das-skript-anhält) ·
[SUSE](#suse-linux-enterprise-und-opensuse) · [Entfernen](#entfernen) · [Testumfang](#testumfang)

## Kurzfassung

```sh
git clone https://github.com/k0lp4tzki/SSHBITE.git && cd SSHBITE
tools/rollout/sshbite-rollout init       # schreibt /etc/sshbite/rollout.conf und rollout.hosts
# beide Dateien ausfüllen: Kontoname, Einstiegshost, Netze, Liste der Hosts
tools/rollout/sshbite-rollout check      # Voraussetzungen hier und auf jedem Host      - ändert nichts
tools/rollout/sshbite-rollout plan       # alles, was apply ändern würde                - ändert nichts
tools/rollout/sshbite-rollout apply      # einrichten und das Ergebnis prüfen
tools/rollout/sshbite-rollout validate   # später: Hosts und Verbindung erneut prüfen   - ändert nichts
```

Danach legen Sie die Anmeldung für die Oberfläche an und starten den ersten Scan; `apply` gibt beide
Befehle am Ende aus. Lesen Sie vor dem ersten echten Scan [side-effects.md](side-effects.md).

`apply` können Sie beliebig oft wiederholen: Was schon stimmt, bleibt unberührt. Jede Zeile der Ausgabe
beginnt mit einem Kennzeichen:

| Kennzeichen | Bedeutung |
|---|---|
| `OK` | ist so, wie es sein soll |
| `PLAN` | `apply` würde das ändern |
| `DONE` | `apply` hat das geändert |
| `WARN` | funktioniert, aber sehen Sie es sich an |
| `FAIL` | braucht Ihre Entscheidung oder einen Handgriff; auf diesem Host wird nichts geändert |

Der Exit-Code ist 0, wenn nichts mit `FAIL` endet, sonst 1; bei einem Fehler in den Dateien oder Optionen 2.

## Was das Skript tut

**Auf dem Scanner-Rechner**

1. Es prüft `ssh`, `ssh-keygen`, `ip` und – je nach `MODE` – Docker oder Python 3.12 mit Node 22, und nennt
   den Befehl, der ein fehlendes Paket installiert.
2. Es erzeugt den Audit-Schlüssel `/etc/sshbite/audit_ed25519`, falls es ihn noch nicht gibt.
3. Es baut das Image `sshbite:<Version>` (`MODE=docker`) oder installiert SSHBITE nach `/opt/sshbite`
   (`MODE=native`).
4. Es exportiert den Collector für Ihren Kontonamen und Collector-Pfad (`sshbite collector export`) und
   prüft die Prüfsummen.
5. Nach den Hosts: Es schreibt `/etc/sshbite/sshbite.yaml` mit den festgelegten Host-Keys des
   Einstiegshosts und `/etc/sshbite/seeds.hosts` mit den Hosts aus `rollout.hosts`
   ([`seeds.hosts_file`](configuration.md#seeds)): Jeder eingerichtete Host wird gescannt, auch wenn kein
   anderer Host auf ihn verweist. Dann gibt es Schlüssel und Konfiguration dem Konto, unter dem SSHBITE
   läuft, startet den Container bzw. den systemd-Dienst und ruft `sshbite config validate --connect` auf.

Eine `sshbite.yaml`, die Sie von Hand geändert haben, überschreibt das Skript nicht: Es zeigt den
Unterschied und schreibt sie nur mit `--write-config` neu (die alte Fassung kommt nach
`/var/lib/sshbite-rollout/backup/`).

**Auf jedem Host** (zuerst dem Einstiegshost), über die Admin-Anmeldung per SSH:

1. Voraussetzungen: `sudo`, `visudo`, `sshd`, `setpriv` (util-linux), OpenSSH ab 7.8, `/etc/sudoers.d`
   eingebunden.
2. Audit-Konto anlegen: eigene Gruppe, Shell `/bin/sh`, Passwort gesperrt.
3. Collector, Gate und Namensauflösung installieren, mit Prüfsumme; jedes Verzeichnis darüber muss root
   gehören.
4. Die sudo-Regel `/etc/sudoers.d/sshbite` installieren (vorher mit `visudo -cf` geprüft).
5. Home und `.ssh` an root geben, `authorized_keys` mit genau einer Zeile schreiben – Variante A für den
   Einstiegshost, B für jeden anderen Host, C für eine Zwischenstation
   ([Varianten](install.md#die-authorized_keys-varianten)).
6. Einstiegshost und Zwischenstationen: den Block `Match User <konto>` eintragen, `sshd -t`, sshd neu laden.
7. Prüfen: `sudo -l -U <konto>` nennt nur den Collector; für das Konto gelten die sshd-Einstellungen; für
   alle anderen Konten hat sich nichts geändert.

Die Dateien kommen nicht per `scp` auf den Host: Das Skript schickt ein einziges Shell-Skript mit den
eingebetteten Dateien über die SSH-Verbindung an `sh -s`. Der Teil, der auf dem Host läuft, ist
[`tools/rollout/host-agent.sh`](../tools/rollout/host-agent.sh) – lesen Sie ihn, bevor Sie ihn als root
ausführen lassen. Alte Fassungen geänderter Dateien liegen auf dem Host unter
`/var/lib/sshbite-rollout/backup/<Zeitpunkt>/`.

**Die Host-Keys des Einstiegshosts** liest das Skript auf dem Einstiegshost selbst (`sshd -T`, dann die
`.pub`-Dateien) – lokal, wenn der Scanner-Rechner der Einstiegshost ist, sonst über Ihre
Admin-SSH-Verbindung. Diese Verbindung prüft den Host-Key gegen Ihre `known_hosts`; das Skript schaltet
diese Prüfung nicht ab. Kennt der Scanner-Rechner einen Host noch nicht, hält das Skript dort an und nennt
den Befehl, mit dem Sie den Fingerabdruck einmal von Hand bestätigen.

## rollout.conf

`/etc/sshbite/rollout.conf`, eine Zeile je Einstellung (`NAME=wert`). Die Datei wird gelesen, nicht
ausgeführt. Eine andere Datei wählen Sie mit `-c DATEI`.

| Einstellung | Standard | Bedeutung |
|---|---|---|
| `AUDIT_USER` | `sshbite` | Name des Audit-Kontos auf allen Hosts, siehe [unten](#der-name-des-audit-kontos). |
| `MODE` | `docker` | `docker`: SSHBITE läuft als Container. `native`: venv in `/opt/sshbite` und systemd-Dienst (Konto `sshbite-app`). |
| `ENTRY_HOST` | – (Pflicht) | Der Einstiegshost, so wie der Scanner-Rechner ihn erreicht. |
| `ENTRY_PORT` | `22` | Sein SSH-Port. |
| `CRAWL_INCLUDE` | leer | Die Netze, die SSHBITE durchsuchen darf (`crawl.include`), durch Komma getrennt. Leer = keine Grenze, mit Warnung. |
| `COLLECTOR_PATH` | `/usr/local/libexec/sshbite/sshbite-collect` | `privilege.collector_path`. |
| `SSH_USER` | `root` | Konto, mit dem das Skript die Hosts einrichtet. Anmeldung per Schlüssel, ohne Passwortabfrage. |
| `SSH_SUDO` | `no` | `yes`: `SSH_USER` ist nicht root und darf `sudo` ohne Passwort. |
| `SSH_OPTS` | leer | Weitere ssh-Optionen, z. B. `-J admin@jump` oder `-i /root/.ssh/rollout`. |
| `SCANNER_FROM` | automatisch | Die Adresse, mit der der Einstiegshost den Scanner-Rechner sieht (für `from=`). Nur bei NAT oder mehreren Netzkarten nötig. |
| `ENTRY_FROM` | automatisch | Die Adresse, mit der die übrigen Hosts den Einstiegshost sehen. |
| `INVENTORY` | `rollout.hosts` neben `rollout.conf` | Die Liste der Hosts. |

## rollout.hosts

Eine Zeile je Host. Der Einstiegshost aus `rollout.conf` gehört immer dazu und muss nicht in der Liste
stehen.

```text
10.20.0.11
10.20.0.12 port=2222
db1.example.org user=admin
10.20.3.1 hop from=10.20.0.5
```

| Angabe | Bedeutung |
|---|---|
| `hop` | Zwischenstation für `crawl.chain_fallback` (Schlüsselzeile C). Braucht `from=` mit der Adresse der vorherigen Station. |
| `from=` | Die Adresse (oder das CIDR, mehrere mit Komma), von der sich SSHBITE an diesem Host anmeldet, wenn die Automatik nicht passt. |
| `port=` | SSH-Port für das Einrichten (Standard 22). |
| `user=` | Admin-Konto für das Einrichten (Standard `SSH_USER`). |

Mit `--host ADRESSE` (mehrfach möglich) arbeitet das Skript nur auf einzelnen Hosts; Konfiguration und
Dienst fasst es dann nur an, wenn der Einstiegshost dabei ist.

## Scanner-Rechner und Einstiegshost auf einem Rechner

Der Scanner-Rechner darf selbst der Einstiegshost sein: ein Server im Netz, der alle Hosts erreicht.
Tragen Sie als `ENTRY_HOST` **seine eigene Adresse im Netz** ein, nicht `127.0.0.1` – unter diesem Namen
erscheint er im Scan. Das Skript erkennt den Fall, richtet den Rechner ohne SSH direkt ein und liest
seine Host-Keys lokal.

- Die `from=`-Adressen bestimmt das Skript aus der Routing-Tabelle: für den Einstiegshost die eigene
  Adresse, für jeden anderen Host die Adresse, mit der dieser Rechner ihn erreicht.
- Mit `MODE=docker` startet das Skript den Container im Netz des Hosts (`--network host`) und die
  Oberfläche nur auf `127.0.0.1:8722`. In einem eigenen Docker-Netz käme die Anmeldung von der Adresse
  des Containers, die kein `from=` benennen kann. (`docs/compose.example.yaml` nutzt ein eigenes
  Docker-Netz und passt deshalb nicht zu diesem Fall.)
- Was es kostet: Der Audit-Schlüssel und die Datenbank mit allen Scan-Ergebnissen liegen auf demselben
  Rechner, auf dem auch der Collector als root läuft. Wer diesen Rechner übernimmt, hat den Schlüssel –
  das gilt für jeden Scanner-Rechner. Behandeln Sie ihn wie einen Admin-Server.

## Der Name des Audit-Kontos

Den Namen wählen Sie in `rollout.conf` mit `AUDIT_USER`, bevor Sie zum ersten Mal `apply` aufrufen:
Kleinbuchstaben, Ziffern, `_` und `-`, beginnend mit einem Buchstaben oder `_`, höchstens 32 Zeichen,
nicht `root`. Das Skript trägt ihn in die sudo-Regel, den sshd-Block und `audit.user` ein.

Ohne das Skript: `sshbite collector export DIR --audit-user NAME` schreibt die sudo-Regel für dieses
Konto; ohne die Option gilt `audit.user` aus der Konfiguration, sonst `sshbite`. Collector, Gate und
Namensauflösung hängen nicht vom Kontonamen ab und sind Byte für Byte dieselben. Die Datei der
sudo-Regel heißt immer `/etc/sudoers.d/sshbite`.

**Den Namen später ändern:** erst `sshbite-rollout remove --yes` mit dem alten Namen, dann `AUDIT_USER`
ändern und `apply`.

## Wo das Skript anhält

Das Skript ändert nichts, was es nicht vorher gezeigt hat, und rät nicht. In diesen Fällen meldet es
`FAIL` und lässt den Host unverändert:

| Fund | Abhilfe |
|---|---|
| Das Konto gibt es schon, und das Skript hat es nicht angelegt. Die Zeile nennt uid, Shell, Gruppen, Einträge im Home und Schlüsselzeilen. | `--adopt-existing-account` übernimmt es: Shell `/bin/sh`, Passwort gesperrt, raus aus Gruppen wie `sudo`, `wheel` oder `docker`, Home und `.ssh` an root, alles außer `authorized_keys` aus `.ssh` ins Backup. Oder einen anderen `AUDIT_USER` wählen. |
| Eine andere Datei in `/etc/sudoers.d` enthält Regeln für das Konto. | `--remove-foreign-sudoers` verschiebt sie ins Backup, wenn sie nur Regeln für dieses Konto enthält. Sonst die Zeilen von Hand entfernen. |
| `/etc/sudoers` selbst enthält eine Regel für das Konto. | Von Hand entfernen. |
| Ein Verzeichnis über dem Collector gehört nicht root oder ist für Gruppe oder andere schreibbar. | Rechte korrigieren oder `COLLECTOR_PATH` ändern. |
| `AllowUsers`/`AllowGroups` in der sshd-Konfiguration nennen das Konto nicht. | Dort aufnehmen. |
| `PermitUserEnvironment yes` oder ein `AcceptEnv` für `PATH`, `LD_*` und Ähnliches. | Abschalten: Damit ließe sich das Gate beeinflussen. |
| sshd liest für das Konto Schlüssel aus einer weiteren Datei außerhalb von `.ssh`. | Datei prüfen und entfernen. |
| Der `Match`-Block würde auch andere Konten ändern oder wirkt nicht (ein früherer `Match`-Block setzt die Werte). | Das Skript stellt die alte Datei wieder her; den Block von Hand eintragen. |
| `setpriv` fehlt. | util-linux installieren. |

Der Block für sshd steht zwischen den Zeilen `# BEGIN sshbite-rollout` und `# END sshbite-rollout` am
Ende von `/etc/ssh/sshd_config`. Gibt es diese Datei nicht (SUSE legt die Standardkonfiguration unter
`/usr/etc/ssh/` ab), schreibt das Skript `/etc/ssh/sshd_config.d/99-sshbite-rollout.conf`.

## SUSE Linux Enterprise und openSUSE

- **`Defaults targetpw` und `ALL ALL=(ALL) ALL`:** Die Standard-`/etc/sudoers` von SUSE erlaubt jedem
  Benutzer alles, wenn er das root-Passwort kennt. `sudo -l -U <konto>` zeigt diese Regel dann neben dem
  Collector an; das Skript meldet `WARN`. Der Audit-Schlüssel kann die Regel nicht nutzen: Das Gate lässt
  nur drei feste Befehle zu, und SSHBITE sendet nie ein Passwort. Ob Sie die beiden Zeilen
  auskommentieren, betrifft alle Benutzer und bleibt Ihre Entscheidung.
- **Die Reihenfolge zählt:** sudo nimmt die letzte passende Regel. Steht `ALL ALL=(ALL) ALL` in
  `/etc/sudoers` *hinter* der Zeile `@includedir /etc/sudoers.d`, überstimmt sie die Collector-Regel; sudo
  fragt dann nach einem Passwort, und der Scan meldet `sudo asks for a password`. Das Skript erkennt das
  und meldet `FAIL`. In der Standarddatei von SUSE steht die Regel vor der includedir-Zeile.
- **Pakete:** `check` nennt die Befehle (`SUSEConnect -p sle-module-containers/…`, `zypper install docker`).
  Die Paketnamen wurden nicht auf einem SLES-System geprüft; `zypper search` zeigt, was Ihr System anbietet.

## Entfernen

```sh
tools/rollout/sshbite-rollout remove          # zeigt, was entfernt würde - ändert nichts
tools/rollout/sshbite-rollout remove --yes
```

Auf jedem Host: die sudo-Regel, Collector, Gate und Namensauflösung, `authorized_keys`, der sshd-Block
und – nur wenn das Skript es angelegt hat – das Konto mit seinem Home (was `useradd` aus `/etc/skel`
kopiert hat, kommt ins Backup). Ein übernommenes Konto bleibt. Auf dem Scanner-Rechner: der Container
bzw. der systemd-Dienst. Es bleiben die Datenbank mit den Scans, `/etc/sshbite` und das Image; siehe
[Deinstallation](install.md#deinstallation).

## Testumfang

Ausgeführt wurde das Skript in Containern mit Ubuntu 24.04 (OpenSSH 9.6, sudo 1.9.15) als Hosts und
`MODE=docker` auf dem Scanner-Rechner:

- `check`, `plan`, `apply`, erneutes `apply` (keine Änderung), `validate`, `remove`, mit einem eigenen
  Kontonamen; danach `sshbite config validate --connect` und ein Scan über den Einstiegshost zu zwei
  weiteren Hosts (beide `ok`, `root`).
- Scanner-Rechner zugleich Einstiegshost, mit Scan: der Rechner selbst und beide Hosts aus `rollout.hosts`
  (als Seeds) wurden als root gelesen.
- Vorhandenes Konto mit Gruppe `sudo`, `authorized_keys2` und einer Regel `NOPASSWD: ALL`: ohne Optionen
  `FAIL` und keine Änderung, mit `--adopt-existing-account --remove-foreign-sudoers` eingerichtet.
- `ALL ALL=(ALL) ALL` mit `Defaults targetpw` vor und hinter der includedir-Zeile, jeweils mit Scan
  gegengeprüft.
- Admin-Konto mit `SSH_SUDO=yes`, Zwischenstation (`hop`), nicht erreichbarer Host.

`tests/e2e/test_rollout.py` prüft den Teil, der auf den Hosts läuft, in der CI gegen ein Image der
Testumgebung (Debian 12).

**Nicht getestet:** SUSE Linux Enterprise und openSUSE (die SUSE-Standardregeln wurden auf Ubuntu
nachgestellt), `MODE=native` (venv, Konto `sshbite-app`, systemd-Dienst), Hosts mit systemd
(`systemctl reload sshd`; in den Containern lud das Skript sshd mit HUP neu), SELinux im Modus enforcing,
`/etc/ssh/sshd_config.d` als Ziel des Blocks.
