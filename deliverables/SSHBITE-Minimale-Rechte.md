# SSHBITE – Minimale Rechte für den Audit-Account

Version 1.0 · 26.11.2026 · gilt für SSHBITE 0.1.0 (Collector `collect.sh`, SHA-256 `6c262392…40f05`)

## 1 Kurzfassung

**Die Frage:** Welche sudo-Rechte braucht der Account `sshbite` (der Audit-Key von SSHBITE) auf den
Zielsystemen – genau, Befehl für Befehl?

**Die Antwort: genau ein Befehl, ohne Argumente:**

```
sshbite ALL=(root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
```

`sshbite-collect` ist das Collector-Skript von SSHBITE, als root-eigene, feste Datei auf jedem Host abgelegt.
Es liest nur und gibt ein Inventar aus. Sonst darf `sshbite` mit sudo nichts – auch nicht `/bin/true`.

> **Warnung – der heutige Stand ist root-äquivalent.** SSHBITE schickt sein Skript heute per stdin an
> `sudo /bin/sh -s` (`sshbite/privilege.py:117-125`). Die Regel aus `docs/install.md:176`
> (`NOPASSWD: /bin/true, /bin/sh -s`) erlaubt damit **jedem Inhaber des Keys, beliebige Befehle als root
> auszuführen** – im Lab nachgewiesen (Kapitel 7, Test 07). Das steht auch in `docs/install.md:182-184`.
> Eine sudo-Regel allein kann das nicht beheben: Wer eine Shell erlaubt, erlaubt alles.

**Wie es trotzdem ohne Code-Änderung geht:** Ein *Forced Command* in `authorized_keys`
(`command="/usr/local/libexec/sshbite/sshbite-gate"`) nimmt jede Verbindung des Keys an und lässt nur die drei
festen Befehle zu, die SSHBITE sendet. Den Befehl `sudo /bin/sh -s` übersetzt es in `sudo sshbite-collect` –
das per stdin gesendete Skript wird nur per SHA-256 mit der installierten Kopie verglichen, **nie
ausgeführt**. Dazu: `restrict`, `from=`, Weiterleitung nur auf dem Einstiegs-Host und auf Hops, Home-Verzeichnis
root-eigen. Im Lab mit 13 Hosts lief der Scan damit vollständig (alle Hosts `root`, Ergebnis identisch mit
dem heutigen Stand) und alle 21 Ausbruchsversuche scheiterten.

| Ein Angreifer mit dem gekaperten Key … | heute (install.md) | mit dieser Konfiguration |
|---|---|---|
| bekommt eine Shell / führt eigene Befehle aus | ja, als root | **nein** (Gate lehnt ab) |
| liest `/etc/shadow`, private Schlüssel, beliebige Dateien | ja | **nein** |
| ändert Dateien, legt Keys oder Benutzer an | ja | **nein** |
| meldet sich von beliebigen Rechnern an | ja (ohne `from=`) | **nein**, nur vom Scanner bzw. Einstiegs-Host |
| lässt den Collector laufen und liest dessen Inventar | ja | **ja** – Restrisiko, Kapitel 5 |
| öffnet Tunnel vom Einstiegs-Host zu SSH-Ports (22) | ja, zu jedem Port | **ja, nur Port 22** – Restrisiko |

**Was der Account danach noch kann:** das SSH-Inventar jedes Hosts lesen (Benutzer, öffentliche Schlüssel,
`authorized_keys`, sshd-Konfiguration, ob private Schlüssel unverschlüsselt sind) und über den Einstiegs-Host
SSH-Ports im Netz erreichen. Er kann keine Geheimnisse lesen (keine Passwort-Hashes, keine privaten Schlüssel)
und nichts verändern. **Zusätzlich gefunden:** Ein *lokaler* Benutzer eines auditierten Hosts kann den als root
laufenden Collector per Symlink-Wechsel dazu bringen, fremde Dateien (im Lab: `/etc/shadow`) in das Inventar
zu schreiben, das an SSHBITE geht (Kapitel 5.2). Das behebt nur eine Code-Änderung (Kapitel 6).

## 2 Was SSHBITE auf einem Host tut

**Verbindung.** SSHBITE meldet sich mit genau einem Key als `sshbite` am Einstiegs-Host (`entry.host`) an,
ohne Agent, ohne Agent-Weiterleitung, ohne PTY (`sshbite/transport.py:220-240`). Jeden weiteren Host erreicht
es über einen `direct-tcpip`-Kanal des Einstiegs-Hosts – SSH-Portweiterleitung, kein `ssh`-Aufruf auf dem Hop
(`transport.py:325-332`, `sshbite/crawl.py:499-501`). Scheitert das mit einem Netzwerkfehler, versucht es den
Weg über den Host, auf dem der Ziel-Host gefunden wurde (`crawl.chain_fallback`, Standard an;
`crawl.py:517-520`, `sshbite/config.py:148`). Im Lab hieß das: c2 über `jump > b3 > c1 > c2`. Für Seeds mit
`probe` prüft SSHBITE vorher per Weiterleitung über den Einstiegs-Host, ob der SSH-Port offen ist
(`crawl.py:372-373, 386`). Ports: 22 bzw. `crawl.ssh_port` und Port-Angaben aus gefundenen `ssh_config`-Dateien
(`crawl.py:595-633`).

**Befehle.** Auf jedem Host sendet SSHBITE nur feste Zeichenketten auf einem Exec-Kanal, Eingaben nur als
stdin (`transport.py:387-395`). Mit `privilege.mode: sudo` (Standard, `config.py:133`) sind es die folgenden;
`S` steht für `test -x /usr/bin/sudo && exec /usr/bin/sudo …; exec /bin/sudo …` (`privilege.py:112-114`):

| Zweck | gesendeter Befehl | Beleg |
|---|---|---|
| sudo-Probe | `S -n /bin/true` | `privilege.py:120, 136` |
| Collector | `S -n /bin/sh -s`, stdin = Skript `collect.sh` | `privilege.py:121, 138` |
| Namensauflösung (ohne sudo; Einstiegs-Host, ggf. der Host, der den Namen enthielt) | `/bin/sh -c 'while IFS= read -r n; do getent hosts …'`, stdin = Namen | `collector/__init__.py:51-54`, `crawl.py:394-402, 659-664` |
| nur mit Passwort | `S -S -k -p '' /bin/true`, dann `… /bin/sh -s` | `privilege.py:122-123, 147-157` |
| ohne sudo (Rückfall) | `/bin/sh -s` | `privilege.py:124, 172` |
| `sshbite config validate --connect` | nur die sudo-Probe | `sshbite/cli.py:141-147` |

`privilege.mode: sudo-login` setzt zusätzlich `-i` (`privilege.py:118`); install.md empfiehlt dafür
`NOPASSWD: ALL` (`docs/install.md:179-180`). Dieser Modus ist mit minimalen Rechten nicht vereinbar.

**Was der Collector liest** (`sshbite/collector/collect.sh`; alle Befehle mit festem `PATH`, Zeile 1):

| Befehl / Datei | root nötig? | Grund | Beleg |
|---|---|---|---|
| `hostname`, `uname`, `id`, `/etc/os-release`, `ip -o addr` | nein | weltlesbar | `collect.sh:96-104` |
| `/etc/ssh/ssh_host_*_key.pub` | nein | 0644 | `collect.sh:109-113` |
| `/usr/sbin/sshd -T` (wirksame sshd-Konfiguration) | **ja** | sshd lädt die privaten Host-Keys; ohne root: „no hostkeys available“ (Lab) | `collect.sh:117` |
| `/etc/ssh/sshd_config` und `Include`-Dateien | Debian nein, RHEL **ja** | RHEL liefert 0600 aus (nicht im Lab geprüft) | `collect.sh:122-143` |
| `getent passwd` | nein | | `collect.sh:155-156` |
| `/etc/shadow`: nur Name, 1. Zeichen des Hash-Felds, Feld 8 | **ja** | 0640 root:shadow | `collect.sh:162-167` |
| `~/.ssh` aller Benutzer: Liste, `known_hosts*`, `config`, `*.pub` | **ja** | `~/.ssh` ist 0700 | `collect.sh:210-251` |
| private Schlüssel: 1. Zeile + `ssh-keygen -y -P ''` / `-l` (öffentliche Hälfte, Fingerprint, „unverschlüsselt?“) | **ja** | 0600; der Inhalt wird nie ausgegeben | `collect.sh:54-73` |
| `authorized_keys` laut `AuthorizedKeysFile` | **ja** | oft 0600 | `collect.sh:146-151, 257-269` |
| `/etc/ssh/ssh_known_hosts`, `ssh_config`, `ssh_config.d/*` | nein | | `collect.sh:275-287` |

Root ist also nur für **Lesen** nötig; der Collector schreibt nichts (`collect.sh:3-6`, im Lab geprüft:
die Ausgabe enthält keine Zeile privaten Schlüsselmaterials, Kapitel 7). Ohne sudo fehlen gerade die
interessanten Daten; SSHBITE markiert den Host dann `partial` (`docs/install.md:158-159`).

## 3 Der heutige Stand und sein Risiko

README und install.md verlangen „an account `sshbite` with sudo on every host“ (`README.md:29`) und empfehlen:

```
Defaults:sshbite !lecture
sshbite ALL=(root) NOPASSWD: /bin/true, /bin/sh -s
```

sudo prüft nur den Befehl und seine Argumente – `/bin/sh -s` – nicht, was danach auf stdin kommt. `sh -s`
führt **jede** Eingabe aus. Wer den Key hat, schreibt also `cat /etc/shadow` oder `useradd …` statt des
Collectors auf stdin und ist root. Im Lab (Kapitel 7, Tests 07, 12, 22) lieferte genau der SSHBITE-Befehl
mit eigenem stdin `uid=0(root)` und den Inhalt von `/etc/shadow`; auch die Passwort-Variante (`sudo -S`)
führte die Zeile nach dem „Passwort“ als root aus. Zusätzlich hatte der Key ohne Optionen eine normale Shell,
konnte von überall anmelden und Tunnel zu jedem Port öffnen (Tests 01, 18-20).

> **Root-äquivalent – und nicht durch sudoers zu beheben.** Jede sudo-Regel, die eine Shell
> (`/bin/sh`, `bash`), einen Interpreter (`python`, `perl`, `awk`), einen Editor oder Pager (`vi`, `less`)
> oder `ALL` erlaubt, ist volles root. Solange SSHBITE den Collector als stdin einer root-Shell übergibt,
> gibt es **keine** sudoers-Regel, mit der der Scan läuft und die nicht root-äquivalent ist. Das Dokument
> umgeht das in Kapitel 4 auf SSH-Ebene und schlägt in Kapitel 6 die Code-Änderung vor.

## 4 Minimal-Konfiguration – Schritt für Schritt

Gilt für SSHBITE 0.1.0 **ohne Code-Änderung**. Alle Dateien liegen in `deliverables/config/` und im Anhang.
Die Bausteine:

| Baustein | Datei | Zweck |
|---|---|---|
| Collector | `/usr/local/libexec/sshbite/sshbite-collect` | `collect.sh` von SSHBITE 0.1.0 plus Zeile `#!/bin/sh`; root:root 0755 |
| Gate | `/usr/local/libexec/sshbite/sshbite-gate` | Forced Command: lässt nur die festen SSHBITE-Befehle zu |
| sudoers | `/etc/sudoers.d/sshbite` | genau eine Regel: Collector ohne Argumente |
| Key | `~sshbite/.ssh/authorized_keys` | `restrict`, `from=`, `command=`, ggf. Weiterleitung |
| Prüfung | `sshbite-pruefen.sh` | prüft alles Obige auf einem Host (nur lesend) |

**Was das Gate tut** (Anhang A.3): sshd startet es bei jeder Verbindung des Keys; der angefragte Befehl steht in
`SSH_ORIGINAL_COMMAND`. Nur bei **exakter** Übereinstimmung mit einem der festen SSHBITE-Befehle handelt es:

| SSHBITE sendet | Gate führt aus |
|---|---|
| sudo-Probe `… sudo -n /bin/true …` | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` (prüft nur, ob die Regel greift) |
| Collector `… sudo -n /bin/sh -s …` | liest stdin, vergleicht SHA-256 mit der installierten Kopie; nur bei Gleichheit `sudo -n …/sshbite-collect </dev/null` |
| Namensauflösung `/bin/sh -c 'while … getent hosts …'` | genau diesen Befehl, ohne sudo |
| alles andere | Abbruch mit `sshbite-gate: Befehl nicht erlaubt`, Exit 126, Eintrag via `logger` in authpriv |

### 4.1 Account

```
useradd --create-home --shell /bin/sh sshbite   # Debian und RHEL gleich
passwd -l sshbite                                # kein Passwort-Login
chown -R root:root /home/sshbite                 # Home gehört root, sshbite legt dort nichts an
chmod 0755 /home/sshbite
install -d -m 0755 -o root -g root /home/sshbite/.ssh
```

- **Shell muss `/bin/sh` bleiben.** sshd startet den Forced Command über die Login-Shell; mit
  `/usr/sbin/nologin` scheitert jede Verbindung („This account is currently not available.“ – im Lab geprüft).
  Eine Shell bekommt der Key trotzdem nicht: der Forced Command ersetzt jeden Befehl.
- Keine Gruppen (`sudo`, `wheel`, `adm`, `shadow`, `docker` …).
- **Home und `.ssh` root-eigen:** sshd akzeptiert root-eigene Dateien (StrictModes). Der Account kann so weder
  `authorized_keys` ändern noch Dateien ablegen, die der Collector als root liest (Kapitel 5.2).
- Wer zentrale Schlüsseldateien nutzt (`AuthorizedKeysFile /etc/ssh/authorized_keys/%u`), erreicht dasselbe dort.

### 4.2 Collector und Gate ablegen

```
install -d -m 0755 -o root -g root /usr/local/libexec/sshbite
install -m 0755 -o root -g root sshbite-collect /usr/local/libexec/sshbite/sshbite-collect
install -m 0755 -o root -g root sshbite-gate    /usr/local/libexec/sshbite/sshbite-gate
tail -n +2 /usr/local/libexec/sshbite/sshbite-collect | sha256sum
# erwartet: 6c262392665b6cd321c7ac52834a69c1e1fcf2fe171552b863742c4ec9940f05
```

Der Collector muss Byte für Byte dem `collect.sh` der eingesetzten SSHBITE-Version entsprechen (nach der
Shebang-Zeile). Das Skript prüft sich selbst: es gibt in der Kopfzeile den Hash seines Inhalts aus und SSHBITE
vergleicht ihn (`collect.sh:2, 12`, `crawl.py:558-562`). **Nach jedem SSHBITE-Update** neu erzeugen:
`{ echo '#!/bin/sh'; cat sshbite/collector/collect.sh; } > sshbite-collect` (oder aus
`sshbite collector show`). Passt die Kopie nicht, lehnt das Gate ab und SSHBITE zeigt den Host als
`collector_error` mit „Collector-Version passt nicht“ (im Lab geprüft, Kapitel 7).

### 4.3 sudoers

```
Defaults:sshbite env_reset
Defaults:sshbite secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:sshbite !lecture, !log_output, !log_input, !requiretty

sshbite ALL=(root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
```

- **Voller Pfad, `""` am Ende:** sudo erlaubt dann genau diesen Aufruf ohne Argumente. Keine Wildcards,
  keine Shell, kein `/bin/true` (die Probe erledigt das Gate mit `sudo -l`).
- **Voraussetzung:** Datei und Verzeichnis gehören root und sind für niemanden sonst beschreibbar. Sonst ist
  die Regel root-äquivalent (wer die Datei ändert, bestimmt, was root ausführt).
- **`NOPASSWD`: ja.** Der Befehl ist fest und nur lesend; ein Passwort schützte ihn kaum, müsste aber auf allen
  Hosts gleich sein, läge beim Scanner neben dem Key und löste bei Debian bei jedem Scan eine
  „SECURITY information“-Mail aus (`docs/side-effects.md:18-34`). Das Gate lehnt die Passwort-Varianten ab.
- **`env_reset`/`secure_path`:** Standard auf Debian und RHEL, hier ausdrücklich. sudo verweigert
  `sudo VAR=wert …` und `sudo -E` (im Lab geprüft); der Collector setzt `PATH` und `LC_ALL` selbst.
- **`noexec`: nein.** Der Collector ist ein Shell-Skript und muss `awk`, `sed`, `ssh-keygen`, `sshd -T` starten;
  `noexec` würde genau das verhindern.
- **`use_pty`:** Debian 12 setzt es global (im Lab aktiv); der Scan lief damit fehlerfrei. Muss nicht geändert werden.
- **`!log_output`, `!log_input`:** I/O-Logs würden eine Kopie des Inventars ablegen (`docs/side-effects.md:55-59`).
  Der normale sudo-Log-Eintrag je Aufruf bleibt – er ist das Monitoring-Signal.
- **`!requiretty`:** SSHBITE fordert kein Terminal an (`transport.py:239, 390`). Ältere RHEL/CentOS-sudoers
  setzten `Defaults requiretty`; dann scheiterte jeder Aufruf. Auf Debian wirkungslos.

### 4.4 authorized_keys

Je Host **eine** Zeile (Anhang A.2), `<…>` ersetzen:

| Host-Rolle | Optionen |
|---|---|
| (A) Einstiegs-Host | `restrict,port-forwarding,permitopen="*:22",from="<SCANNER-IP>",command="…/sshbite-gate"` |
| (B) jeder andere Host | `restrict,from="<EINSTIEGS-HOST-IP>",command="…/sshbite-gate"` |
| (C) Hop für `chain_fallback` | wie (A), aber `from="<VORHERIGER-HOP-IP>"` |

- `restrict` schaltet PTY, Agent-, X11- und Portweiterleitung und `~/.ssh/rc` ab (OpenSSH ≥ 7.2);
  `port-forwarding` erlaubt Weiterleitung wieder, `permitopen` beschränkt sie auf Port 22 (jede Adresse).
  Weitere SSH-Ports als zusätzliches `permitopen="*:<PORT>"`. Wer die Ziele kennt, listet statt `*` Adressen.
- `from=`: die Adresse, **wie der Host sie sieht**. Läuft SSHBITE in Docker, ist es die Adresse des
  Docker-Hosts (NAT). Nachlesen im Auth-Log des Einstiegs-Hosts: `Accepted publickey for sshbite from …`.
  Die übrigen Hosts sehen den Einstiegs-Host (Adresse im jeweiligen Netz) bzw. den vorherigen Hop.
- **Welche Hosts Hops sind**, zeigt der erste Scan (Spalte Route, im Lab `jump > b3 > c1 > c2`: b3 und c1
  brauchen Variante C). Wer das nicht will: `crawl.chain_fallback: false` – dann braucht nur der Einstiegs-Host
  Weiterleitung, nicht direkt erreichbare Hosts bleiben `unreachable`.
- sshd muss für `sshbite` `AllowTcpForwarding yes` oder `local` erlauben – nur auf A/C nötig
  (`docs/install.md:141-145`); `AllowUsers`/`AllowGroups` ggf. ergänzen.
- `permitopen="*:22"` im Lab mit OpenSSH 9.2p1 geprüft (Port 22 offen, Port 2200 abgelehnt).

### 4.5 SSHBITE-Konfiguration

`privilege.mode: sudo` (Standard) beibehalten; `sudo-login` und `none` funktionieren mit dem Gate nicht. Kein
`--ask-sudo-password`. Hosts ohne diese Einrichtung fallen nicht mehr auf `partial` zurück, sondern melden
`collector_error` – das Gate lehnt den unprivilegierten Rückfall `/bin/sh -s` ab.

### 4.6 Ausrollen und prüfen

```
visudo -cf sudoers.d-sshbite                     # vor dem Kopieren
install -m 0440 -o root -g root sudoers.d-sshbite /etc/sudoers.d/sshbite
visudo -c                                         # gesamte sudo-Konfiguration
sudo -l -U sshbite
#   User sshbite may run the following commands on <host>:
#       (root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
install -m 0644 -o root -g root authorized_keys /home/sshbite/.ssh/authorized_keys
sh sshbite-pruefen.sh                             # als root; Exit 0 = alles richtig
```

Danach am Scanner: `sshbite config validate --connect` muss `sudo: root` melden; dann scannen. Zeigt
`sudo -l -U sshbite` mehr als diese eine Zeile, gibt es weitere Regeln für den Account (z. B. Gruppe `sudo`/
`wheel` oder eine alte Datei in `/etc/sudoers.d/`) – entfernen.

### 4.7 Unterschiede Debian/Ubuntu und RHEL-Familie

| Punkt | Debian/Ubuntu | RHEL/Alma/Rocky | Folge |
|---|---|---|---|
| sudo-Pfad | `/usr/bin/sudo` | `/usr/bin/sudo` | Gate nimmt sonst `/bin/sudo` |
| `/bin/sh` | dash | bash | Gate und Collector sind POSIX-sh; im Lab nur dash getestet |
| `sshd_config` | 0644 | 0600 | dort root nötig (Kapitel 2) |
| Admin-Gruppe | `sudo` | `wheel` | `sshbite` in keiner |
| `requiretty` | nie | ältere Versionen | `!requiretty` gesetzt |
| SELinux | – | enforcing | `/usr/local/libexec` hat Typ `bin_t`; **nicht getestet** |
| sudo-Mail bei Fehlschlag | `mail_badpass` | Standard | bei `NOPASSWD` keine Mail |

**Im Lab getestet ist nur Debian 12** (sudo 1.9.13p3, OpenSSH 9.2p1). RHEL-Familie: **nicht getestet**.

## 5 Was ein Angreifer mit dem Account noch kann (Restrisiko)

### 5.1 Mit gestohlenem Key (von der Scanner-Adresse aus)

- **Inventar lesen:** auf jedem Host den Collector starten und dessen Ausgabe lesen – Hostname, IPs, OS,
  wirksame sshd-Konfiguration, alle Benutzer (`getent passwd`), je Benutzer ob ein Passwort gesetzt/gesperrt ist
  (1. Zeichen des Hash-Felds, kein Hash), alle `authorized_keys` mit Optionen, `known_hosts`, `ssh_config`,
  öffentliche Schlüssel und **welche privaten Schlüssel unverschlüsselt herumliegen**. Das ist eine
  Landkarte für den nächsten Schritt, aber kein Zugang: kein Inhalt privater Schlüssel, keine Passwort-Hashes.
- **Tunnel zu SSH-Ports:** über den Einstiegs-Host (und Hops) Port 22 jeder erreichbaren Adresse. Nützt nur mit
  anderen gültigen Zugangsdaten. Enger: `permitopen` mit Adressliste statt `*`.
- **Last und Log-Rauschen:** den Collector beliebig oft starten.
- **Nicht mehr möglich** (Kapitel 7): Shell, eigene Befehle, andere sudo-Befehle, Dateien schreiben,
  `authorized_keys` ändern, Agent/X11/PTY, andere Ports, Anmeldung von anderen Adressen.

### 5.2 Symlink-Race durch lokale Benutzer (Fehler im Collector)

`content()` prüft eine Datei und liest sie danach als root (`collect.sh:39-43`; Symlink-Prüfung vorher in
`collect.sh:242-248`, `260-265`). Ein lokaler Benutzer kann dazwischen `~/.ssh/known_hosts…` durch einen Link
auf eine fremde Datei ersetzen. Im Lab (Benutzer `ops`, 200 Collector-Läufe als root) stand in **36 Läufen der
volle Inhalt von `/etc/shadow`** in der Ausgabe. Dasselbe geht mit jeder für root lesbaren Datei (die ersten 5000 Zeilen,
`collect.sh:43`), z. B. privaten Host-Keys. Die Daten landen in der SSHBITE-Datenbank, nicht beim lokalen Benutzer.
Gefährlich wird es, wenn ein Angreifer **beides** hat: den Key und einen Benutzer auf demselben Host – oder
wenn der Account `sshbite` selbst in sein Home schreiben kann. Deshalb ist das Home in 4.1 root-eigen und der
Forced Command lässt keine Shell zu. Beheben lässt sich der Fehler nur im Collector (Kapitel 6, Änderung 3).

Weiter gilt: `ssh-keygen` parst als root Dateien, die Benutzer kontrollieren (`collect.sh:69-71`). Eine
Lücke in diesem Parser liefe als root. Auch das behebt Änderung 3.

### 5.3 Gegenmaßnahmen

- Key nur auf dem Scanner, Modus 0600, mit Passphrase (`audit.key_passphrase_env`, `docs/install.md:128-129`).
- **Key nur für die Dauer des Audits:** danach die `authorized_keys`-Zeile entfernen (oder den Account
  mit `usermod -e 1 sshbite` ablaufen lassen – nicht im Lab geprüft); vor dem nächsten Audit wieder freischalten.
- **Monitoring:** sudo-Log mit `USER=root ; COMMAND=/usr/local/libexec/sshbite/sshbite-collect` außerhalb der
  Scan-Fenster und jeder `sshbite-gate`-Eintrag („abgelehnt“) in authpriv sind Alarmzeichen. Ein Scan erzeugt pro
  Host genau einen Collector-Aufruf.
- SSHBITE-Datenbank schützen wie die Daten, die sie enthält (`docs/configuration.md:82`).

## 6 Code-Änderung für die Zielkonfiguration

**Nicht Teil dieser Order.** Die Konfiguration aus Kapitel 4 ist heute einsatzfähig und nicht root-äquivalent.
Sie hat drei Schwächen, die nur der Code beseitigt: das Gate muss stdin hashen und SSHBITEs Befehlszeilen
wörtlich kennen (jedes Update kann beides ändern); SSHBITE sendet weiterhin Skripte an Shells; der Symlink-Race
(5.2) bleibt.

| # | Änderung | Wo | Aufwand |
|---|---|---|---|
| 1 | Neuer Modus `privilege.mode: installed`: SSHBITE ruft `sudo -n <privilege.collector_path>` ohne stdin auf, Probe `sudo -n -l <Pfad>`; kein `/bin/sh -s`, kein Rückfall ohne sudo. Kopfzeilen-Hash wird wie heute geprüft | `privilege.py:117-173`, `config.py:132-140`, `cli.py:141-147` | 1–1,5 PT |
| 2 | `sshbite collector export DIR`: schreibt `sshbite-collect`, `sshbite-resolve` und die sudoers-/authorized_keys-Vorlagen mit Prüfsumme; install.md „Sudoers“ ersetzen | `cli.py`, `collector/`, `docs/install.md:156-194` | 1 PT |
| 3 | Collector liest Dateien in Benutzer-Homes **als dieser Benutzer** (`setpriv`/`runuser`, beide util-linux) – auch `ssh-keygen`. Der Race bringt dann nur, was der Benutzer ohnehin lesen darf | `collect.sh:34-73, 210-269`, `collector/lint.py` | 2–3 PT |
| 4 | Tests: Lab-E2E mit Modus `installed`, Race-Test, ein RHEL-Lab-Host | `tests/`, `lab/` | 1–2 PT |

Gesamt etwa **5–7,5 Personentage**.

**Zielkonfiguration nach der Änderung** (Unterschiede zu Kapitel 4):

```
# sudoers: unverändert eine Regel
sshbite ALL=(root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""

# authorized_keys: das Gate wird ein reiner Verteiler ohne stdin-Hash
restrict,from="<EINSTIEGS-HOST-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" ssh-ed25519 …
#   erlaubt: "sudo -n -l <collector>", "sudo -n <collector>", "<resolve>" – sonst nichts
```

```
# sshbite.yaml
privilege:
  mode: installed
  collector_path: /usr/local/libexec/sshbite/sshbite-collect
```

Optional danach: den Collector nicht als root, sondern mit nur `CAP_DAC_READ_SEARCH` laufen lassen (liest alles,
schreibt nichts) – nicht untersucht.

## 7 Nachweis im Lab

**Aufbau:** Lab aus `compose.yaml` → `compose.lab.yaml` → `lab/compose.yaml` (13 Debian-12-Hosts, Einstieg `jump`,
Netze 172.30.1/2/3.0/24, c-Netz nur über b3). SSHBITE 0.1.0 lief außerhalb auf dem Scanner (Adresse aus Sicht des
Labs 172.30.1.2) mit `lab/demo/sshbite.yaml`. Konfiguration per Lab-Steuerung (root, Port 2200) eingespielt.
Alles reproduzierbar mit `tools/rechte-lab/nachweis.sh`; die vollständigen Protokolle liegen in
`deliverables/nachweis/01-06*.txt`.

**A – Heutiger Stand** (sudoers aus install.md, `authorized_keys` ohne Optionen):

```
$ sshbite config validate --connect
entry OK, pinned key matches, sudo: root
$ sshbite scan --label "install.md-Regel"
hosts:    13 connected; 12 ok, 1 unreachable, 1 excluded, 2 out_of_scope, 1 unresolvable
findings: 37 - 4 critical, 16 high, 14 medium, 2 low, 1 info
### 07 Eigenes Skript per stdin an sudo /bin/sh -s (exakter SSHBITE-Befehl)
$ ssh sshbite@jump test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s
  (stdin: id; head -n 2 /etc/shadow)
uid=0(root) gid=0(root) groups=0(root)
root:*:20780:0:99999:7:::
```

**B – Minimal-Konfiguration** (Kapitel 4, alle 13 Hosts; b3 und c1 als Hops, Variante C):

```
$ visudo -cf /tmp/sb/sudoers.d-sshbite           -> parsed OK   (auf allen 13 Hosts)
$ sudo -l -U sshbite
    (root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
$ sh sshbite-pruefen.sh                          -> 19 x OK, Exit 0
                                                    (heutiger Stand: 11 x FEHLER, Exit 1)
$ sshbite config validate --connect
entry OK, pinned key matches, sudo: root
$ sshbite scan --label minimal
hosts:    13 connected; 12 ok, 1 unreachable, 1 excluded, 2 out_of_scope, 1 unresolvable
findings: 37 - 4 critical, 16 high, 14 medium, 2 low, 1 info
$ sshbite diff 1 2
hosts: 0 added, 0 removed, 0 changed   (ebenso keys, placements, edges, findings)
```

Alle 13 verbundenen Hosts mit Privileg `root`, Routen wie vorher (`jump > b3 > c1 > c2`). Der eine
`unreachable` (172.30.1.99) ist auch heute nicht erreichbar – eine Lab-Adresse ohne Host.

**Ausbruchsversuche mit dem gestohlenen Key** (`tools/rechte-lab/ausbruch.sh`), heute → minimal:

| # | Versuch | heute | minimal |
|---|---|---|---|
| 01 | interaktive Shell mit PTY | Shell | PTY request failed |
| 02 | `id` ohne sudo | uid=1000 | Gate: nicht erlaubt (126) |
| 03-05 | `sudo -i`, `sudo sh -c id`, `sudo cat /etc/shadow` | Passwort verlangt | Gate: nicht erlaubt |
| 06 | `sudo -l` | zeigt Regel | Gate: nicht erlaubt |
| 07 | eigenes Skript an den exakten Collector-Befehl | **root, shadow gelesen** | Gate: Version passt nicht |
| 08-10 | Collector mit Argument, mit `LD_PRELOAD`, direkt | Passwort verlangt | Gate: nicht erlaubt |
| 11 | Collector-Befehl mit angehängtem `; id` | Shell-Fehler | Gate: nicht erlaubt |
| 12 | Passwort-Variante, 2. Zeile `id` | **root** | Gate: nicht erlaubt |
| 13-16 | `/bin/sh -s`, `sudo -i`-Variante, `sh -c 'id'`, `cat /etc/passwd` | ohne root ausgeführt¹ | Gate: nicht erlaubt |
| 17 | Tunnel jump → a1:22 | offen | offen (gewollt) |
| 18 | Tunnel jump → a1:2200 | offen | **abgelehnt** |
| 19 | Tunnel über a1 (kein Hop) | offen | **abgelehnt** |
| 20 | Anmeldung an a1 direkt vom Scanner | angemeldet | **Permission denied** (`from=`) |
| 21 | a1: `sudo sh -c id` | Passwort verlangt | Gate: nicht erlaubt |
| 22 | a1: eigenes Skript an den Collector-Befehl | **root** | Gate: Version passt nicht |

¹ Test 14 (`sudo -i`-Variante) heute: Passwort verlangt. 21 von 22 Versuchen werden mit der Minimal-Konfiguration
abgewiesen; Test 17 ist die gewollte Weiterleitung.

**Zweite Verteidigungslinie** – falls jemand doch eine Shell als `sshbite` hätte (Protokoll 05; Lab-Steuerung,
`su sshbite`): `sudo -i`, `sudo /bin/sh`, `sudo cat /etc/shadow`, `sudo /bin/true`, Collector mit Argument,
`sudo -u daemon` → „a password is required“; `sudo PATH=/tmp …` → „not allowed to set the following environment
variables“; `sudo -E` → „not allowed to preserve the environment“; Schreiben in `/usr/local/libexec/sshbite/`, ins
Home, in `authorized_keys` → „Permission denied“. Der erlaubte Collector-Lauf enthielt 0 Zeilen privaten
Schlüsselmaterials; der SHADOW-Abschnitt nur `root:*:`.

**C – Falsche Collector-Version** (eine Zeile an die Kopie auf a5 angehängt): Scan läuft, a5 =
`collector_error`, Meldung „no collector output: sshbite-gate: Collector-Version passt nicht zu …“.

**D – Symlink-Race** (5.2): `collector runs: 200, runs with a full /etc/shadow line in the output: 36` (ohne Race: 0).
Eine frühere Wiederholung ergab 33 von 200.

**Nicht getestet:** RHEL-Familie (SELinux, bash als `/bin/sh`, ältere sudo/OpenSSH); OpenSSH < 9.2 für
`permitopen="*:22"`; der `logger`-Eintrag des Gates (die Lab-Container haben kein Syslog); SSHBITE im
Docker-Container hinter NAT (nur der Scanner außerhalb wurde verwendet); Passwort-/`sudo-login`-Betrieb
mit dem Gate (bewusst nicht unterstützt).

## Anhang A – Konfigurationsdateien

Alle Dateien liegen fertig in `deliverables/config/`. `sshbite-collect` ist `sshbite/collector/collect.sh` von
SSHBITE 0.1.0 mit vorangestelltem `#!/bin/sh` (290 + 1 Zeilen; hier nicht abgedruckt).

### A.1 /etc/sudoers.d/sshbite (`config/sudoers.d-sshbite`)

```
# /etc/sudoers.d/sshbite - SSHBITE-Audit-Account, minimale Rechte (SSHBITE 0.1.0)
# Ablage: install -m 0440 -o root -g root sudoers.d-sshbite /etc/sudoers.d/sshbite
# Pruefen: visudo -cf /etc/sudoers.d/sshbite  und  sudo -l -U sshbite
#
# Erlaubt ist GENAU EIN Befehl: das fest installierte, root-eigene Collector-Skript, ohne Argumente
# ("" am Ende = keine Argumente erlaubt). Kein /bin/sh, kein /bin/true, keine Wildcards.
# Voraussetzung: /usr/local/libexec/sshbite/ und die Datei darin gehoeren root und sind fuer
# niemanden sonst beschreibbar - sonst ist diese Regel root-aequivalent.
# Nur zusammen mit dem Forced Command sshbite-gate in authorized_keys verwenden.

Defaults:sshbite env_reset
Defaults:sshbite secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:sshbite !lecture, !log_output, !log_input, !requiretty

sshbite ALL=(root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
```

### A.2 authorized_keys (`config/authorized_keys.sshbite`)

```
# authorized_keys des Accounts sshbite - Ablage: /home/sshbite/.ssh/authorized_keys (root:root, 0644)
# Platzhalter in <SPITZEN KLAMMERN> ersetzen; "ssh-ed25519 AAAA..." = Inhalt von /etc/sshbite/audit_ed25519.pub.
# Jede Zeile ist EINE Zeile (kein Umbruch). Nur die zum Host passende Variante eintragen.
#
# (A) Einstiegs-/Jump-Host (entry.host): Login nur vom Scanner; Weiterleitung nur zu SSH-Ports.
#     Fuer jeden weiteren SSH-Port im Netz (crawl.ssh_port, Port-Angaben in ssh_config) ein weiteres
#     permitopen="*:<PORT>" anfuegen.
restrict,port-forwarding,permitopen="*:22",from="<SCANNER-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" ssh-ed25519 <AUDIT-PUBLIC-KEY> sshbite-audit
#
# (B) Jeder andere Host: Login nur vom Einstiegs-Host (dessen Adresse im Netz dieses Hosts),
#     keine Weiterleitung.
restrict,from="<EINSTIEGS-HOST-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" ssh-ed25519 <AUDIT-PUBLIC-KEY> sshbite-audit
#
# (C) Nur falls crawl.chain_fallback benoetigt wird: Hosts, ueber die SSHBITE andere Segmente erreicht
#     (Zwischen-Hop), brauchen wie (A) port-forwarding; from= ist dann die Adresse des vorherigen Hops.
restrict,port-forwarding,permitopen="*:22",from="<VORHERIGER-HOP-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" ssh-ed25519 <AUDIT-PUBLIC-KEY> sshbite-audit
```

### A.3 Gate (`config/sshbite-gate`)

```
#!/bin/sh
# sshbite-gate - Forced Command fuer den SSHBITE-Audit-Account (authorized_keys: command="...").
# Ablage: /usr/local/libexec/sshbite/sshbite-gate   Eigentuemer root:root, Modus 0755.
#
# sshd startet dieses Skript bei JEDER Verbindung des Audit-Keys statt des angefragten Befehls;
# der angefragte Befehl steht in SSH_ORIGINAL_COMMAND. Erlaubt sind genau die festen Befehle,
# die SSHBITE 0.1.0 sendet (sshbite/privilege.py, sshbite/collector/__init__.py):
#   1. sudo-Probe              -> sudo -n -l <Collector>    (prueft die Regel, fuehrt nichts aus)
#   2. Collector "sudo sh -s"  -> sudo -n <Collector>       (fest installierte Kopie; stdin wird nur
#                                 per SHA-256 mit dieser Kopie verglichen und NIE ausgefuehrt)
#   3. Namensaufloesung        -> der feste resolve-Befehl, ohne sudo
# Alles andere (Shell, andere Skripte, sudo -i, Passwort-Varianten, scp/sftp) wird abgelehnt.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077

COLLECT=/usr/local/libexec/sshbite/sshbite-collect
SUDO=/usr/bin/sudo
[ -x "$SUDO" ] || SUDO=/bin/sudo
C=${SSH_ORIGINAL_COMMAND-}

PROBE='test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/true; exec /bin/sudo -n /bin/true'
RUN='test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s'
RESOLVE=$(cat <<'EOF'
/bin/sh -c 'while IFS= read -r n; do getent hosts -- "$n" | awk -v n="$n" '\''{print n"\t"$1}'\''; done'
EOF
)

deny() {
  printf 'sshbite-gate: %s\n' "$1" >&2
  logger -p authpriv.warning -t sshbite-gate -- "abgelehnt ($1): $(printf '%s' "$C" | tr -c '[:print:]' '?' | cut -c1-200)" 2>/dev/null
  exit 126
}

if [ "$C" = "$PROBE" ]; then
  exec "$SUDO" -n -l "$COLLECT" >/dev/null
elif [ "$C" = "$RUN" ]; then
  # Das von SSHBITE gesendete Skript muss Byte fuer Byte der installierten Kopie (ohne Shebang) entsprechen.
  got=$(sha256sum) || deny "stdin nicht lesbar"
  want=$(tail -n +2 "$COLLECT" | sha256sum) || deny "$COLLECT fehlt"
  [ "$got" = "$want" ] || deny "Collector-Version passt nicht zu $COLLECT"
  exec "$SUDO" -n "$COLLECT" </dev/null
elif [ "$C" = "$RESOLVE" ]; then
  exec /bin/sh -c "$C"
fi
deny "Befehl nicht erlaubt"
```

### A.4 Prüfskript (`config/sshbite-pruefen.sh`)

```
#!/bin/sh
# sshbite-pruefen.sh - prueft auf EINEM Host, ob die Minimal-Konfiguration fuer den SSHBITE-Audit-Account
# richtig liegt. Als root ausfuehren:  sh sshbite-pruefen.sh   (aendert nichts; Exit 0 = alles OK)
PATH=/usr/sbin:/usr/bin:/sbin:/bin
U=sshbite
D=/usr/local/libexec/sshbite
C=$D/sshbite-collect
G=$D/sshbite-gate
S=/etc/sudoers.d/sshbite
WANT_SHA=6c262392665b6cd321c7ac52834a69c1e1fcf2fe171552b863742c4ec9940f05   # collect.sh von SSHBITE 0.1.0
bad=0
ok()   { printf 'OK      %s\n' "$1"; }
fail() { printf 'FEHLER  %s\n' "$1"; bad=1; }

[ "$(id -u)" = 0 ] || { echo "als root ausfuehren"; exit 2; }
H=$(getent passwd "$U" | cut -d: -f6); SH=$(getent passwd "$U" | cut -d: -f7)
[ -n "$H" ] && ok "Account $U existiert (Home $H, Shell $SH)" || { fail "Account $U fehlt"; exit 1; }
case "$SH" in */nologin | */false) fail "Shell $SH: der Forced Command braucht /bin/sh" ;; *) ok "Shell $SH" ;; esac
id -nG "$U" | grep -qw -e sudo -e wheel -e adm -e shadow && fail "$U ist in einer privilegierten Gruppe: $(id -nG "$U")" || ok "keine privilegierten Gruppen ($(id -nG "$U"))"
passwd -S "$U" 2>/dev/null | awk '{print $2}' | grep -q '^L' && ok "Passwort gesperrt" || fail "Passwort nicht gesperrt (passwd -l $U)"

for p in "$D" "$C" "$G" "$S" "$H" "$H/.ssh" "$H/.ssh/authorized_keys"; do
  st=$(stat -c '%U %a' "$p" 2>/dev/null) || { fail "$p fehlt"; continue; }
  own=${st% *}; mode=${st#* }
  w=$(( (0$mode & 022) ))
  if [ "$own" = root ] && [ "$w" = 0 ]; then ok "$p root-eigen, Modus $mode"; else fail "$p: Eigentuemer $own, Modus $mode (root, nicht gruppen-/weltbeschreibbar)"; fi
done
[ "$(stat -c %a "$S" 2>/dev/null)" = 440 ] || fail "$S sollte Modus 0440 haben"
visudo -cf "$S" >/dev/null 2>&1 && ok "visudo -cf $S" || fail "visudo -cf $S meldet Fehler"
visudo -c >/dev/null 2>&1 && ok "visudo -c (gesamte sudo-Konfiguration)" || fail "visudo -c meldet Fehler"

L=$(sudo -l -U "$U" 2>/dev/null | sed -n '/may run the following/,$p' | tail -n +2 | sed 's/^ *//')
if [ "$L" = "(root) NOPASSWD: $C \"\"" ]; then ok "sudo -l -U $U: genau eine Regel: $L"
else fail "sudo -l -U $U zeigt mehr oder anderes als die eine Regel:"; printf '        %s\n' "$L"; fi

have=$(tail -n +2 "$C" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "$have" = "$WANT_SHA" ] && ok "Collector entspricht SSHBITE 0.1.0 (sha256 $have)" || fail "Collector-Pruefsumme $have, erwartet $WANT_SHA"

AK=$H/.ssh/authorized_keys
n=$(grep -cv -e '^#' -e '^[[:space:]]*$' "$AK" 2>/dev/null)
[ "$n" = 1 ] && ok "authorized_keys: genau ein Schluessel" || fail "authorized_keys: $n Schluesselzeilen (erwartet 1)"
k=$(grep -v -e '^#' -e '^[[:space:]]*$' "$AK" 2>/dev/null | head -n 1)
case "$k" in restrict,*) ok "authorized_keys: restrict" ;; *) fail "authorized_keys: Zeile beginnt nicht mit restrict" ;; esac
case "$k" in *"command=\"$G\""*) ok "authorized_keys: command=\"$G\"" ;; *) fail "authorized_keys: Forced Command fehlt" ;; esac
case "$k" in *'from="'*) ok "authorized_keys: from= gesetzt" ;; *) fail "authorized_keys: from= fehlt" ;; esac
case "$k" in *'<'*) fail "authorized_keys: Platzhalter <...> nicht ersetzt" ;; esac
case "$k" in *port-forwarding*) echo "HINWEIS port-forwarding erlaubt - nur auf Einstiegs-Host und noetigen Hops richtig" ;; esac
exit "$bad"
```
