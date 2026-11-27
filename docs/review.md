<a id="read-only-review-guide"></a>

# Leitfaden zur Prüfung des rein lesenden Verhaltens

SSHBITE darf die Systeme, die es prüft, nicht verändern. Dieser Leitfaden zeigt einem Prüfer – ohne den
Python-Code zu lesen –, was SSHBITE genau an einen Zielhost sendet, wie man das prüft und was die automatischen
Prüfungen garantieren und was nicht.

<a id="what-reaches-a-target"></a>

## Was einen Zielhost erreicht

SSHBITE spricht nur SSH (asyncssh im SSHBITE-Prozess; nirgends läuft ein `ssh`-Client). Auf einem Zielhost öffnet es
**Exec-Kanäle ohne Terminal** und führt genau diese Befehlszeichenketten aus – nichts davon wird je aus Daten
zusammengesetzt, die auf einem Zielhost gefunden wurden:

`sudo` steht in der Tabelle kurz für seinen absoluten Pfad: Jeder sudo-Befehl wird als
`test -x /usr/bin/sudo && exec /usr/bin/sudo ARGS; exec /bin/sudo ARGS` gesendet – also `/usr/bin/sudo`, oder
`/bin/sudo` nur dort, wo es den ersten nicht gibt. Der `PATH` des Audit-Kontos entscheidet nie, welches `sudo` läuft.

| Befehl | Wo | stdin |
|---|---|---|
| `sudo -n /bin/true` | jeder Host (`privilege.mode: sudo`) | – |
| `sudo -n /bin/sh -s` | wenn die Probe erfolgreich war | `collect.sh` |
| `sudo -S -k -p '' /bin/true` | wenn sudo ein Passwort verlangt, eines angegeben wurde und der Host innerhalb von `privilege.password_scope` liegt (leer = alle) | das Passwort |
| `sudo -S -k -p '' /bin/sh -s` | wenn diese Probe erfolgreich war | das Passwort, dann `collect.sh` |
| `/bin/sh -s` | wenn sudo nicht möglich ist (der Host wird `partial`) | `collect.sh` |
| `/bin/sh -c '<resolve.sh>'` | Einstiegshost (und ein verweisender Host für Namen, die der Einstiegshost nicht auflösen kann) | Hostnamen, einer pro Zeile, als Daten |

Mit `privilege.mode: sudo-login` tragen die sudo-Befehle `-i`; mit `none` wird nur `/bin/sh -s` verwendet.

### `privilege.mode: installed`

In diesem Modus (empfohlen, [install.md](install.md#zielhosts-vorbereiten-installierter-collector)) wird nichts
von oben gesendet. Dies sind die einzigen Befehlszeichenketten, P = `privilege.collector_path`
(Standard `/usr/local/libexec/sshbite/sshbite-collect`):

| Befehl | Wo | stdin |
|---|---|---|
| `sudo -n -l P` | jeder Host: die Probe | leer (sofort EOF) |
| `sudo -n P` | wenn die Probe erfolgreich war: der installierte Collector als root | leer (sofort EOF) |
| `<dir of P>/sshbite-resolve` | Einstiegshost (und ein verweisender Host für Namen, die der Einstiegshost nicht auflösen kann) | Hostnamen, einer pro Zeile, als Daten |

Kein Skript, kein `/bin/sh`, kein `-S`, kein Passwort und kein Rückfall auf einen Lauf ohne Rechte. `sudo` steht hier
ohne Pfad; das Gate führt `/usr/bin/sudo` aus (oder `/bin/sudo`, wo es den ersten nicht gibt). Das installierte
`sshbite-collect` ist `#!/bin/sh` plus `collect.sh` Byte für Byte; der Scan speichert den SHA-256 dieser Datei
(`collector sha256` in `sshbite scans show`), derselbe Wert wie in `SHA256SUMS` des Exports. Die erste
Ausgabezeile des Collectors trägt wie bisher B; ein Host mit einem anderen B wird `collector_error`
(*installed collector version differs*).

`sshbite-resolve` ist `#!/bin/sh` plus `resolve.sh`: `while IFS= read -r n; do getent hosts -- "$n" | …`.
Jeder Name wird als eine Zeile in eine Variable gelesen und nur, in Anführungszeichen und nach `--`, als Argument an
`getent` und als awk-Variable übergeben – nie ausgewertet oder ausgeführt. SSHBITE sendet außerdem nur Namen, die
auf `[A-Za-z0-9._-]` passen.

<a id="the-gate-sshbite-gate"></a>

### Das Gate `sshbite-gate`

Die `authorized_keys`-Zeile des Audit-Schlüssels führt das Gate aus (`command="…/sshbite-gate"`), egal was der Client
anfordert. Es ist ein kurzes POSIX-sh-Skript, geschrieben von `sshbite collector export`; lesen Sie es dort. Es

- setzt `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C` und `umask 077`;
- vergleicht `SSH_ORIGINAL_COMMAND` mit `[ "$C" = "…" ]` mit genau den drei Zeichenketten der Tabelle –
  kein Muster, kein `case`, kein `eval`, kein `sh -c`;
- führt `exec "$SUDO" -n -l P </dev/null`, `exec "$TIMEOUT" -k 5 3600 "$SUDO" -n P </dev/null` (schlicht
  `exec "$SUDO" -n P </dev/null`, wo coreutils `timeout` fehlt) oder `exec …/sshbite-resolve` aus (stdin wird für die
  Namen durchgereicht) – die sudo-Aufrufe erhalten `/dev/null` als stdin, sodass nichts, was ein Client sendet, sie
  erreichen kann. Nach 3600 s (dem größten `limits.host_timeout`) erhält sudo TERM und gibt es an den Collector
  weiter, 5 s später folgt KILL: Kein Root-Prozess überlebt einen abgebrochenen Scan lange;
- verweigert alles andere – einen leeren oder fehlenden Befehl (interaktive Anmeldung), Subsysteme wie sftp,
  die Befehle der Legacy-Modi, zusätzliche Argumente, andere Leerzeichen, angehängtes `; …` – mit
  `sshbite-gate: denied (command not allowed)` auf stderr und **Exit-Code 126**;
- protokolliert jede Anfrage in Syslog `authpriv` (`allowed: probe|collect|resolve` oder `denied: <command>`,
  nicht druckbare Zeichen als `?`, höchstens 200 Zeichen); `logger` läuft unter `timeout -k 1 2`, sodass ein
  hängendes Syslog eine Anfrage um höchstens 3 s verzögert und ein fehlendes Syslog das Ergebnis nicht ändert;
- liest und hasht stdin nie.

Die sudoers-Datei erlaubt dem Konto genau einen Befehl: `sshbite ALL=(root) NOPASSWD: P ""` – P ohne
Argumente. `restrict` in `authorized_keys` schaltet pty, Agent- und X11-Weiterleitung ab; nur der Einstiegshost (und
Hops) dürfen weiterleiten, und nur zu Port 22 (`permitopen`); sie dürfen keinen entfernten TCP-Listener öffnen
(`permitlisten="localhost:22"`, siehe [install.md](install.md#die-authorized_keys-varianten)). Der Lab-Test
`tests/e2e/test_lab_installed.py` (i04) versucht eine Shell mit und ohne pty, `/bin/sh -s` mit einem Skript, beide
sudo-Befehle der Legacy-Modi, `sudo -n -l P; id`, `sudo -n P x`, `sudo -n /bin/sh`, sftp, eine Weiterleitung an einen
anderen Port, Remote-Weiterleitungen (`ssh -R`) und eine Anmeldung von einer anderen Adresse: Alles wird verweigert.

Auf dem Einstiegshost und auf Hops einer verketteten Route öffnet SSHBITE zusätzlich `direct-tcpip`-Kanäle
(Port-Weiterleitung) zum nächsten Host. Es verwendet **nicht** den ssh-Client des Hops, daher wird auf einem Hop keine
`known_hosts`-Datei gelesen oder geschrieben. Es fordert nie ein pty, Agent-Weiterleitung, X11-Weiterleitung, sftp oder
scp an und verwendet nie einen auf einem Zielhost gefundenen Schlüssel.

<a id="print-what-is-sent"></a>

## Gesendete Befehle ausgeben

```sh
sshbite collector show > collector-review.txt
docker exec sshbite sshbite collector show > collector-review.txt     # Docker
```

Die Ausgabe hat drei Teile:

```text
===== collect.sh  sha256 6c262392…40f05  lint: OK
<the complete script>
===== resolve.sh  sha256 f048726e…f2ff  lint: OK
<the complete script>
===== literal commands sent on exec channels (privilege.mode: sudo / sudo-login)
<every command string of the table above>
===== literal commands sent on exec channels (privilege.mode: installed, collector_path /usr/local/libexec/sshbite/sshbite-collect)
<the three command strings of mode installed>
```

Die installierten Dateien selbst stammen aus `sshbite collector export DIR`; `sshbite-collect` und
`sshbite-resolve` sind dort die beiden obigen Skripte mit einer vorangestellten Zeile `#!/bin/sh`.

Prüfen Sie gegen die installierte Version: Die Skripte sind Teil des Pakets und werden aus ihm ausgegeben.
Jeder Scan speichert den SHA-256 des `collect.sh`, das er gesendet hat – angezeigt von `sshbite scans show ID`
(`collector sha256 …`) und auf der Seite des Scans in der UI. Weicht er von dem Hash ab, den Sie geprüft haben, wurde
eine andere Version verwendet. Die zweite Zeile des Skripts, `B=<12 hex digits>`, ist der Kurz-Hash seines Rumpfs
(ein Unit-Test hält ihn korrekt); der Collector gibt ihn in seiner ersten Ausgabezeile aus, und SSHBITE markiert einen
Host als `collector_error`, wenn diese Zeile nicht passt.

<a id="reviewing-collectsh"></a>

## `collect.sh` prüfen

Lesen Sie es von oben nach unten; es sind etwa 300 Zeilen POSIX sh. Zu bestätigen ist:

1. **Die erste Zeile** legt die Umgebung fest: `LC_ALL=C; export LC_ALL; PATH=/usr/sbin:/usr/bin:/sbin:/bin; set -u`.
2. **Ausgabe geht nur nach stdout.** Die einzigen Umleitungen sind `2>/dev/null`, `2>&1` und `</dev/null`;
   es gibt kein `>`, `>>` oder `tee`, also kann nichts in eine Datei geschrieben werden.
3. **Nur lesende Befehle:** `cat head ls stat awk sed grep getent ip hostname uname id sort printf
   test [ true`, dazu `ssh-keygen` und `sshd` in festen Formen, `setpriv` in genau einer Form (siehe
   [unten](#dateien-in-home-verzeichnissen-werden-als-ihr-besitzer-gelesen)), dazu die im Skript selbst definierten
   Shell-Funktionen (`sec`, `val`, `fhdr`, `uls`, …).
4. **Abschnitte und was sie lesen:**

   | Abschnitt | Liest |
   |---|---|
   | META | `hostname`, `uname -srm`, `id -u`, `/etc/os-release` (20 Zeilen), Schnittstellenadressen (`ip -o addr show`, sonst `hostname -I`, sonst `ifconfig -a`) |
   | HOSTKEYS | `/etc/ssh/ssh_host_*_key.pub` |
   | SSHD | `sshd -T` (gibt die wirksame Konfiguration aus), `/etc/ssh/sshd_config` und bis zu 20 Dateien aus deren `Include`-Zeilen |
   | ACCOUNTS | `getent passwd` (höchstens 20.000 Zeilen), sonst `/etc/passwd` |
   | SHADOW | nur root: `awk -F: '{print $1":"substr($2,1,1)":"$8}' /etc/shadow` – der Benutzername, das **erste Zeichen** des Hash-Felds (`!`, `*`, `$`) und das Ablaufdatum. Kein Hash verlässt den Host. |
   | USERS | **als das Konto** (`setpriv`, siehe unten), pro Konto mit `~/.ssh` oder einer authorized_keys-Datei (höchstens 2.000): Dateimetadaten jedes Eintrags in `~/.ssh` (höchstens 100); der Inhalt von `authorized_keys*` (gemäß `AuthorizedKeysFile`), `known_hosts*`, `config`, `*.pub` (höchstens 5.000 Zeilen, Dateien > 1 MiB werden übersprungen) |
   | private Schlüssel | nie ausgegeben. Nur ihre erste Zeile (`-----BEGIN … PRIVATE KEY-----`), `ssh-keygen -y -P '' -f FILE` (gibt den **öffentlichen** Schlüssel aus, wenn es keine Passphrase gibt; „incorrect passphrase“ bedeutet verschlüsselt) und `ssh-keygen -l -f FILE` (Fingerprint) |
   | SYSTEM | `/etc/ssh/ssh_known_hosts`, `/etc/ssh/ssh_config`, `/etc/ssh/ssh_config.d/*` (höchstens 20) |

5. **Nichts vom Zielhost wird ausgeführt.** Dateinamen und Dateiinhalte werden nur als Argumente übergeben
   oder ausgegeben; kein `eval`, kein `$var` als Befehlsname, keine Backquotes, kein `sh -c "$x"`.

`resolve.sh` ist eine Zeile: `while IFS= read -r n; do getent hosts -- "$n" | awk …; done`. Die Namen
kommen über stdin und sind immer nur ein Argument von `getent hosts`. SSHBITE sendet nur Namen, die auf
`^[A-Za-z0-9._-]{1,253}$` passen, höchstens 500 pro Aufruf.

<a id="what-the-allowlist-lint-guarantees"></a>

## Was der Allowlist-Lint garantiert

`sshbite/collector/lint.py` prüft beide Skripte statisch. Er läuft in den Unit-Tests (`tests/unit/test_lint.py`,
Teil der CI) und jedes Mal, wenn `sshbite collector show` ein Skript ausgibt (`lint: OK` oder die Verstöße). Er
zerlegt die Skripte so in Tokens, wie es eine POSIX-Shell tut – Quoting, Kommentare, Pipelines, Listen,
`if`/`while`/`case`, Funktionsdefinitionen und `$(…)`-Befehlssubstitutionen, rekursiv – und schlägt fehl bei:

- jedem Befehl, der nicht auf der obigen Allowlist steht (oder keine im Skript definierte Funktion ist, oder keines
  der Builtins `set export read continue break return shift :`);
- jedem von `rm mv cp tee touch mkdir mktemp chmod chown ln dd install truncate ssh scp sftp curl wget eval
  exec . source sh bash sudo su xargs env nohup nc socat python python3 perl runuser`;
- `setpriv` in jeder anderen Form als `setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs --
  CMD` (Wort für Wort verglichen, einschließlich Anführungszeichen), oder wenn es etwas anderes als
  `ls stat head test ssh-keygen` umschließt (deren Argumente dann nach ihren eigenen Regeln geprüft werden); einer
  Variablen als umschlossenem Befehl;
- einem Befehlsnamen, der `$` enthält (aus Daten gebaut), einem Befehl mit einem unerwarteten absoluten Pfad (nur
  `/usr/sbin/sshd` ist erlaubt), Hintergrundjobs (`&`) und Backquotes;
- jeder anderen Umleitung als `2>/dev/null`, `2>&1`, `</dev/null`, und `>>` an jeder Stelle;
- Argumenten außerhalb der festen Formen: `ssh-keygen` nur `-y -P "" -f FILE` und `-l -f FILE`; `sshd` nur
  `-T`; `sed` nur `s/^/|/`; `ip` nur `-o addr show`; `hostname` nur ohne Argumente oder `-I`;
  `ifconfig` nur `-a`; `getent` nur `passwd` oder `hosts`; `sort` ohne Ausgabeoptionen; `awk`-Programmen
  ohne `system()`, `getline`, `close`/`fflush` oder `print`/`printf` mit Umleitung in eine Datei oder Pipe.

Tests füttern den Lint außerdem absichtlich mit schlechten Skripten (`>`-Dateien, `sed -i`, `eval`, `$cmd`,
`curl`, …), um zu zeigen, dass er sie erkennt.

<a id="what-the-lint-does-not-guarantee"></a>

## Was der Lint nicht garantiert

- **Er prüft die ausgelieferten Skripte, nicht die Programme auf dem Zielhost.** Auf einem kompromittierten Host
  können `cat` oder `sudo` ersetzt sein. SSHBITE behandelt alles, was es liest, als nicht vertrauenswürdige Daten
  (Größenbegrenzungen, nichts wird ausgeführt oder als HTML dargestellt), kann einen kompromittierten Host aber nicht
  dazu bringen, die Wahrheit zu sagen.
- **Erlaubte Befehle können eigene Nebenwirkungen haben.** `sshd -T` und `ssh-keygen -y/-l` geben nur aus,
  was der Lab-Test prüft (siehe unten). Das Lesen von Dateien kann Zugriffszeiten aktualisieren; Anmeldungen und sudo
  werden protokolliert. All das ist in [side-effects.md](side-effects.md) aufgeführt.
- **Die wörtlichen sudo/sh-Befehlszeichenketten** sind nicht Teil der Skripte; sie sind in
  `sshbite/privilege.py` festgelegt und werden zur Prüfung von `collector show` ausgegeben.

<a id="files-in-user-homes-are-read-as-their-owner"></a>

## Dateien in Home-Verzeichnissen werden als ihr Besitzer gelesen

Der Collector läuft als root, liest aber die Dateien anderer Benutzer nicht als root. Alles, was er unterhalb des
`~/.ssh` eines Benutzers liest, und jeden `AuthorizedKeysFile`-Pfad dieses Benutzers (auch absolute wie
`/etc/ssh/authorized_keys/%u`), liest er **als dieser Benutzer** – so, wie sshd selbst authorized_keys liest:

- die Hilfsfunktionen `uls`, `ustat`, `ulsnd`, `uread`, `utest` und `ukg` am Anfang von `collect.sh` führen `ls -A`,
  `stat` (und dessen Rückfall `ls -lnd`), `head -c`, `test -r/-x/-f` und `ssh-keygen -y/-l` als
  `timeout -k 1 5 setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- CMD …` mit uid, gid und
  Gruppen des Kontos aus passwd aus. `setpriv` (util-linux) wechselt nur die IDs; es öffnet keine PAM-Session und
  protokolliert nichts. `--no-new-privs` blockiert setuid-Programme. `runuser` und `su` verbietet der Lint, und
  `setpriv` erlaubt der Lint nur genau hinter `timeout -k 1 5`;
- das gilt, wenn der Collector als root läuft und die uid des Kontos nicht 0 ist. Das eigene Home-Verzeichnis von root
  wird als root gelesen; ein Collector ohne Rechte liest wie bisher alles als er selbst;
- nur die Shell-Tests `[ -L ] [ -d ] [ -f ] [ -e ]` laufen als root – sie betrachten Metadaten, nie Inhalte.
  HOSTKEYS, SSHD, SHADOW, SYSTEM und META bleiben root;
- eine Datei, die der Benutzer nicht lesen kann (z. B. eine root gehörende `authorized_keys2` mit 0600 im
  Home-Verzeichnis), wird als `unreadable by account` gemeldet und beim Host als Grund `unreadable by account: PATH`
  angezeigt; der Host bleibt `ok`. sshd kann eine solche Datei ebenfalls nicht verwenden;
- `ssh-keygen` lehnt einen privaten Schlüssel ab, den Gruppe oder andere lesen dürfen, wenn seine *reale* uid der
  Besitzer des Schlüssels ist („bad permissions“, wie `ssh` es tut). Nur dann läuft es noch einmal als
  `timeout -k 1 5 setpriv --ruid="$nbd" --euid="$uid" --regid="$gid" --clear-groups --no-new-privs --
  ssh-keygen -y -P '' -f PATH`: reale uid `nobody` (aus passwd), effektive und gespeicherte uid das Konto, keine
  zusätzlichen Gruppen, keine Capability. Es öffnet die Datei mit den Rechten des Kontos (der Race unten bringt
  nichts) und akzeptiert sie, weil seine reale uid nicht der Besitzer ist. Kein `ssh-keygen` parst Bytes eines
  Benutzers als root, und keines liest stdin (der Lint verweigert `/dev/stdin`, `-` und `/dev/fd/N` für
  `ssh-keygen`). Der Schlüssel verlässt den Host nie; nur seine öffentliche Hälfte wird ausgegeben. Ein solcher
  Schlüssel wird daher weiterhin als *unencrypted* und mit *bad permissions* gemeldet; bei einem *verschlüsselten*
  Schlüssel, den andere lesen dürfen, bleibt der Passphrase-Zustand *unknown* (nur ein Erfolg ersetzt die erste
  Antwort). Ohne ein Konto `nobody` (uid ≠ 0) in passwd entfällt der zweite Versuch, und der Schlüssel wird nur als
  *bad permissions* gemeldet. (Die frühere Pipe in das eigene `ssh-keygen` des Collectors lässt sich nicht auf das
  Konto verlagern: Die Pipe gehört root, und das Konto darf `/dev/stdin` nicht erneut öffnen – geprüft auf Debian 12
  und AlmaLinux 9.);
- **Zeitlimit:** Ein Benutzer kann eine Datei nach den Prüfungen des Collectors (`[ -f ]` als root,
  `test -f` als der Benutzer direkt vor dem Lesen) gegen eine FIFO austauschen; deren Öffnen blockiert für immer.
  Jedes Lesen als das Konto endet daher nach 5 s (TERM, KILL 1 s später); die Datei wird als `read timed out` gemeldet,
  und der Lauf geht mit der nächsten Datei weiter. Eine lokale Datei von höchstens 1 MiB ist in Millisekunden gelesen;
  5 s lassen Spielraum für einen ausgelasteten Host oder ein Home-Verzeichnis im Netzwerk. Nach zwei Zeitüberschreitungen
  wird der Rest dieses Kontos übersprungen (`time budget exceeded`), sodass ein Konto einen Lauf um höchstens etwa
  12 s verzögert. `read timed out` wird beim Host als Grund angezeigt, der Host bleibt `ok`; `time budget exceeded`
  macht ihn `partial`. Ohne `timeout` (coreutils) liest der Collector nichts in Home-Verzeichnissen (`timeout
  (coreutils) missing: files in user homes not read`, `partial`). Im Modus installed begrenzt das Gate außerdem den
  gesamten Collector-Lauf auf 3600 s (das größte `limits.host_timeout`), danach gibt sudo TERM an den Collector weiter;
- **Ausgabebudget:** Wie bisher wird eine Datei bis 1 MiB (sonst `too large`) und 5000 Zeilen gelesen; jetzt wird das
  an den gelesenen Bytes geprüft, nicht nur über `stat`. Zusätzlich darf ein Konto höchstens 4 MiB Dateiinhalt ausgeben
  (vier Dateien an der Dateigrenze – ein echtes Konto hat einige KiB, eine große known_hosts etwa 1 MiB). Darüber
  hinaus wird der Rest des Kontos mit `output budget exceeded` für sein `~/.ssh` übersprungen, der Host ist `partial`,
  und das nächste Konto wird vollständig gelesen: Ein Benutzer kann Konten, die später in `/etc/passwd` stehen, nicht
  aus dem Transportlimit (`limits.max_output_mb`, 32 MiB) drängen. Die `AuthorizedKeysFile`-Dateien eines Kontos
  werden zuerst gelesen, sodass eine Flut an anderer Stelle in seinem `~/.ssh` sie nicht verdrängen kann;
- **sicherer Fehlerfall (fail closed):** Ohne `/usr/bin/setpriv` (oder `/bin/setpriv`) liest der Collector nichts in
  Home-Verzeichnissen – kein Rückfall auf root –, und der Host wird `partial` mit
  `setpriv (util-linux) missing: files in user homes not read`. Host-Keys, sshd und die Shadow-Zusammenfassung
  werden trotzdem eingesammelt.

Der alte Race – ein lokaler Benutzer tauscht zwischen Prüfung und Lesen des Collectors eine Datei in seinem `~/.ssh`,
oder `~/.ssh` selbst, gegen einen Symlink auf eine Datei, die nur root lesen darf – liefert also nur noch Namen,
Metadaten und Inhalte, die dieser Benutzer ohnehin lesen darf. POSIX sh kann eine Datei immer noch nicht öffnen und
danach prüfen, und das Fenster zwischen `[ -L ]` und dem Lesen besteht weiterhin; es spielt keine Rolle mehr.

Der Lab-Test `i08_race` (`tests/e2e/test_lab_installed.py`, mit `lab/race.sh`) belegt das auf einem Debian-12- und
einem AlmaLinux-9-Host: Ein lokaler Benutzer wechselt `~/.ssh/known_hosts` zwischen einer Datei und einem Symlink auf
eine Canary-Datei, die nur root lesen darf, und `~/.ssh` zwischen dem Verzeichnis und einem Symlink auf
ein Verzeichnis, das nur root lesen darf, in Endlosschleifen. 200 Lesevorgänge als root (die Kontrolle) müssen den
Canary mindestens einmal sehen; 200 Collector-Läufe durch das installierte Gate dürfen ihn kein einziges Mal sehen, und
mindestens einer davon muss auf den getauschten Zustand getroffen sein (`symlink not followed` oder
`unreadable by account`). Die Zählungen stehen in `evidence/hardening/race-count.md`.

Die FIFO-Variante (`i09_fifo_race`, `lab/race.sh start fifo`) wechselt `~/.ssh/known_hosts` zwischen einer Datei,
einem Symlink und einer FIFO. Die Kontrolle (root, `head` unter `timeout 2`) muss mindestens einmal blockieren; 200
Collector-Läufe durch das Gate pro Host müssen alle innerhalb von 30 s mit `#END` enden, mindestens einer muss
`read timed out` melden, und danach darf kein Root-Prozess von `sudo` oder `sshbite-collect` auf dem Host übrig sein
(`evidence/hardening/race-count-fifo.md`). `i10_flood` flutet `~/.ssh` eines Benutzers mit 40 Dateien zu je 1 MB und
prüft, dass ein Konto, das später in passwd steht, vollständig ist und der Host `partial` mit `output budget exceeded`
ist.

<a id="residual-risk-the-audit-key-reveals-the-inventory"></a>

## Restrisiko: Der Audit-Schlüssel verrät das Inventar

Auch mit `privilege.mode: installed` kann jeder, der den Audit-Schlüssel besitzt und sich von einer erlaubten Adresse
verbindet, den installierten Collector ausführen und lesen, was er ausgibt: jede `authorized_keys`-Zeile,
`known_hosts`, ssh-Konfigurationen, öffentliche Schlüssel, `sshd -T` und aus `/etc/shadow` nur
`name:first character:expiry`. Das ist eine Landkarte, wer sich wo anmelden darf – wertvoll für einen Angreifer, aber
kein Root-Zugriff: Der Schlüssel gibt keine Shell, keinen eigenen Befehl, keine Root-Datei außerhalb dieses Inventars
und keinen Schreibzugriff. Schützen Sie den Schlüssel entsprechend (Modus 0600, ein eigener Rechner, `from=` auf jedem
Host).

<a id="how-read-only-behaviour-is-tested"></a>

## Wie das rein lesende Verhalten getestet wird

Der Lab-Test (`tests/e2e/test_lab.py`, in der CI gegen 13 echte OpenSSH-9.2-Hosts ausgeführt) erstellt vor und nach
jedem Scan einen Snapshot von `/etc`, `/root` und `/home` auf jedem Host der Testumgebung – jeder Pfad mit Modus,
Besitzer, Größe und mtime, dazu der SHA-256 jeder regulären Datei – und schlägt fehl, wenn sie nicht identisch sind.
Eine separate Prüfung (`lab/writecheck.sh`) führt `sshd -T` und `ssh-keygen -y/-l` auf Hosts der Testumgebung aus und
bestätigt, dass sich auf dem Root-Dateisystem nichts ändert (außerhalb von `/proc`, `/sys`, `/dev`, `/run`,
`/var/log`).
