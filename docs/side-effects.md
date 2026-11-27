<a id="side-effects-on-the-audited-systems"></a>

# Nebenwirkungen auf den geprüften Systemen

SSHBITE schreibt keine Datei auf einem Zielhost – nicht unter `/etc`, `/root` oder `/home`, nicht in `/tmp`, in keine
`known_hosts` (siehe [review.md](review.md)). Aber Anmelden, sudo-Aufrufe und das Lesen von Dateien sind nicht
unsichtbar. Diese Seite listet alles auf, was ein Scan hinterlassen oder auslösen kann, damit Sie die richtigen
Personen **vor dem ersten echten Scan** warnen können. Nach einem Sicherheitsvorfall sehen mehrere dieser Spuren genau
so aus wie ein Angreifer, der sich seitlich im Netz bewegt.

<a id="tell-these-people-first"></a>

## Diese Personen zuerst informieren

| Wer | Warum |
|---|---|
| **Empfänger von sudo-Mails** (`root`-Aliase, Ticketsysteme) | sudo kann einen Bericht *"SECURITY information for HOST"* – „This incident has been reported to the administrator“ – für jeden Host mailen, auf dem sudo verweigert oder ein Passwort verlangt, und zwar bei jedem Scan (siehe unten). |
| Betreiber von SOC / IDS / EDR | SSH vom Einstiegshost zu jedem Zielhost, ein Port-Sweep für CIDR-Seeds, root liest private Schlüssel und `/etc/shadow`. |
| Forensik, falls eine Untersuchung läuft | Das Lesen von Dateien kann deren Zugriffszeiten ändern. |
| Verantwortliche für fail2ban / sshguard / CrowdSec | Fehlgeschlagene Anmeldungen des Audit-Kontos können zur Sperre der Adresse des Einstiegshosts führen. |

<a id="sudo-the-incident-mail-on-refused-sudo"></a>

## Die Incident-Mail bei verweigertem sudo

Auf jedem Host führt SSHBITE zuerst `sudo -n /bin/true` aus (mit `privilege.mode: sudo`; sudo über seinen absoluten
Pfad `/usr/bin/sudo`, oder `/bin/sudo`, wo es den ersten nicht gibt). Immer wenn sudo
verweigert, kann es einen Bericht an `mailto` (Standard `root`) mit dem Betreff
*"\*\*\* SECURITY information for HOST \*\*\*"* mailen, sofern der Host Mail versenden kann. Welche Verweigerungen
eine Mail auslösen, hängt von den sudoers-Optionen ab. Debian und Ubuntu liefern `Defaults mail_badpass` in
`/etc/sudoers` aus, und sudos `mail_no_user` ist standardmäßig eingeschaltet. Folgendes haben wir in der Testumgebung
(Lab) beobachtet (Debian 12, sudo 1.9.13, Debians Standard-sudoers, Mails mit einem Test-Mailer aufgefangen):

| Audit-Konto auf dem Host | Was SSHBITE ausführt | Mail |
|---|---|---|
| `NOPASSWD`-Regel ([install.md](install.md#legacy-modus-sudo-binsh--s-entspricht-vollem-root-zugriff)) | `sudo -n …` | **keine** |
| Regel, die ein Passwort verlangt | `sudo -n /bin/true` (Probe) | **ja**: `sshbite : a password is required ; … COMMAND=/bin/true` – bei jedem Scan, auch wenn das richtige Passwort danach angegeben wird |
| Regel, die ein Passwort verlangt, falsches `--ask-sudo-password` | `sudo -S -k -p '' /bin/true` | **ja, eine zweite**: `1 incorrect password attempt` |
| gar keine Regel | `sudo -n /bin/true` | keine (sudo meldet nur „a password is required“) |
| gar keine Regel, und `--ask-sudo-password` ist das echte Passwort des Kontos | `sudo -S -k -p '' /bin/true` | **ja**: `user NOT in sudoers` (die Konsole meldet „This incident has been reported to the administrator“) |

Ein Scan kann also eine oder zwei Mails **pro Host und pro Scan** auslösen; ein nächtlicher Timer wiederholt sie jede
Nacht. Hosts, auf denen sudo verweigert wird, werden ohne Rechte gescannt und als `partial` markiert. Weitere Optionen
(`mail_no_perms`, `mail_always`) erzeugen zusätzliche Mails, wo sie eingeschaltet sind; andere sudo-Versionen und
Distributionen können sich anders verhalten.

So vermeiden Sie die Mails: Verteilen Sie vor dem Scan auf jedem Host eine `NOPASSWD`-Regel für das Audit-Konto.
Verlangt Ihre Richtlinie ein Passwort, informieren Sie die Mail-Empfänger, wann Scans laufen und von welchem Konto,
oder erwägen Sie `Defaults:sshbite !mail_badpass` auf diesen Hosts (das verbirgt allerdings auch echtes Passwortraten
gegen dieses Konto). Mit `privilege.mode: none` ruft SSHBITE nie sudo auf (alle Hosts werden `partial`).

<a id="logs-written-on-every-scanned-host"></a>

## Logs auf jedem gescannten Host

- **Authentifizierungslog / Journal** (`/var/log/auth.log`, `/var/log/secure`, `journalctl`): sshd protokolliert die
  Anmeldung von `sshbite` mit dem Fingerprint des Audit-Schlüssels und der Quelladresse – dem SSHBITE-Rechner beim
  Einstiegshost, dem Einstiegshost (oder dem vorherigen Hop einer verketteten Route) bei allen anderen – sowie
  PAM-Zeilen zum Öffnen und Schließen der Session. Hosts, auf denen der Schlüssel nicht verteilt ist, protokollieren
  stattdessen fehlgeschlagene Anmeldungen (`Connection closed by authenticating user sshbite … [preauth]`).
- **sudo-Log** (Auth-Log, Journal oder sudos eigene Logdatei): eine Zeile pro sudo-Befehl, also
  `COMMAND=/bin/true` und `COMMAND=/bin/sh -s` pro Host, und `incorrect password attempt` bei einem falschen
  sudo-Passwort, dazu PAM-Session-Zeilen für root.
- **Mit `privilege.mode: installed`** erhält das sudo-Log stattdessen zwei Einträge pro Host: die Probe
  `sudo -n -l <collector>` und den Collector-Lauf `sudo -n <collector>`; `config validate --connect` fügt
  dieselben zwei auf dem Einstiegshost hinzu. Das Gate `sshbite-gate` protokolliert jede Anfrage des Audit-Schlüssels
  in die Syslog-Facility `authpriv` mit dem Tag `sshbite-gate` (jeder `logger`-Aufruf erhält höchstens 2 s):
  `allowed: probe`, `allowed: collect` und `allowed: resolve` (info) – drei bis vier Zeilen pro Host und Scan – und
  `denied: <command>` (warning) für alles andere. Eine `denied`-Zeile von der Adresse des SSHBITE-Rechners während
  eines Scans bedeutet eine Abweichung in Konfiguration oder Installation; zu jedem anderen Zeitpunkt lohnt sich ein
  genauer Blick. Es wird nie ein sudo-Passwort gesendet, daher kann die „Incident“-Mail oben nicht durch ein falsches
  Passwort ausgelöst werden; ein Host, dessen sudo-Regel kein `NOPASSWD` hat, verweigert die Probe aber trotzdem
  (und kann eine Mail senden).
- **sudo-I/O-Logging:** Ist `log_input`/`log_output` für das Konto eingeschaltet, zeichnet sudo das Collector-Skript
  und seine vollständige Ausgabe (Inhalte von authorized_keys, Dateilisten, das erste Zeichen jedes Shadow-Hash-Felds)
  in seinem I/O-Log-Verzeichnis auf (z. B. `/var/log/sudo-io`). Dieses Verzeichnis enthält dann eine Kopie des
  Inventars – schützen Sie es oder schalten Sie es für das Audit-Konto ab. Scannen Sie mit einem sudo-Passwort, prüfen
  Sie, ob Ihre sudo-Version auch dieses dort aufzeichnet, oder verwenden Sie auf solchen Hosts `NOPASSWD`.
- **wtmp / lastlog / utmp:** OpenSSH schreibt diese nur für Sessions mit Terminal. SSHBITE fordert kein Terminal an,
  daher zeigen `last` und `lastlog` das Audit-Konto normalerweise nicht. PAM-Module in Ihrem sshd-Stack
  (z. B. `pam_lastlog`, `pam_wtmp`) können die Anmeldung trotzdem aufzeichnen.
- **auditd / Process Accounting:** Wenn eingeschaltet, wird jedes `exec` (`sudo`, `sh`, `cat`, `ssh-keygen`,
  `sshd -T`, …) und jedes Lesen überwachter Dateien wie `/etc/shadow` aufgezeichnet.

<a id="other-state-outside-etc-root-home"></a>

## Weitere Spuren auf dem System

Dieser Abschnitt betrifft Zustand außerhalb von `/etc`, `/root` und `/home`.

- **sudo-Lecture-Markierung:** Nach dem ersten sudo *mit Passwort* kann sudo `/var/lib/sudo/lectured/sshbite`
  anlegen (der Pfad unterscheidet sich je nach Distribution). `Defaults:sshbite !lecture` verhindert das.
- **sudo-Zeitstempel** in `/run/sudo/ts/` (tmpfs, nach einem Neustart weg), abhängig von sudo-Version und
  Richtlinie. Die Passwort-Befehle von SSHBITE verwenden `sudo -k`, womit sudo die Authentifizierung nicht
  zwischenspeichert.
- **systemd-logind:** Auf systemd-Hosts erzeugt die Anmeldung eine Session für `sshbite`, startet eventuell dessen
  User-Manager (`user@UID.service`) und legt `/run/user/UID` an; beides verschwindet mit dem Ende der Session (außer
  wenn Lingering für das Konto eingeschaltet ist).
- **Home-Verzeichnis:** SSHBITE schreibt dort nichts. Hat das Konto kein Home-Verzeichnis und ist `pam_mkhomedir`
  konfiguriert, legt PAM bei der ersten Anmeldung eines an.

<a id="file-access-times"></a>

## Zugriffszeiten von Dateien

Der Collector liest `authorized_keys`, `known_hosts`, ssh-Konfigurationen, `.pub`-Dateien, die erste Zeile privater
Schlüssel, `/etc/shadow`, `/etc/passwd`, `sshd_config` und weiteres. Mit der üblichen Mount-Option `relatime`
aktualisiert der Kernel beim Lesen die **Zugriffszeit** einer Datei, wenn diese älter als ihre Änderungszeit oder
älter als 24 Stunden war (nicht mit `noatime`). Modifikations- und Change-Zeit bleiben unberührt, und der Lab-Test
prüft, dass sich Inhalte, Rechte, Besitzer, Größen und mtimes nicht ändern.

Stützt sich eine forensische Untersuchung auf Zugriffszeiten, erstellen Sie deren Images oder Zeitleisten **vor** dem
Scan, oder teilen Sie den Ermittlern mit, welches Konto und welches Zeitfenster sie ignorieren sollen.

<a id="network-and-security-monitoring"></a>

## Netzwerk und Sicherheitsüberwachung

- Eine Gruppe von SSH-Verbindungen vom SSHBITE-Rechner zum Einstiegshost (`limits.entry_connections`, Standard 4);
  vom Einstiegshost aus eine getunnelte SSH-Verbindung zu Port 22 (oder dem genannten Port) jedes gescannten Hosts –
  bis zu `limits.concurrency` (20) gleichzeitig. Mit dem verketteten Fallback leiten auch Zwischenhosts Verbindungen
  weiter. Für ein IDS oder NDR sieht das aus wie seitliche Bewegung (Lateral Movement) vom Einstiegshost aus.
- **CIDR-Seeds:** Jede Adresse aus `seeds.cidrs` erhält vom Einstiegshost einen TCP-Verbindungsaufbau zum SSH-Port –
  ein Port-Sweep.
- **DNS:** Hostnamen werden auf dem Einstiegshost mit `getent hosts` aufgelöst (und Namen, die er nicht auflösen kann,
  auf dem Host, der auf sie verweist) – also DNS-Anfragen von diesen Hosts. Gehashte `known_hosts`-Zeilen werden auf
  dem SSHBITE-Rechner ohne jeden Netzwerkverkehr abgeglichen.
- **EDR-Regeln für Zugriff auf Zugangsdaten:** root, der `ssh-keygen -y`/`-l` auf private Schlüssel anwendet und
  `/etc/shadow` liest, trifft gängige Erkennungen (z. B. MITRE ATT&CK T1552.004 *Private Keys*, T1003.008
  */etc/passwd and /etc/shadow*). Rechnen Sie mit Alarmen, oder nehmen Sie die Session des Audit-Kontos in Absprache
  mit dem SOC aus.
- **Fehlgeschlagene Anmeldungen und Sperren:** Hosts, auf denen der Audit-Schlüssel fehlt, sehen fehlgeschlagene
  Public-Key-Anmeldungen vom Einstiegshost. fail2ban, sshguard oder CrowdSec können die Adresse des **Einstiegshosts**
  sperren – das sperrt auch Administratoren aus, die diesen Jump-Host nutzen. Tragen Sie den Einstiegshost in deren
  Ausnahmelisten ein oder verteilen Sie zuerst den Schlüssel.

<a id="load"></a>

## Last

Pro Host: eine Anmeldung, zwei sudo-Aufrufe, einige Sekunden `sh`, `sshd -T` und ein `ssh-keygen`-Lauf pro
gefundenem privatem Schlüssel; die Ausgabe liegt meist deutlich unter 1 MB (begrenzt durch `limits.max_output_mb`).
Der Einstiegshost trägt alle Tunnel.

<a id="what-sshbite-does-not-do"></a>

## Was SSHBITE nicht tut

Es schreibt, erzeugt, löscht oder ändert keine Dateien auf Zielhosts, ändert auf keinem Hop `known_hosts` (dort läuft
kein ssh-Client), verwendet keine auf Zielhosts gefundenen Schlüssel, leitet keinen Agent weiter und probiert keine
Passwörter für SSH-Anmeldungen. Das einzige Passwort, das es je sendet, ist das sudo-Passwort, das Sie ihm geben, und
zwar an `sudo -S` auf Hosts, die danach fragen und innerhalb von `privilege.password_scope` liegen (leer = jeder Host).

<a id="the-sudo-password-can-be-captured-by-a-compromised-host"></a>

## Ein kompromittierter Host kann das sudo-Passwort abgreifen

SSHBITE ruft sudo über seinen absoluten Pfad auf, nie über den `PATH` des Audit-Kontos. Das schützt das Passwort nicht
vor einem Host, der bereits kompromittiert ist – dem Grund, aus dem Sie scannen. Root auf diesem Host kontrolliert
sudo selbst, die Login-Shell und sshd und kann eine sudo-Passwortabfrage nachahmen; SSHBITE sendet ihm dann das
Passwort, und es funktioniert auf jedem anderen Host, der es akzeptiert. Daher:

- bevorzugen Sie `NOPASSWD`-sudo für das Audit-Konto ([install.md](install.md#legacy-modus-sudo-binsh--s-entspricht-vollem-root-zugriff)) – dann wird kein Passwort gesendet;
- andernfalls geben Sie dem Audit-Konto ein Passwort, das **nur von diesem Konto verwendet wird**, und **ändern Sie es
  nach dem Scan**;
- begrenzen Sie die Hosts, die es erhalten dürfen, mit `privilege.password_scope`; ein Host außerhalb des Bereichs,
  der nach einem Passwort fragt, wird ohne Rechte gescannt und als partial markiert (*sudo password not sent (outside
  privilege.password_scope)*).

Mehr dazu in [operations.md](operations.md#das-sudo-passwort).

<a id="how-this-was-checked"></a>

## Wie das geprüft wurde

Der Lab-Test prüft, dass `/etc`, `/root` und `/home` von 13 echten OpenSSH-Hosts (Debian 12, OpenSSH 9.2,
sudo 1.9) und eines AlmaLinux-9-Hosts vor und nach jedem Scan byte-identisch sind, und dass `sshd -T` und `ssh-keygen`
auf dem Root-Dateisystem außerhalb von `/proc`, `/sys`, `/dev`, `/run` und `/var/log` nichts ändern (siehe
[review.md](review.md#wie-das-rein-lesende-verhalten-getestet-wird)). Die oben genannten Logeinträge, Mails,
Zugriffszeiten und Auswirkungen auf die Überwachung kann SSHBITE nicht vermeiden. Die sudo-Mails in der Tabelle wurden
in der Testumgebung mit einem Test-Mailer aufgefangen (`evidence/p3/sudo-mail-lab-test.txt`); die Testumgebung hat
keinen echten Mail Transfer Agent.
