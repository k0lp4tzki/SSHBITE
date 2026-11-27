<a id="configuration-reference"></a>

# Konfigurationsreferenz

SSHBITE liest eine YAML-Datei: den Pfad aus `-c PATH`, sonst aus `$SSHBITE_CONFIG`, sonst
`/etc/sshbite/sshbite.yaml` (im Docker-Image `SSHBITE_CONFIG=/etc/sshbite/sshbite.yaml`).
`sshbite init-config` gibt ein Beispiel mit jedem Schlüssel aus. Nur `entry.host` und `entry.host_keys` haben keinen
brauchbaren Standardwert.

- Unbekannte Schlüssel sind Fehler. Fehlermeldungen nennen den Pfad, z. B.
  `sshbite.yaml: crawl.include[2]: not a CIDR or glob`.
- Relative Dateipfade (`database`, `audit.key_file`, `seeds.*`, `hostkeys.known_hosts_file`) gelten relativ zum
  Verzeichnis der Konfigurationsdatei; `~` wird expandiert.
- Prüfen Sie eine Konfiguration mit `sshbite config validate` (fügen Sie `--connect` hinzu, um auch den Einstiegshost
  zu testen). Exit-Code 2 bedeutet einen Konfigurationsfehler.
- Halten Sie die Datei auf Modus 0600: `config validate` warnt, wenn die Konfiguration oder die Datenbank für Gruppe
  oder alle lesbar ist.

<a id="complete-example-with-the-defaults"></a>

## Vollständiges Beispiel mit den Standardwerten

```yaml
database: /var/lib/sshbite/sshbite.db
entry:
  host: jump01.corp.example     # so, wie er vom SSHBITE-Rechner aus erreichbar ist
  port: 22
  host_keys: ["ssh-ed25519 AAAAC3Nza..."]   # Pflicht; ein Treffer genügt zur Verifikation
audit:
  user: sshbite
  key_file: /etc/sshbite/audit_ed25519      # muss 0600 sein
  key_passphrase_env: null
privilege:
  mode: sudo   # sudo | sudo-login | none | installed (empfohlen, siehe docs/install.md)
  # collector_path: /usr/local/libexec/sshbite/sshbite-collect   # nur für Modus installed
  password_scope: []  # CIDRs / Hostnamen-Globs, die das sudo-Passwort erhalten dürfen; leer = jeder Host
crawl:
  max_depth: 10
  max_hosts: 1000
  include: []       # CIDRs / Hostnamen-Globs; leer = keine Einschränkung
  exclude: []       # hat immer Vorrang
  chain_fallback: true
  hash_probe_include_cidrs: true
  hash_probe_max_addresses: 4096
  ssh_port: 22
seeds:              # optionale zusätzliche Seeds, Tiefe 0
  hosts_file: null              # host oder host:port pro Zeile, '#' leitet Kommentare ein
  cidrs: []                     # jede Adresse wird über den Einstiegshost geprüft; insgesamt <= 65536
  ansible_inventories: []       # statisch, INI oder YAML
hostkeys:
  mode: tofu                    # tofu | strict
  known_hosts_file: null        # Pflicht bei strict
limits:
  concurrency: 20
  host_timeout: 30              # gesamter Host: Verbindung + Anmeldung + sudo-Probe + Einsammeln
  connect_timeout: 10           # pro Hop
  entry_connections: 4          # Tunnel werden über diese Verbindungen gebündelt
  max_output_mb: 32
rules:
  strength:                     # der erste Treffer gilt
    good:     [ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com]
    ok:       [ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, "ssh-rsa>=3072"]
    weak:     ["ssh-rsa>=2048"]
    critical: ["ssh-rsa<2048", ssh-dss]
  many_hosts_threshold: 10
  ignore_audit_key: true
grouping:
  tags: [{name: dmz, match: ["10.1.0.0/16", "web-*"]}]   # der erste Treffer gilt, sonst "untagged"
web:
  bind: 127.0.0.1
  port: 8722
  session_hours: 8
  secure_cookie: false          # true hinter einem TLS-Reverse-Proxy (mit --tls-cert immer true)
  trusted_proxies: []           # Proxy-IPs/CIDRs, deren X-Forwarded-For den Client nennt
```

Die Zeile `grouping.tags` ist ein Beispiel; der Standardwert ist „keine Tags“ (`tags: []`).

Verwenden Sie im Docker-Image `database: /data/sshbite.db` und Pfade unter `/etc/sshbite/`.

<a id="keys"></a>

## Konfigurationsschlüssel

<a id="top-level"></a>

### Oberste Ebene

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `database` | `/var/lib/sshbite/sshbite.db` | Die SQLite-Datenbank. Wird bei der ersten Verwendung mit Modus 0600 angelegt (Verzeichnis 0700). Scanner und UI teilen sie sich. Im Docker-Image muss sie `/data/sshbite.db` sein: `/data` ist das Volume des Images für die Datenbank (`/etc/sshbite` wird nur lesend eingebunden). |

### `entry`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `entry.host` | – (Pflicht) | Name oder Adresse des Einstiegshosts (Jump-Host), so wie er vom SSHBITE-Rechner aus erreicht wird. Wird immer gescannt, in Tiefe 0. |
| `entry.port` | `22` | Sein SSH-Port. |
| `entry.host_keys` | `[]` | Festgelegte Host-Keys, jeweils `"<algorithm> <base64> [comment]"`, wie von `ssh-keyscan` ausgegeben. Ein Treffer genügt zur Verifikation des Einstiegshosts. Leer = jeder Scan bricht ab (Exit-Code 3) und `config validate` schlägt fehl. Siehe [install.md](install.md#host-key-festlegen-und-konfiguration-schreiben). |

### `audit`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `audit.user` | `sshbite` | Konto, das auf jedem Host und jedem Hop verwendet wird. Behalten Sie im Modus `installed` `sshbite` bei: Die von `sshbite collector export` geschriebene sudoers-Datei (`sudoers.d-sshbite`) und die authorized_keys-Vorlage (`authorized_keys.sshbite`) enthalten fest `sshbite` bzw. `/home/sshbite`. Mit einem anderen Namen müssen Sie beide Dateien von Hand anpassen, und ihre Prüfsummen in `SHA256SUMS` stimmen dann nicht mehr. |
| `audit.key_file` | `/etc/sshbite/audit_ed25519` | Der private Audit-Schlüssel. Muss eine reguläre Datei mit Modus 0600 sein, lesbar für den Benutzer, unter dem SSHBITE läuft. Es ist der einzige Schlüssel, den SSHBITE je verwendet; Agents und auf Zielhosts gefundene Schlüssel werden nie verwendet. |
| `audit.key_passphrase_env` | `null` | Name einer Umgebungsvariablen, die die Passphrase des Schlüssels enthält (nicht die Passphrase selbst). Nicht gesetzte Variable = Konfigurationsfehler. |

### `privilege`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `privilege.mode` | `sudo` | `installed` (empfohlen): führt den Collector aus, den `sshbite collector export` geschrieben und Sie auf jedem Host installiert haben ([install.md](install.md#zielhosts-vorbereiten-installierter-collector)): Probe `sudo -n -l P`, dann `sudo -n P`, beide mit leerem stdin (P = `collector_path`); Namen werden mit dem exportierten `sshbite-resolve` neben P aufgelöst. Es wird kein Skript an eine Shell gesendet, nie ein sudo-Passwort gesendet, und es gibt keinen Rückfall auf einen Lauf ohne Rechte: Ein Host, dessen Probe fehlschlägt oder dessen Collector eine andere Version hat, wird `collector_error` mit einer Meldung, die sagt, was zu beheben ist. `--ask-sudo-password` wird abgelehnt (Exit-Code 2); `SSHBITE_SUDO_PASSWORD` wird mit einer Warnung ignoriert. `sudo` (der Standard; Legacy-Modus – entspricht vollem Root-Zugriff für jeden, der den Audit-Schlüssel besitzt, siehe [install.md](install.md#legacy-modus-sudo-binsh--s-entspricht-vollem-root-zugriff)): Probe `sudo -n /bin/true`, dann wird der Collector als `sudo -n /bin/sh -s` ausgeführt. `sudo-login`: dasselbe mit `-i` (Login-Umgebung von root). `none`: nie sudo aufrufen; jeder Host wird ohne Rechte gescannt und als `partial` markiert. Mit einem sudo-Passwort (`--ask-sudo-password` oder `SSHBITE_SUDO_PASSWORD`) wird ein Host, der danach fragt, mit `sudo -S -k -p ''` versucht. sudo wird immer über seinen absoluten Pfad aufgerufen (`/usr/bin/sudo`, sonst `/bin/sudo`). |
| `privilege.collector_path` | `/usr/local/libexec/sshbite/sshbite-collect` | Nur für Modus `installed`: wo der Collector auf den Hosts installiert ist. Ein absoluter Pfad aus Buchstaben, Ziffern, `.`, `_`, `-` und `/`, ohne `.`- oder `..`-Segment, höchstens 200 Zeichen. `sshbite-resolve` und `sshbite-gate` werden im selben Verzeichnis erwartet. In einem anderen Modus warnt `config validate`, dass der Schlüssel ignoriert wird. |
| `privilege.password_scope` | `[]` | CIDRs oder Hostnamen-Globs (Syntax wie include) der Hosts, die das sudo-Passwort erhalten dürfen. Leer = jeder Host. Einem Host außerhalb des Bereichs, der nach einem Passwort fragt, wird es nicht gesendet: Er wird ohne Rechte gescannt und als `partial` markiert mit *sudo password not sent (outside privilege.password_scope)*. Ein kompromittierter Host kann eine sudo-Passwortabfrage nachahmen – siehe [operations.md](operations.md#das-sudo-passwort). Muss im Modus `installed` leer sein (Fehler, Exit-Code 2). |

### `crawl`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `crawl.max_depth` | `10` | Hosts, die mehr als so viele Schritte von Tiefe 0 entfernt sind, werden als `max_depth` aufgeführt, nicht gescannt. `0` = nur Einstiegshost und Seeds. Bereich 0–100. CLI: `--max-depth`. |
| `crawl.max_hosts` | `1000` | Höchstzahl der in einem Scan eingereihten Hosts; weitere Verweise werden als `max_hosts` aufgeführt. Bereich 1–100000. CLI: `--max-hosts`. |
| `crawl.include` | `[]` | CIDRs (`10.1.0.0/16`) oder Hostnamen-Globs (`*.corp.example`). Wenn gesetzt, wird ein entdeckter Host nur gescannt, wenn einer seiner Namen (Glob, ohne Beachtung der Groß-/Kleinschreibung) oder eine seiner IPs (CIDR) passt; andere sind `out_of_scope`. Leer = keine Einschränkung: Dann stammen Ziele und Ports aus den known_hosts, `~/.ssh/config` und `from=`-Optionen der gescannten Hosts, und `config validate` und `scan` geben eine Warnung aus (*crawl.include is empty: …*). Der Einstiegshost wird immer gescannt. |
| `crawl.exclude` | `[]` | Gleiche Syntax. Zu einem passenden Host wird nie eine Verbindung aufgebaut, er wird nur als `excluded` aufgeführt. Exclude hat Vorrang vor include und vor Seeds. |
| `crawl.chain_fallback` | `true` | Scheitert die Standardroute (Einstiegshost → Zielhost) mit einem Netzwerkfehler, wird es entlang des Wegs erneut versucht, auf dem der Host entdeckt wurde (Einstiegshost → Elternhost → … → Zielhost), mit dem Audit-Konto und einer Host-Key-Prüfung auf jedem Hop. Authentifizierungsfehler lösen das nicht aus. |
| `crawl.hash_probe_include_cidrs` | `true` | Gehashte known_hosts-Zeilen (`\|1\|…`) werden gegen jeden im Scan bekannten Namen und jede IP abgeglichen; ist dies eingeschaltet, auch gegen jede IPv4-Adresse in den `include`-CIDRs. Dafür wird keine Verbindung aufgebaut. |
| `crawl.hash_probe_max_addresses` | `4096` | Obergrenze der include-CIDR-Adressen, die für gehashte Zeilen ausprobiert werden. Bereich 0–1048576. |
| `crawl.ssh_port` | `22` | Port für Verweise und Seeds, die keinen Port nennen. |

### `seeds`

Alle Seeds beginnen in Tiefe 0 neben dem Einstiegshost. Sie sind optional: Der Normalfall ist der Crawl allein vom
Einstiegshost aus.

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `seeds.hosts_file` | `null` | Eine Textdatei: ein `host`, `host:port` oder `[host]:port` pro Zeile; `#` leitet einen Kommentar ein. |
| `seeds.cidrs` | `[]` | Netze, deren jede Adresse vor dem Scan **vom Einstiegshost aus** per TCP geprüft wird (2 s); stumme Adressen erhalten den Status `no_ssh` und sind standardmäßig ausgeblendet. Insgesamt höchstens 65.536 Adressen. |
| `seeds.ansible_inventories` | `[]` | Statische Ansible-Inventories, INI oder YAML (`.yml`/`.yaml` oder beginnend mit `all:`/`---`). `ansible_host`, `ansible_port` und Bereiche wie `web[01:10]` werden ausgewertet; die erste Gruppe wird die `ansible`-Gruppe des Hosts in der Heatmap. Dynamische Inventories (Skripte, Plugins) werden nicht ausgeführt. |

### `hostkeys`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `hostkeys.mode` | `tofu` | `tofu`: Der erste für eine Adresse, einen Port und einen Algorithmus gesehene Schlüssel wird gespeichert; ein später abweichender Schlüssel ergibt den Status `hostkey_mismatch` und den kritischen Befund `host_key_changed`, und auf dem Host wird keine Anmeldung durchgeführt, bis `sshbite hostkey accept ADDR[:PORT]` ausgeführt wurde. `strict`: Der Schlüssel eines Hosts muss unter einem seiner Namen oder einer seiner Adressen in `known_hosts_file` stehen, sonst Status `hostkey_unknown`. Hops werden genauso geprüft. Der Einstiegshost wird immer gegen `entry.host_keys` geprüft. |
| `hostkeys.known_hosts_file` | `null` | OpenSSH-known_hosts-Datei für `strict` (dann Pflicht). |

### `limits`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `limits.concurrency` | `20` | Gleichzeitig eingesammelte Hosts. Bereich 1–500. CLI: `--concurrency`. |
| `limits.host_timeout` | `30` | Sekunden für einen Host insgesamt: Verbindung, Authentifizierung, sudo-Probe und Einsammeln. Überschritten = Status `timeout`. Größer als 0, höchstens 3600. CLI: `--timeout`. |
| `limits.connect_timeout` | `10` | Sekunden pro Hop für den Verbindungsaufbau. Größer als 0, höchstens 600. |
| `limits.entry_connections` | `4` | SSH-Verbindungen zum Einstiegshost; alle Tunnel werden über sie gebündelt. Bereich 1–32. |
| `limits.max_output_mb` | `32` | Höchstmenge an Collector-Ausgabe, die von einem Host gelesen wird. Wird sie erreicht, ergibt das den Status `output_limit`; die bis dahin gelesenen Daten bleiben erhalten und der Host zählt als partial. Bereich 1–1024. |

### `rules`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `rules.strength.good` / `.ok` / `.weak` / `.critical` | siehe Beispiel | Klassen der Schlüsselstärke. Jeder Eintrag ist ein Algorithmusname (`ssh-ed25519`) oder `algorithm` + `>=`, `<=`, `>`, `<` oder `==` + Bits (`"ssh-rsa>=3072"`; in YAML in Anführungszeichen setzen). Die Klassen werden in der Reihenfolge good, ok, weak, critical geprüft, und der erste passende Eintrag gilt; ein Schlüssel, auf den nichts passt, ist `unknown`. `critical`-Schlüssel erhalten den Befund `key_strength_critical`, `weak`-Schlüssel `key_strength_weak`. |
| `rules.many_hosts_threshold` | `10` | Ein Schlüssel, der auf mindestens so vielen Hosts autorisiert ist, erhält den Befund `key_on_many_hosts`. Mindestens 2. |
| `rules.ignore_audit_key` | `true` | Die eigenen authorized_keys-Zeilen des Audit-Schlüssels bei Kanten und Befunden auslassen. |

### `grouping`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `grouping.tags` | `[]` | Liste von `{name, match}`. `match` verwendet die Syntax von include/exclude. Ein Host erhält den ersten passenden Tag, sonst `untagged`. Die Heatmap kann nach Tag gruppieren. |

### `web`

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `web.bind` | `127.0.0.1` | Adresse, auf der `sshbite serve` lauscht. Eine Nicht-Loopback-Adresse braucht `--tls-cert` und `--tls-key`, oder `web.secure_cookie: true` (TLS an einem Reverse Proxy), oder `serve --insecure-bind` (protokolliert eine Warnung). Im Docker-Image (`SSHBITE_IN_CONTAINER=1`) ignoriert `serve` ohne `--bind` diesen Wert und lauscht unabhängig von `web.bind` auf `0.0.0.0`; veröffentlichen Sie den Port nur auf `127.0.0.1`. Ein ausdrückliches `--bind` folgt auch dort der obigen Regel. CLI: `--bind`. |
| `web.port` | `8722` | Port. CLI: `--port`. |
| `web.session_hours` | `8` | Lebensdauer einer UI-Login-Session in Stunden. |
| `web.secure_cookie` | `false` | `true`: Das Session-Cookie trägt `Secure` (wird nur über HTTPS gesendet). Setzen Sie es, wenn TLS an einem Reverse Proxy endet ([operations.md](operations.md#hinter-einem-reverse-proxy-tls-am-proxy)). Mit `--tls-cert` immer eingeschaltet. |
| `web.trusted_proxies` | `[]` | IPs oder CIDRs von Reverse Proxies. Nur wenn die verbindende Gegenstelle in dieser Liste steht, wird der **letzte** Eintrag von `X-Forwarded-For` als Client-Adresse für die Login-Begrenzung pro IP verwendet; sonst wird der Header ignoriert. |

<a id="environment-variables"></a>

## Umgebungsvariablen

| Variable | Bedeutung |
|---|---|
| `SSHBITE_CONFIG` | Konfigurationspfad, wenn `-c` nicht angegeben ist. |
| `SSHBITE_SUDO_PASSWORD` | sudo-Passwort für `scan`, als Alternative zu `--ask-sudo-password` (z. B. für einen Timer); nur in den Legacy-Modi, mit `privilege.mode: installed` wird es mit einer Warnung ignoriert. Wird direkt nach dem Lesen aus der Umgebung von SSHBITE entfernt; nie gespeichert oder protokolliert. **Nicht empfohlen:** Der Wert bleibt in `/proc/<pid>/environ` lesbar, solange der Prozess läuft, und `docker inspect` zeigt ihn, wenn er mit `docker run -e` oder einer Compose-Datei übergeben wurde ([operations.md](operations.md#das-sudo-passwort)). |
| `SSHBITE_IN_CONTAINER` | `1` im Docker-Image: `serve` ohne `--bind` bindet `0.0.0.0` ohne TLS, unabhängig von `web.bind`. Setzen Sie sie nirgends sonst. |
| die in `audit.key_passphrase_env` genannte | Passphrase des Audit-Schlüssels. |
