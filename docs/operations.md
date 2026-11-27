<a id="operations-services-nightly-scans-backup-update"></a>

# Betrieb: Dienste, nächtliche Scans, Sicherung, Aktualisierung

Inhalt: [Oberfläche als Dienst](#die-oberfläche-als-systemd-dienst) ·
[hinter einem Reverse Proxy](#hinter-einem-reverse-proxy-tls-am-proxy) ·
[nächtlicher Scan](#nächtlicher-scan-mit-einem-systemd-timer) · [das sudo-Passwort](#das-sudo-passwort) ·
[Docker](#docker) · [UI-Anmeldungen](#ui-anmeldungen) · [Sicherung](#sicherung-und-wiederherstellung) ·
[Aktualisierung](#aktualisierung) · [Deinstallation](#deinstallation) · [Aufbewahrung](#aufbewahrung)

<a id="the-ui-as-a-systemd-service"></a>

## Die Oberfläche als systemd-Dienst

[`systemd/sshbite-serve.service`](systemd/sshbite-serve.service) startet `sshbite serve` als das Konto
`sshbite-app` aus [install.md](install.md#pfad-c-nativ-mit-pip-und-systemd), mit der Datenbank in
`/var/lib/sshbite`:

```sh
cp docs/systemd/sshbite-serve.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sshbite-serve.service
journalctl -u sshbite-serve.service        # "SSHBITE UI on http://127.0.0.1:8722/ ..."
```

`serve` hört auf `web.bind`:`web.port` (127.0.0.1:8722). Eine Adresse außerhalb von Loopback lehnt es ab,
außer es wurde mit `--tls-cert FILE --tls-key FILE` gestartet, oder TLS endet an einem Reverse Proxy und
`web.secure_cookie: true` ist gesetzt (nächster Abschnitt). `--insecure-bind` hebt die Ablehnung auf und
schreibt eine Warnung ins Log – Anmeldepasswort und Sitzungs-Cookie gehen dann im Klartext über das Netz;
verwenden Sie es nur in einem Test. Die Unit ist gehärtet (`ProtectSystem=strict`, nur `/var/lib/sshbite`
beschreibbar); passen Sie `ReadWritePaths` an, wenn Ihre Datenbank woanders liegt.

Im Docker-Image (`SSHBITE_IN_CONTAINER=1`) hört `serve` ohne `--bind` im Container auf 0.0.0.0, denn die
Compose-Datei veröffentlicht den Port nur auf `127.0.0.1` des Hosts. Ein ausdrückliches `--bind` auf eine
Adresse außerhalb von Loopback bekommt diese Ausnahme nicht: Dann gilt dieselbe Regel wie oben.

<a id="behind-a-reverse-proxy-tls-at-the-proxy"></a>

## Hinter einem Reverse Proxy (TLS am Proxy)

Für den Zugriff von anderen Rechnern stellen Sie einen Reverse Proxy mit TLS vor SSHBITE und lassen
SSHBITE selbst auf Loopback (oder in einem privaten Container-Netz). Zwei Einstellungen passen SSHBITE an
diesen Aufbau an:

```yaml
web:
  bind: 127.0.0.1           # hierher verbindet sich der Proxy; in Docker: 127.0.0.1:8722:8722 veröffentlichen
  port: 8722
  secure_cookie: true       # das Sitzungs-Cookie bekommt "Secure": Browser senden es nur über HTTPS
  trusted_proxies: [127.0.0.1]   # die Adresse des Proxys, wie SSHBITE sie sieht (IPs oder CIDRs)
```

- **`secure_cookie`** – das Cookie trägt `Secure`, der Browser sendet es also nie über einfaches HTTP. Mit
  `--tls-cert` ist es immer an. Mit `secure_cookie` und ohne Proxy kann sich ein Browser über `http://`
  nicht anmelden (außer auf `localhost`) – das ist gewollt.
- **`trusted_proxies`** – nur wenn die TCP-Gegenstelle in dieser Liste steht, nimmt SSHBITE die
  Client-Adresse für die Anmeldegrenze pro IP (20 Fehlversuche in 15 Minuten → HTTP 429) aus
  `X-Forwarded-For`, und zwar nur den **letzten** Eintrag: die Adresse, die der Proxy selbst gesehen hat.
  Frühere Einträge stammen vom Client und werden ignoriert. Von jeder anderen Gegenstelle wird der Header
  ignoriert. Ohne diese Einstellung teilen sich alle Benutzer hinter dem Proxy eine Adresse, und 20
  Fehlversuche irgendeines Benutzers sperren alle für 15 Minuten aus.
- In Docker erreicht der Proxy SSHBITE meist über ein Container-Netz: Tragen Sie die Adresse des
  Proxy-Containers (oder das CIDR des Netzes, wenn sonst nichts Unvertrautes darin hängt) in
  `trusted_proxies` ein, starten Sie den Container mit `sshbite serve --bind 0.0.0.0` und lassen Sie
  `secure_cookie: true` gesetzt – ohne das lehnt SSHBITE diesen Bind ab.

Beispiel für nginx auf demselben Host (die Zertifikatspfade sind Ihre):

```nginx
server {
    listen 443 ssl;
    server_name sshbite.corp.example;
    ssl_certificate     /etc/ssl/sshbite/fullchain.pem;
    ssl_certificate_key /etc/ssl/sshbite/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 64k;                    # größere /api-Anfragen beantwortet SSHBITE ohnehin mit 413

    location / {
        proxy_pass http://127.0.0.1:8722;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # ein Sprung: genau die Adresse des Clients
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

`proxy_set_header X-Forwarded-For $remote_addr` ersetzt, was der Client geschickt hat; mit
`$proxy_add_x_forwarded_for` bleibt der eigene Wert des Clients vorne stehen, den SSHBITE ignoriert, weil
es nur den letzten Eintrag liest. Prüfen Sie es: Melden Sie sich unter `https://sshbite.corp.example/` an;
die Entwicklerwerkzeuge des Browsers zeigen das Cookie `sshbite_session` mit *Secure*. 20 falsche
Passwörter von einem Rechner ergeben dort HTTP 429, während ein zweiter Rechner sich weiter anmelden kann.

<a id="nightly-scan-with-a-systemd-timer"></a>

## Nächtlicher Scan mit einem systemd-Timer

[`systemd/sshbite-scan.service`](systemd/sshbite-scan.service) führt einen Scan aus;
[`systemd/sshbite-scan.timer`](systemd/sshbite-scan.timer) startet ihn jede Nacht um 02:30 (mit bis zu
15 Minuten zufälliger Verzögerung; ein verpasster Lauf wird nach dem Booten nachgeholt):

```sh
cp docs/systemd/sshbite-scan.service docs/systemd/sshbite-scan.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sshbite-scan.timer
systemctl list-timers sshbite-scan.timer
systemctl start sshbite-scan.service        # jetzt einmal ausführen
journalctl -u sshbite-scan.service          # Konsolenausgabe und Zusammenfassung des Scans
```

- Der Dienst schlägt fehl, wenn der Scan nicht mit 0 endet: 2 (Konfiguration), 3 (Einstiegshost nicht
  erreichbar oder Host-Key weicht ab – untersuchen Sie das vor allem anderen), 4 (intern), 5 (ein Scan lief
  noch). Hosts mit `partial` oder `unreachable` lassen ihn nicht fehlschlagen.
- Die Oberfläche darf gleichzeitig laufen; sie zeigt den laufenden Scan und übernimmt das Ergebnis.
- Im empfohlenen Modus `privilege.mode: installed` braucht der Scan kein Passwort. Nur im Legacy-Modus mit
  sudo-Passwort: Schreiben Sie `SSHBITE_SUDO_PASSWORD=…` in eine Datei, die root gehört und den Modus 0600
  hat, und aktivieren Sie die Zeile `EnvironmentFile=` der Unit. SSHBITE entfernt die Variable aus seiner
  Umgebung, sobald es sie gelesen hat, und speichert sie nie; die Datei auf der Platte müssen Sie schützen.
  Die Variable wird unterstützt, ist aber **nicht empfohlen**: siehe [das sudo-Passwort](#das-sudo-passwort).

<a id="the-sudo-password"></a>

## Das sudo-Passwort

Dieser Abschnitt gilt nur für den [Legacy-Modus](install.md#legacy-modus-sudo-binsh--s-entspricht-vollem-root-zugriff).
Im Modus `installed` sendet SSHBITE nie ein sudo-Passwort: `--ask-sudo-password` wird mit Exit-Code 2
abgelehnt, ein gesetztes `SSHBITE_SUDO_PASSWORD` nur mit einer Warnung quittiert.

Will sudo auf Ihren Hosts ein Passwort, kann SSHBITE eines senden (`--ask-sudo-password`). Lesen Sie vorher:

- **Ein kompromittierter Host kann es abgreifen.** SSHBITE ruft sudo mit absolutem Pfad auf
  (`/usr/bin/sudo`, oder `/bin/sudo`, wo es das erste nicht gibt) und nie über den `PATH` des Audit-Kontos.
  Ein Angreifer mit root auf einem Zielhost – die Lage nach einem Vorfall – beherrscht aber sudo, Shell und
  sshd dieses Hosts und kann eine sudo-Passwortabfrage vortäuschen. SSHBITE gibt ihm dann das Passwort.
- **Nehmen Sie deshalb ein Passwort, das für nichts anderes taugt:** ein Passwort nur für das Audit-Konto
  `sshbite`, gleich auf allen Hosts oder je Gruppe, und **wechseln Sie es nach dem Scan**. Nie ein
  persönliches oder ein Admin-Passwort. `NOPASSWD`-sudo für das Audit-Konto
  ([install.md](install.md#legacy-modus-sudo-binsh--s-entspricht-vollem-root-zugriff)) erspart die Frage
  ganz – und der [installierte Collector](install.md#zielhosts-vorbereiten-installierter-collector) erst recht.
- **Begrenzen Sie, wohin es geht:** `privilege.password_scope` (CIDRs oder Hostnamen-Muster) nennt die
  Hosts, die das Passwort bekommen dürfen; leer (Standard) heißt jeder Host. Ein Host außerhalb, der nach
  einem Passwort fragt, wird ohne Rechte gescannt und als `partial` markiert, mit *sudo password not sent
  (outside privilege.password_scope)*.
- **Wie Sie es eingeben:** `--ask-sudo-password` fragt in einem Terminal und lehnt ab, wenn stdin keines ist
  (das Passwort könnte sonst angezeigt oder protokolliert werden). In Docker heißt das `docker exec -it`,
  nicht nur `-i`. `SSHBITE_SUDO_PASSWORD` wird für unbeaufsichtigte Läufe unterstützt, ist aber **nicht
  empfohlen**: Der Wert bleibt während der Laufzeit des Prozesses in `/proc/<pid>/environ` lesbar, und wenn
  Sie ihn mit `docker run -e` oder in einer Compose-Datei übergeben, zeigt ihn `docker inspect`. Wenn Sie
  ihn verwenden müssen, übergeben Sie ihn an `docker exec -e` aus einer `EnvironmentFile`, die nur root
  lesen kann, wie es die nächtliche Unit tut – nie an den Container.

## Docker

Der Container führt `sshbite serve` aus (siehe [install.md](install.md#pfad-b-docker) und
[compose.example.yaml](compose.example.yaml)); `restart: unless-stopped` startet ihn nach einem Neustart
wieder. Alles andere läuft mit `docker exec` darin:

```sh
docker exec sshbite sshbite scan
docker exec sshbite sshbite scans list
docker logs sshbite
```

Nur im Legacy-Modus mit sudo-Passwort lautet die Scan-Zeile
`docker exec -it sshbite sshbite scan --ask-sudo-password`.

Für den nächtlichen Scan nehmen Sie [`systemd/sshbite-scan-docker.service`](systemd/sshbite-scan-docker.service)
(installiert als `sshbite-scan.service`) mit demselben Timer. Er führt
`docker exec sshbite sshbite scan --label nightly` aus. Im Legacy-Modus mit sudo-Passwort liest er es aus
einer `EnvironmentFile` außerhalb von `/etc/sshbite` und übergibt es mit
`docker exec -e SSHBITE_SUDO_PASSWORD`, sodass das Passwort nie auf einer Befehlszeile steht (zu den
Risiken siehe [das sudo-Passwort](#das-sudo-passwort)). Im Modus installed ist die Variable nicht gesetzt
und wird nicht gebraucht.

<a id="ui-logins"></a>

## UI-Anmeldungen

```sh
sshbite user add NAME        # Passwort zweimal abgefragt, mindestens 12 Zeichen (argon2id)
sshbite user passwd NAME     # neues Passwort; beendet die Sitzungen des Benutzers und hebt eine Sperre auf
sshbite user remove NAME
printf '%s\n' "$PW" | sshbite user add NAME --password-stdin   # Skripte: eine Zeile von stdin, keine Abfrage
```

Die Abfragen brauchen ein Terminal: Ohne eines (`docker exec -i`, eine Pipe) lehnen sie ab, weil das
Passwort angezeigt werden könnte. Verwenden Sie `docker exec -it sshbite sshbite user add NAME`, oder
`--password-stdin` in Skripten.

Fünf Fehlversuche innerhalb von 15 Minuten sperren diesen Benutzer für 15 Minuten; 20 Fehlversuche von
einer Adresse innerhalb von 15 Minuten werden mit HTTP 429 beantwortet. Sitzungen gelten
`web.session_hours` (8) Stunden.

<a id="backup-and-restore"></a>

## Sicherung und Wiederherstellung

Die Datenbank enthält jeden Scan, die vertrauten Host-Keys (TOFU), Schlüssel-Beschriftungen und die
UI-Anmeldungen. Sichern Sie sie mit der Online-Sicherung von SQLite; das ist auch während laufender Scans
und Oberfläche sicher:

```sh
sshbite db backup /var/backups/sshbite/sshbite-$(date +%F).db      # überschreibt nichts; Dateimodus 0600
```

Bei Docker schreiben Sie die Sicherung in das Daten-Volume und kopieren sie heraus:

```sh
docker exec sshbite sshbite db backup /data/backup-$(date +%F).db
docker cp sshbite:/data/backup-$(date +%F).db /var/backups/sshbite/
docker exec sshbite rm /data/backup-$(date +%F).db
```

Die Datenbank ist vertraulich: Sie zeigt, wer welches System mit welchem Schlüssel erreichen kann. Schützen
Sie Sicherungen so gut wie die Datenbank selbst. Sichern Sie `/etc/sshbite` (Konfiguration,
Audit-Schlüssel) getrennt, nach Ihren Regeln für Geheimnisse.

**Wiederherstellen:** Halten Sie die Oberfläche an und stellen Sie sicher, dass kein Scan läuft; ersetzen Sie
dann die Datenbankdatei und entfernen Sie ihre Dateien `-wal`/`-shm`:

```sh
systemctl stop sshbite-serve.service sshbite-scan.timer
cp /var/backups/sshbite/sshbite-2026-11-20.db /var/lib/sshbite/sshbite.db
rm -f /var/lib/sshbite/sshbite.db-wal /var/lib/sshbite/sshbite.db-shm
chown sshbite-app: /var/lib/sshbite/sshbite.db && chmod 600 /var/lib/sshbite/sshbite.db
systemctl start sshbite-serve.service sshbite-scan.timer
```

<a id="update"></a>

## Aktualisierung

Die Schritte mit allen Befehlen und Prüfungen stehen in [install.md](install.md#aktualisierung). Kurz:

1. Lesen Sie die Versionshinweise und sichern Sie die Datenbank (oben).
2. Installieren Sie die neue Version:
   - pip: im neuen Checkout
     `/opt/sshbite/bin/pip install --require-hashes -r requirements-runtime.lock && /opt/sshbite/bin/pip install --no-deps .`,
     dann `systemctl restart sshbite-serve.service`.
   - Docker: `docker build -t sshbite:<NEW-VERSION> .`, den neuen Tag in der Zeile `image:` von
     `docs/compose.example.yaml` (oder Ihrer Kopie) eintragen, dann
     `docker compose -f docs/compose.example.yaml up -d`.
3. Exportieren Sie den Collector neu, prüfen Sie die Prüfsummen und installieren Sie den geänderten
   `sshbite-collect` auf jedem Zielhost. Bis dahin erscheint jeder Host im Modus installed als
   `collector_error` mit `installed collector version differs from this SSHBITE …`.
4. Das erste `sshbite serve` oder `sshbite scan` der neuen Version stellt die Datenbank automatisch um.
   Bevor es etwas ändert, schreibt es eine Kopie neben die Datenbank, benannt nach der Version, die umstellt,
   z. B. `/var/lib/sshbite/sshbite.db.pre-0.2.0` (`/data/sshbite.db.pre-0.2.0` in Docker). Ohne anstehende
   Umstellung wird nichts geschrieben.
5. Prüfen Sie mit `config validate --connect` und scannen Sie.

Zurück zur alten Version: Installieren Sie die alte Version und stellen Sie die Datei `.pre-<version>` her,
wie unter *Wiederherstellen* beschrieben. Löschen Sie die `.pre-`-Dateien, sobald die neue Version
funktioniert – sie enthalten dieselben vertraulichen Daten.

## Deinstallation

Scanner-Rechner und Zielhosts: siehe [install.md](install.md#deinstallation).

<a id="retention"></a>

## Aufbewahrung

Jeder Scan bleibt in der Datenbank, bis Sie ihn löschen. `sshbite scans delete ID` entfernt einen Scan und
die Hosts und Schlüssel, auf die kein anderer Scan mehr verweist; Beschriftungen noch benutzter Schlüssel
bleiben erhalten. Behalten Sie mindestens die Scans, die Sie noch mit `sshbite diff` vergleichen wollen.
