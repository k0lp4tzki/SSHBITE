<a id="cleanup-workflow-remove-a-key-and-confirm"></a>

# Bereinigungsablauf: einen Schlüssel entfernen und bestätigen

SSHBITE ändert nie einen Zielhost. Die Bereinigung erledigen Ihre Administratoren mit der Arbeitsliste von SSHBITE,
und der nächste Scan bestätigt sie. Beispiel: Entfernen Sie jeden autorisierten Schlüssel, dessen privater Teil auf
keinem gescannten Host gefunden wurde (`key_unknown_origin`) – nach einem Sicherheitsvorfall der wahrscheinlichste Ort
für einen Schlüssel, den jemand von außen zurückgelassen hat.

<a id="1-decide-what-to-remove"></a>

## 1. Festlegen, was entfernt wird

In der UI: **Findings** → *Rule* „Key of unknown origin“ (`key_unknown_origin`), *Severity* „High and
above“. Jede Zeile zeigt Host, Benutzer, `file:line`, Fingerprint und die Empfehlung. Öffnen Sie einen Schlüssel, um
zu sehen, wo überall er autorisiert ist, wo Kopien seiner `.pub` liegen und welche Kanten er erzeugt; **Show in graph**
zeigt seine Nachbarschaft.

Halten Sie Entscheidungen am Schlüssel fest: Setzen Sie ein Label, einen Verantwortlichen und eine Notiz
(z. B. *„Dienstleister 2019 – entfernen“*). Labels werden nur in der Datenbank von SSHBITE gespeichert und erscheinen
in den Exporten (`key_label`).

<a id="2-export-the-worklist"></a>

## 2. Arbeitsliste exportieren

In der UI mit **Export CSV** auf der gefilterten Findings-Liste (exportiert genau die gefilterten Zeilen), oder auf
der Kommandozeile:

```sh
sshbite export --scan latest --what findings --rule key_unknown_origin --min-severity high \
  --format csv -o worklist.csv
# Docker: nach /data schreiben und herauskopieren
docker exec sshbite sshbite export --what findings --rule key_unknown_origin --min-severity high -o /data/worklist.csv
docker cp sshbite:/data/worklist.csv .
```

Die CSV-Datei hat eine Kopfzeile und die Spalten `finding_id, scan_id, severity, rule, host, host_ips, user,
key_fp, key_alg, key_bits, key_label, file, line_no, detail, recommendation, removal_hint, status`.
`status` ist leer – eine Spalte für die Administratoren. Beispielzeile:

```text
5,1,high,key_unknown_origin,b1,172.30.2.11,root,SHA256:yIQEm8Cg…,ssh-dss,1024,,/root/.ssh/authorized_keys,2,
"{""comment"": ""legacy-dsa""}","Identify the owner, else remove",
delete line 2 of /root/.ssh/authorized_keys on b1 (SHA256:yIQEm8Cg…),
```

Zellen, die mit `=`, `+`, `-`, `@` oder einem Tabulator beginnen, erhalten ein vorangestelltes `'`, damit die Datei
gefahrlos in einer Tabellenkalkulation geöffnet werden kann. `--format json` liefert dieselben Felder. Weitere
Arbeitslisten: `--what authorized` (jede authorized_keys-Zeile), `--what keys`, `--what edges`, `--what hosts`;
`--host GLOB` begrenzt auf bestimmte Hosts.

<a id="3-remove-the-lines-on-the-hosts"></a>

## 3. Zeilen auf den Hosts entfernen

Die Administratoren entfernen die Zeilen von Hand oder mit ihrem Konfigurationsmanagement. Die Zeilennummern sind die
des Scans: Sobald eine Zeile gelöscht ist, rücken die Zeilen darunter nach oben. Identifizieren Sie jede Zeile an ihrem
**Fingerprint**, nicht nur an ihrer Nummer:

```sh
ssh-keygen -lf /root/.ssh/authorized_keys      # ein Fingerprint pro Schlüsselzeile, in Dateireihenfolge
```

Entfernen Sie mehrere Zeilen einer Datei von unten nach oben und prüfen Sie das Ergebnis mit demselben Befehl. Wird
der Schlüssel durch Konfigurationsmanagement verwaltet (Ansible, Puppet, …), entfernen Sie ihn dort, sonst kommt er
wieder.

<a id="4-scan-again"></a>

## 4. Erneut scannen

```sh
sshbite scan --label "after cleanup"
```

<a id="5-confirm-with-the-diff"></a>

## 5. Mit dem Diff bestätigen

```sh
sshbite diff 4 5              # Scan davor, Scan danach (oder die Diff-Ansicht in der UI)
```

Der Diff listet je Kategorie auf, was hinzugekommen, entfernt oder geändert ist. Entfernte Zeilen erscheinen als
entfernte Fundstellen (placements), die von ihnen erzeugten Kanten als entfernte Kanten und ihre Befunde als
entfernte Befunde:

```text
placements: 1 added, 3 removed, 0 changed
  - authorized a5:root SHA256:udc9qDdY… (/root/.ssh/authorized_keys:1)
edges: 1 added, 2 removed, 0 changed
  - access jump:ops -> a5:root SHA256:udc9qDdY… [confirmed]
findings: 2 added, 2 removed, 0 changed
  - high root_authorized_key a5:root SHA256:udc9qDdY… /root/.ssh/authorized_keys:1
```

Eine übersehene Zeile erscheint nicht als entfernt – sie ist im neuen Scan noch vorhanden. Exportieren Sie die
Arbeitsliste des neuen Scans (Schritt 2), um genau zu sehen, was übrig ist. Achten Sie auch auf die **hinzugekommenen**
Einträge: Ein neuer Schlüssel mit unbekannter Herkunft nach der Bereinigung verdient Aufmerksamkeit.

`sshbite diff A B --format json` und der JSON-Export der Diff-Ansicht liefern dasselbe Ergebnis für Tickets oder
Berichte.
