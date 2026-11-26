# Cleanup workflow: remove a key and confirm

SSHBITE never changes a target. Cleaning up is done by your admins, with SSHBITE's worklist, and confirmed
by the next scan. Example: remove every authorized key whose private half was found on no scanned host
(`key_unknown_origin`) – after an incident, the most likely place for a key someone outside left behind.

## 1. Decide what to remove

In the UI: **Findings** → *Rule* "Key of unknown origin" (`key_unknown_origin`), *Severity* "High and
above". Each row shows host, user, `file:line`, fingerprint and the recommendation. Open a key to see everywhere it is authorized,
where copies of its `.pub` lie and which edges it creates; **Show in graph** shows its neighbourhood.

Record decisions on the key: set a label, owner and note (e.g. *"contractor 2019 – remove"*). Labels are
stored only in SSHBITE's database and appear in the exports (`key_label`).

## 2. Export the worklist

In the UI, **Export CSV** on the filtered Findings list (it exports exactly the filtered rows), or on the
command line:

```sh
sshbite export --scan latest --what findings --rule key_unknown_origin --min-severity high \
  --format csv -o worklist.csv
# Docker: write it into /data and copy it out
docker exec sshbite sshbite export --what findings --rule key_unknown_origin --min-severity high -o /data/worklist.csv
docker cp sshbite:/data/worklist.csv .
```

The CSV has a header row and the columns `finding_id, scan_id, severity, rule, host, host_ips, user,
key_fp, key_alg, key_bits, key_label, file, line_no, detail, recommendation, removal_hint, status`.
`status` is empty – a column for the admins. Example row:

```
5,1,high,key_unknown_origin,b1,172.30.2.11,root,SHA256:yIQEm8Cg…,ssh-dss,1024,,/root/.ssh/authorized_keys,2,
"{""comment"": ""legacy-dsa""}","Identify the owner, else remove",
delete line 2 of /root/.ssh/authorized_keys on b1 (SHA256:yIQEm8Cg…),
```

Cells that start with `=`, `+`, `-`, `@` or a tab are prefixed with `'`, so the file is safe to open in a
spreadsheet. `--format json` gives the same fields. Other worklists: `--what authorized` (every
authorized_keys line), `--what keys`, `--what edges`, `--what hosts`; `--host GLOB` limits to hosts.

## 3. Remove the lines on the hosts

The admins remove the lines by hand or with their configuration management. Line numbers are those of the
scan: once a line is deleted, the lines below it move up. Identify each line by its **fingerprint**, not
only by its number:

```sh
ssh-keygen -lf /root/.ssh/authorized_keys      # one fingerprint per key line, in file order
```

Remove several lines of one file from the bottom up, and check the result with the same command. If the
key is managed by configuration management (Ansible, Puppet, …), remove it there, or it will come back.

## 4. Scan again

```sh
sshbite scan --label "after cleanup"
```

## 5. Confirm with the diff

```sh
sshbite diff 4 5              # scan before, scan after (or the Diff screen in the UI)
```

The diff lists per category what was added, removed or changed. Removed lines appear as removed
placements, the edges they created as removed edges, and their findings as removed findings:

```
placements: 1 added, 3 removed, 0 changed
  - authorized a5:root SHA256:udc9qDdY… (/root/.ssh/authorized_keys:1)
edges: 1 added, 2 removed, 0 changed
  - access jump:ops -> a5:root SHA256:udc9qDdY… [confirmed]
findings: 2 added, 2 removed, 0 changed
  - high root_authorized_key a5:root SHA256:udc9qDdY… /root/.ssh/authorized_keys:1
```

A line that was missed does not appear as removed – it is still in the new scan. Export the worklist of
the new scan (step 2) to see exactly what is left. Watch the **added** entries too: a new key with unknown
origin after the cleanup deserves attention.

`sshbite diff A B --format json` and the JSON export of the Diff screen give the same result for tickets
or reports.
