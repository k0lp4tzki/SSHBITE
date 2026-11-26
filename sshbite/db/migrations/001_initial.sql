-- SSHBITE schema v1 (spec 4.1). Times are ISO-8601 UTC; fp = 'SHA256:...'.

-- ---------------------------------------------------------------- global
CREATE TABLE scan (
    id               INTEGER PRIMARY KEY,
    label            TEXT,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    status           TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'aborted')),
    synthetic        INTEGER NOT NULL DEFAULT 0,
    tool_version     TEXT,
    collector_sha256 TEXT,
    config_sha256    TEXT,
    entry_host       TEXT,
    params           TEXT,          -- JSON
    counts           TEXT,          -- JSON
    progress         TEXT,          -- JSON {phase, depth, queued, running, done, by_status}
    pid              INTEGER
);

-- one scan at a time (spec 3.4): the row holds the PID of the running scan
CREATE TABLE scan_lock (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    pid        INTEGER NOT NULL,
    scan_id    INTEGER,
    started_at TEXT NOT NULL
);

CREATE TABLE host (
    id              INTEGER PRIMARY KEY,
    identity        TEXT NOT NULL UNIQUE,   -- hk:<fp> | addr:<ip>[:port] | name:<name>
    display_name    TEXT NOT NULL,
    synthetic       INTEGER NOT NULL DEFAULT 0,
    first_seen_scan INTEGER,
    last_seen_scan  INTEGER
);

CREATE TABLE trusted_hostkey (
    addr            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    alg             TEXT NOT NULL,
    fp              TEXT NOT NULL,
    first_seen_scan INTEGER,
    accepted_at     TEXT,
    UNIQUE (addr, port, alg)
);

CREATE TABLE key (
    fp              TEXT PRIMARY KEY,
    alg             TEXT,
    bits            INTEGER,
    strength        TEXT NOT NULL CHECK (strength IN ('good', 'ok', 'weak', 'critical', 'unknown')),
    first_seen_scan INTEGER,
    last_seen_scan  INTEGER
);

-- survives scan deletion; the only data the UI writes apart from sessions
CREATE TABLE key_label (
    fp         TEXT PRIMARY KEY,
    label      TEXT CHECK (label IS NULL OR length(label) <= 80),
    owner      TEXT CHECK (owner IS NULL OR length(owner) <= 80),
    note       TEXT CHECK (note IS NULL OR length(note) <= 2000),
    updated_at TEXT,
    updated_by TEXT
);

CREATE TABLE app_user (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    pw_hash       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT
);

CREATE TABLE session (
    token_sha256 TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);

-- ---------------------------------------------------------------- per scan
CREATE TABLE reference (
    id             INTEGER PRIMARY KEY,
    scan_id        INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    from_host_id   INTEGER REFERENCES host(id),
    username       TEXT,
    source         TEXT NOT NULL CHECK (source IN ('known_hosts', 'known_hosts_hashed', 'system_known_hosts',
                        'ssh_config', 'system_ssh_config', 'ssh_config_proxyjump', 'from_option')),
    file           TEXT,
    line_no        INTEGER,
    value          TEXT NOT NULL,
    resolved_ips   TEXT,            -- JSON
    target_host_id INTEGER REFERENCES host(id),
    outcome        TEXT NOT NULL    -- alias already excluded out_of_scope max_depth max_hosts queued unresolvable
);
CREATE INDEX reference_scan ON reference(scan_id, from_host_id);

CREATE TABLE host_scan (
    scan_id            INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id            INTEGER NOT NULL REFERENCES host(id),
    status             TEXT NOT NULL,
    privilege          TEXT,        -- root | sudo_password | unprivileged
    depth              INTEGER,
    discovered_via_ref INTEGER REFERENCES reference(id) ON DELETE SET NULL,
    seed_source        TEXT,        -- 'entry' or 'seed:<source>'
    route              TEXT,        -- JSON, e.g. ["jump","b3","c1"]
    route_attempts     TEXT,        -- JSON [{route, error}]
    connect_addr       TEXT,
    connect_port       INTEGER,
    hostname           TEXT,
    os                 TEXT,
    kernel             TEXT,
    ips                TEXT,        -- JSON
    partial_reasons    TEXT,        -- JSON
    error              TEXT,
    alias_of_host_id   INTEGER REFERENCES host(id),
    unresolved_hashed  INTEGER NOT NULL DEFAULT 0,
    duration_ms        INTEGER,
    PRIMARY KEY (scan_id, host_id)
);
CREATE INDEX host_scan_status ON host_scan(scan_id, status);

CREATE TABLE host_name (
    scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES host(id),
    kind    TEXT NOT NULL CHECK (kind IN ('name', 'ip')),
    value   TEXT NOT NULL,
    UNIQUE (scan_id, kind, value)
);
CREATE INDEX host_name_host ON host_name(scan_id, host_id);

CREATE TABLE host_key (
    scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES host(id),
    alg     TEXT NOT NULL,
    fp      TEXT NOT NULL,
    bits    INTEGER
);
CREATE INDEX host_key_host ON host_key(scan_id, host_id);
CREATE INDEX host_key_fp ON host_key(scan_id, fp);

CREATE TABLE host_group (
    scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES host(id),
    kind    TEXT NOT NULL CHECK (kind IN ('subnet', 'ansible', 'tag')),
    name    TEXT NOT NULL
);
CREATE INDEX host_group_host ON host_group(scan_id, host_id);

CREATE TABLE sshd_setting (
    scan_id INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES host(id),
    source  TEXT NOT NULL CHECK (source IN ('sshd-T', 'parsed')),
    name    TEXT NOT NULL,
    value   TEXT,
    file    TEXT,
    line    INTEGER
);
CREATE INDEX sshd_setting_host ON sshd_setting(scan_id, host_id);

CREATE TABLE account (
    scan_id     INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id     INTEGER NOT NULL REFERENCES host(id),
    username    TEXT NOT NULL,
    uid         INTEGER,
    gid         INTEGER,
    home        TEXT,
    shell       TEXT,
    login_shell INTEGER NOT NULL,
    pw_state    TEXT NOT NULL CHECK (pw_state IN ('locked', 'hash', 'none', 'unknown')),
    expiry      TEXT,
    PRIMARY KEY (scan_id, host_id, username)
);

CREATE TABLE authorized_entry (
    id             INTEGER PRIMARY KEY,
    scan_id        INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id        INTEGER NOT NULL REFERENCES host(id),
    username       TEXT NOT NULL,
    file           TEXT NOT NULL,
    line_no        INTEGER NOT NULL,
    fp             TEXT,
    alg            TEXT,
    comment        TEXT,
    options        TEXT,            -- JSON [[name, value|null], ...]
    from_patterns  TEXT,            -- JSON
    command        TEXT,
    restrict       INTEGER NOT NULL DEFAULT 0,
    cert_authority INTEGER NOT NULL DEFAULT 0,
    principals     TEXT,
    expiry_time    TEXT,
    user_exists    INTEGER NOT NULL DEFAULT 1,
    raw            TEXT
);
CREATE INDEX authorized_entry_fp ON authorized_entry(scan_id, fp);
CREATE INDEX authorized_entry_host ON authorized_entry(scan_id, host_id);

CREATE TABLE private_key (
    id        INTEGER PRIMARY KEY,
    scan_id   INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id   INTEGER NOT NULL REFERENCES host(id),
    username  TEXT NOT NULL,
    path      TEXT NOT NULL,
    fp        TEXT,
    alg       TEXT,
    bits      INTEGER,
    encrypted TEXT NOT NULL CHECK (encrypted IN ('yes', 'no', 'unknown')),
    mode      INTEGER,
    owner     TEXT,
    mtime     TEXT,
    has_pub   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX private_key_fp ON private_key(scan_id, fp);
CREATE INDEX private_key_host ON private_key(scan_id, host_id);

CREATE TABLE pub_file (
    scan_id  INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id  INTEGER NOT NULL REFERENCES host(id),
    username TEXT NOT NULL,
    path     TEXT NOT NULL,
    fp       TEXT,
    comment  TEXT
);
CREATE INDEX pub_file_fp ON pub_file(scan_id, fp);

CREATE TABLE known_host_entry (
    id             INTEGER PRIMARY KEY,
    scan_id        INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id        INTEGER NOT NULL REFERENCES host(id),
    username       TEXT NOT NULL,   -- '' = system file
    file           TEXT NOT NULL,
    line_no        INTEGER NOT NULL,
    marker         TEXT,
    hashed         INTEGER NOT NULL DEFAULT 0,
    patterns       TEXT,            -- JSON
    resolved_value TEXT,
    target_host_id INTEGER REFERENCES host(id),
    key_alg        TEXT,
    key_fp         TEXT,
    matches_actual TEXT NOT NULL DEFAULT 'unknown' CHECK (matches_actual IN ('yes', 'no', 'unknown'))
);
CREATE INDEX known_host_entry_host ON known_host_entry(scan_id, host_id);
CREATE INDEX known_host_entry_target ON known_host_entry(scan_id, target_host_id);

CREATE TABLE ssh_config_entry (
    id             INTEGER PRIMARY KEY,
    scan_id        INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id        INTEGER NOT NULL REFERENCES host(id),
    username       TEXT NOT NULL,   -- '' = system file
    file           TEXT NOT NULL,
    line_no        INTEGER NOT NULL,
    host_pattern   TEXT,
    hostname       TEXT,
    user           TEXT,
    port           INTEGER,
    identity_files TEXT,            -- JSON
    proxyjump      TEXT
);
CREATE INDEX ssh_config_entry_host ON ssh_config_entry(scan_id, host_id);

CREATE TABLE edge (
    id                  INTEGER PRIMARY KEY,
    scan_id             INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL CHECK (kind IN ('access', 'evidence')),
    src_host_id         INTEGER REFERENCES host(id),   -- NULL = unknown origin (node id unknown:<fp>)
    src_user            TEXT,
    dst_host_id         INTEGER NOT NULL REFERENCES host(id),
    dst_user            TEXT,
    fp                  TEXT,
    status              TEXT NOT NULL,  -- confirmed restricted_ok restricted_blocked unknown_origin known_hosts ssh_config
    effective           INTEGER NOT NULL DEFAULT 0,
    flags               TEXT,           -- JSON
    authorized_entry_id INTEGER REFERENCES authorized_entry(id) ON DELETE CASCADE,
    private_key_id      INTEGER REFERENCES private_key(id) ON DELETE CASCADE,
    reference_id        INTEGER REFERENCES reference(id) ON DELETE CASCADE
);
CREATE INDEX edge_dst ON edge(scan_id, dst_host_id);
CREATE INDEX edge_src ON edge(scan_id, src_host_id);
CREATE INDEX edge_fp ON edge(scan_id, fp);

CREATE TABLE finding (
    id             INTEGER PRIMARY KEY,
    scan_id        INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    rule           TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    host_id        INTEGER REFERENCES host(id),
    username       TEXT,
    fp             TEXT,
    file           TEXT,
    line_no        INTEGER,
    detail         TEXT,            -- JSON
    recommendation TEXT NOT NULL,
    ident          TEXT NOT NULL    -- sha1(rule|host identity|user|fp|file|line), stable across scans
);
CREATE INDEX finding_severity ON finding(scan_id, severity);
CREATE INDEX finding_rule ON finding(scan_id, rule);
CREATE INDEX finding_host ON finding(scan_id, host_id);

CREATE TABLE host_metric (
    scan_id         INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    host_id         INTEGER NOT NULL REFERENCES host(id),
    in_hosts        INTEGER NOT NULL DEFAULT 0,
    in_users        INTEGER NOT NULL DEFAULT 0,
    in_keys         INTEGER NOT NULL DEFAULT 0,
    in_unknown_keys INTEGER NOT NULL DEFAULT 0,
    out_hosts       INTEGER NOT NULL DEFAULT 0,
    out_users       INTEGER NOT NULL DEFAULT 0,
    out_keys        INTEGER NOT NULL DEFAULT 0,
    ev_in_hosts     INTEGER NOT NULL DEFAULT 0,
    ev_out_hosts    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, host_id)
);
