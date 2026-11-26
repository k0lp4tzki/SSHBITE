"""Static allowlist check of the target scripts (spec 3.6).

The scripts are tokenised like a POSIX shell would: comments, quotes, command
substitutions ($(...), recursively), arithmetic, pipelines, lists, compound
commands and case patterns. Every simple command's name must be on the
allowlist (or be a function defined in the same script, or a harmless shell
builtin); every redirection must be one of the three allowed forms; a few
commands get argument rules (ssh-keygen, sshd, sed, awk, ip, hostname, sort...).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ALLOWED_COMMANDS = {
    "cat", "head", "ls", "stat", "awk", "sed", "grep", "getent", "ip", "hostname", "uname", "id",
    "sort", "printf", "test", "[", "true", "ssh-keygen", "sshd",
    # ifconfig is named in spec 3.5 (META fallback) but not in the 3.6 list; it is read-only
    # with -a and allowed only in exactly that form (see ARG_RULES).
    "ifconfig",
    # spec 7.1: reads in user homes run as the account; only in the one form of _check_setpriv
    "setpriv",
}
FORBIDDEN_COMMANDS = {
    "rm", "mv", "cp", "tee", "touch", "mkdir", "mktemp", "chmod", "chown", "ln", "dd", "install",
    "truncate", "ssh", "scp", "sftp", "curl", "wget", "eval", "exec", ".", "source", "sh", "bash",
    "sudo", "su", "xargs", "env", "nohup", "nc", "socat", "python", "python3", "perl",
    # spec 7.1: runuser opens a PAM session (log entries, possibly writes); setpriv only switches ids
    "runuser",
}
# spec 7.5: the only allowed setpriv form, compared with the raw (quoted) words, and what it may run
SETPRIV_ARGS = ['--reuid="$uid"', '--regid="$gid"', "--init-groups", "--no-new-privs", "--"]
SETPRIV_WRAPPED = {"ls", "stat", "head", "test", "ssh-keygen"}
SETPRIV_FORM = "setpriv: only '--reuid=\"$uid\" --regid=\"$gid\" --init-groups --no-new-privs -- CMD' is allowed"
BUILTINS = {"set", "export", "read", "continue", "break", "return", "shift", ":"}
KEYWORDS_PREFIX = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "fi", "done", "}", "esac"}
ALLOWED_REDIRECTIONS = {"2>/dev/null", "2>&1", "</dev/null"}


@dataclass
class Violation:
    line: int
    message: str

    def __str__(self) -> str:
        return f"line {self.line}: {self.message}"


class _LintError(Exception):
    pass


@dataclass
class Tok:
    kind: str   # word | op | redir | newline
    value: str  # for words: raw text; ops: operator; redir: normalised form
    line: int
    literal: str = ""  # words: value with quotes removed (substitutions kept verbatim)


def _match_paren(s: str, i: int) -> int:
    """s[i] is just after '$('. Return index of the matching ')'."""
    depth = 1
    n = len(s)
    while i < n:
        c = s[i]
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise _LintError("unterminated single quote")
            i = j + 1
            continue
        if c == '"':
            i = _skip_dquote(s, i + 1)
            continue
        if c == "\\":
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise _LintError("unterminated $(")


def _skip_dquote(s: str, i: int) -> int:
    """s[i] is just after an opening '"'. Return index after the closing quote."""
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "`":
            raise _LintError("backquote command substitution is not allowed")
        if s.startswith("$((", i):
            j = s.find("))", i)
            if j < 0:
                raise _LintError("unterminated $((")
            i = j + 2
            continue
        if s.startswith("$(", i):
            i = _match_paren(s, i + 2) + 1
            continue
        i += 1
    raise _LintError("unterminated double quote")


class Linter:
    def __init__(self, text: str, name: str):
        self.text = text
        self.name = name
        self.violations: list[Violation] = []
        self.functions: set[str] = set()
        self.substitutions: list[tuple[str, int]] = []
        self.commands_seen: list[str] = []

    # ---- tokeniser ------------------------------------------------------------
    def tokenize(self, s: str, base_line: int) -> list[Tok]:
        toks: list[Tok] = []
        i, n = 0, len(s)
        line = base_line
        word: list[str] = []
        lit: list[str] = []
        word_start_line = line

        def flush():
            nonlocal word, lit
            if word:
                toks.append(Tok("word", "".join(word), word_start_line, "".join(lit)))
                word, lit = [], []

        while i < n:
            c = s[i]
            if c == "\n":
                flush()
                toks.append(Tok("newline", "\n", line))
                line += 1
                i += 1
                continue
            if c in " \t":
                flush()
                i += 1
                continue
            if c == "#" and not word:
                j = s.find("\n", i)
                i = n if j < 0 else j
                continue
            if not word:
                word_start_line = line
            if c == "\\":
                if i + 1 < n and s[i + 1] == "\n":
                    i += 2
                    line += 1
                    continue
                word.append(s[i:i + 2])
                lit.append(s[i + 1:i + 2])
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    raise _LintError("unterminated single quote")
                word.append(s[i:j + 1])
                lit.append(s[i + 1:j])
                line += s.count("\n", i, j)
                i = j + 1
                if not word or word == ["''"]:
                    pass
                continue
            if c == '"':
                j = _skip_dquote(s, i + 1)
                inner = s[i + 1:j - 1]
                self._collect_substitutions(inner, line)
                word.append(s[i:j])
                lit.append(inner)
                line += s.count("\n", i, j)
                i = j
                continue
            if c == "`":
                raise _LintError(f"line {line}: backquote command substitution is not allowed")
            if s.startswith("$((", i):
                j = s.find("))", i)
                if j < 0:
                    raise _LintError("unterminated $((")
                word.append(s[i:j + 2])
                lit.append(s[i:j + 2])
                i = j + 2
                continue
            if s.startswith("$(", i):
                j = _match_paren(s, i + 2)
                self.substitutions.append((s[i + 2:j], line))
                word.append(s[i:j + 1])
                lit.append(s[i:j + 1])
                line += s.count("\n", i, j)
                i = j + 1
                continue
            if c in "<>":
                # redirection: optional fd digits already in word
                fd = ""
                if word and "".join(word).isdigit():
                    fd = "".join(word)
                    word, lit = [], []
                else:
                    flush()
                j = i
                while j < n and s[j] in "<>&|":
                    j += 1
                op = s[i:j]
                # target word
                k = j
                while k < n and s[k] in " \t":
                    k += 1
                m = k
                while m < n and s[m] not in " \t\n;|&()<>":
                    m += 1
                target = s[k:m]
                toks.append(Tok("redir", fd + op + target, line))
                i = m
                continue
            if c in ";|&()":
                flush()
                if s.startswith(";;", i):
                    toks.append(Tok("op", ";;", line))
                    i += 2
                elif s.startswith("&&", i) or s.startswith("||", i):
                    toks.append(Tok("op", s[i:i + 2], line))
                    i += 2
                else:
                    toks.append(Tok("op", c, line))
                    i += 1
                continue
            word.append(c)
            lit.append(c)
            i += 1
        flush()
        return toks

    def _collect_substitutions(self, inner: str, line: int) -> None:
        i = 0
        while i < len(inner):
            if inner[i] == "\\":
                i += 2
                continue
            if inner.startswith("$((", i):
                j = inner.find("))", i)
                i = len(inner) if j < 0 else j + 2
                continue
            if inner.startswith("$(", i):
                j = _match_paren(inner, i + 2)
                self.substitutions.append((inner[i + 2:j], line))
                i = j + 1
                continue
            i += 1

    # ---- command walker -------------------------------------------------------
    def check(self, s: str, base_line: int = 1) -> None:
        try:
            toks = self.tokenize(s, base_line)
        except _LintError as exc:
            self.violations.append(Violation(base_line, str(exc)))
            return
        self._walk(toks)

    def _walk(self, toks: list[Tok]) -> None:
        i, n = 0, len(toks)
        state = "cmd"  # cmd | case_word | case_pat
        case_depth = 0
        while i < n:
            t = toks[i]
            if t.kind == "redir":
                self._check_redir(t)
                i += 1
                continue
            if t.kind in ("newline",) or (t.kind == "op" and t.value in (";", "&&", "||", "|", "&")):
                if t.kind == "op" and t.value == "&":
                    self.violations.append(Violation(t.line, "background jobs (&) are not allowed"))
                i += 1
                continue
            if t.kind == "op" and t.value == ";;":
                state = "case_pat"
                i += 1
                continue
            if state == "case_pat":
                # skip pattern list up to ')', or end the case at esac
                if t.kind == "word" and t.value == "esac":
                    case_depth -= 1
                    state = "cmd"
                    i += 1
                    continue
                while i < n and not (toks[i].kind == "op" and toks[i].value == ")"):
                    i += 1
                i += 1
                state = "cmd"
                continue
            if t.kind == "op" and t.value in "()":
                i += 1
                continue
            # a simple command starts here
            j = i
            words: list[Tok] = []
            while j < n and not (toks[j].kind in ("newline",) or (toks[j].kind == "op")):
                if toks[j].kind == "redir":
                    self._check_redir(toks[j])
                else:
                    words.append(toks[j])
                j += 1
            # function definition: name ( ) {
            if len(words) == 1 and j + 1 < n and toks[j].kind == "op" and toks[j].value == "(" \
                    and toks[j + 1].kind == "op" and toks[j + 1].value == ")":
                self.functions.add(words[0].value)
                i = j + 2
                continue
            k = 0
            # leading keywords
            while k < len(words) and words[k].value in KEYWORDS_PREFIX:
                k += 1
            if k < len(words) and words[k].value == "for":
                i = j
                continue
            if k < len(words) and words[k].value == "case":
                case_depth += 1
                state = "case_pat"
                i = j
                # skip to after 'in' (on the same token run)
                continue
            # assignments
            while k < len(words) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[k].value):
                k += 1
            # assignments followed by a keyword (e.g. "x=1; then") are not possible; done
            if k < len(words):
                self._check_command(words[k], words[k + 1:])
            i = j
        if case_depth:
            self.violations.append(Violation(toks[-1].line if toks else 0, "unterminated case"))

    def _check_redir(self, t: Tok) -> None:
        if t.value not in ALLOWED_REDIRECTIONS:
            self.violations.append(Violation(t.line, f"redirection '{t.value}' is not allowed"))

    def _check_command(self, cmd: Tok, args: list[Tok]) -> None:
        raw = cmd.literal
        name = raw.rsplit("/", 1)[-1] if raw.startswith("/") else raw
        self.commands_seen.append(name)
        if "$" in raw:
            self.violations.append(Violation(cmd.line, f"command name built from data: {cmd.value}"))
            return
        if name in FORBIDDEN_COMMANDS:
            self.violations.append(Violation(cmd.line, f"forbidden command '{name}'"))
            return
        if name in self.functions or name in BUILTINS:
            return
        if name not in ALLOWED_COMMANDS:
            self.violations.append(Violation(cmd.line, f"command '{name}' is not on the allowlist"))
            return
        if raw.startswith("/") and raw not in ("/usr/sbin/sshd",):
            self.violations.append(Violation(cmd.line, f"unexpected command path {raw}"))
        if name == "setpriv":
            self._check_setpriv(cmd, args)
            return
        a = [w.literal for w in args]
        rule = ARG_RULES.get(name)
        if rule:
            msg = rule(a)
            if msg:
                self.violations.append(Violation(cmd.line, f"{name}: {msg}"))

    def _check_setpriv(self, cmd: Tok, args: list[Tok]) -> None:
        """setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- CMD ARGS (spec 7.5)."""
        n = len(SETPRIV_ARGS)
        if [w.value for w in args[:n]] != SETPRIV_ARGS or len(args) <= n:
            self.violations.append(Violation(cmd.line, SETPRIV_FORM))
            return
        wrapped = args[n]
        if "$" in wrapped.literal:
            self.violations.append(Violation(wrapped.line, f"command name built from data: {wrapped.value}"))
            return
        name = wrapped.literal.rsplit("/", 1)[-1] if wrapped.literal.startswith("/") else wrapped.literal
        if name not in SETPRIV_WRAPPED:
            self.violations.append(Violation(wrapped.line, f"setpriv: command '{name}' may not be wrapped"))
            return
        self._check_command(wrapped, args[n + 1:])


def _ssh_keygen(a: list[str]) -> str | None:
    if len(a) == 5 and a[0] == "-y" and a[1] == "-P" and a[2] == "" and a[3] == "-f":
        return None
    if len(a) == 3 and a[0] == "-l" and a[1] == "-f":
        return None
    return f"only '-y -P \"\" -f FILE' and '-l -f FILE' are allowed, got {a}"


def _sshd(a: list[str]) -> str | None:
    return None if a == ["-T"] else f"only -T is allowed, got {a}"


def _sed(a: list[str]) -> str | None:
    if a != ["s/^/|/"]:
        return f"only the prefix script s/^/|/ is allowed, got {a}"
    return None


_AWK_BAD = [
    (re.compile(r"\bsystem\s*\("), "system()"),
    (re.compile(r"\bgetline\b"), "getline"),
    (re.compile(r"\b(close|fflush)\s*\("), "close/fflush"),
    (re.compile(r"\bprintf?\b[^;{}\n]*[>|]"), "print/printf with output redirection or pipe"),
]


def _awk(a: list[str]) -> str | None:
    for arg in a:
        for rx, what in _AWK_BAD:
            if rx.search(arg):
                return f"awk program uses {what}"
    return None


def _ip(a: list[str]) -> str | None:
    return None if a == ["-o", "addr", "show"] else f"only 'ip -o addr show' is allowed, got {a}"


def _hostname(a: list[str]) -> str | None:
    return None if a in ([], ["-I"]) else f"only 'hostname' and 'hostname -I' are allowed, got {a}"


def _ifconfig(a: list[str]) -> str | None:
    return None if a == ["-a"] else "only 'ifconfig -a' is allowed"


def _sort(a: list[str]) -> str | None:
    for x in a:
        if x.startswith("-o") or x.startswith("--output") or x.startswith("--compress-program"):
            return "sort output options are not allowed"
    return None


def _getent(a: list[str]) -> str | None:
    return None if a and a[0] in ("passwd", "hosts") else f"only 'getent passwd|hosts' is allowed, got {a}"


ARG_RULES = {
    "ssh-keygen": _ssh_keygen, "sshd": _sshd, "sed": _sed, "awk": _awk, "ip": _ip,
    "hostname": _hostname, "ifconfig": _ifconfig, "sort": _sort, "getent": _getent,
}


def lint(text: str, name: str = "script") -> list[Violation]:
    """Return all violations; an empty list means the script passes."""
    lt = Linter(text, name)
    # top level
    lt.check(text, 1)
    # command substitutions, recursively (collected while tokenising)
    seen = 0
    while seen < len(lt.substitutions):
        sub, line = lt.substitutions[seen]
        seen += 1
        lt.check(sub, line)
    # function names are only known after the full pass: re-check unknown names
    out = []
    for v in lt.violations:
        m = re.match(r"command '([^']+)' is not on the allowlist", v.message)
        if m and m.group(1) in lt.functions:
            continue
        out.append(v)
    # sanity: forbidden words must not appear as commands anywhere (belt and braces)
    if ">>" in re.sub(r"'[^']*'", "", text):
        out.append(Violation(0, "'>>' found"))
    return out


def commands_used(text: str) -> set[str]:
    lt = Linter(text, "x")
    lt.check(text, 1)
    seen = 0
    while seen < len(lt.substitutions):
        sub, line = lt.substitutions[seen]
        seen += 1
        lt.check(sub, line)
    return set(lt.commands_seen)
