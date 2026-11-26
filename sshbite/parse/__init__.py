"""Parsers for collector output and OpenSSH file formats. All input is untrusted."""

MAX_LINE = 16 * 1024


def cap(line: str) -> str:
    return line if len(line) <= MAX_LINE else line[:MAX_LINE]


def ssh_pattern_match(value: str, pattern: str) -> bool:
    """OpenSSH match_pattern(): only '*' and '?' are wildcards, case-insensitive; '[' is literal."""
    import re

    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern.lower())
    return re.fullmatch(rx, value.lower(), re.S) is not None
