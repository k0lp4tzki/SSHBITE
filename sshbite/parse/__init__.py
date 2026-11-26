"""Parsers for collector output and OpenSSH file formats. All input is untrusted."""

MAX_LINE = 16 * 1024


def cap(line: str) -> str:
    return line if len(line) <= MAX_LINE else line[:MAX_LINE]
