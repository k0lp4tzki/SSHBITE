"""Exceptions that map to CLI exit codes (spec 3.2)."""


class SshbiteError(Exception):
    exit_code = 4


class ConfigError(SshbiteError):
    exit_code = 2


class EntryError(SshbiteError):
    """Entry failure: unreachable, pin missing or mismatch, auth failed."""

    exit_code = 3


class ScanLocked(SshbiteError):
    exit_code = 5
