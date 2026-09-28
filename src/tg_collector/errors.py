"""Conditions that must stop a whole run (not just one chat).

The Telegram adapter raises these; the export driver lets them through its
per-chat error handling and the CLI turns them into exit code 2 with the
operator-facing message. Kept Telethon-free so the driver stays testable
with fakes.
"""


class ExportHalt(RuntimeError):
    """Base: the run cannot continue safely; the cursor is preserved."""


class NotLoggedIn(ExportHalt):
    """The session is missing, expired or revoked: run ``login`` again."""


class AccountUnavailable(ExportHalt):
    """Telegram reports the account as deactivated, banned, frozen or spam-limited."""


class SessionBusy(ExportHalt):
    """Another process is using the same session file."""


class TakeoutDelayed(ExportHalt):
    """Telegram asks to confirm the data export on another device or to wait."""

    def __init__(self, seconds: int):
        super().__init__(
            f"Telegram requires confirmation of the data export: approve it on another logged-in device "
            f"or wait {seconds} seconds ({seconds // 3600} h), then re-run.")
        self.seconds = seconds


class FloodTooLong(ExportHalt):
    """A FloodWait longer than the configured ceiling: a sign to back off for the day."""

    def __init__(self, seconds: int, limit: int):
        super().__init__(
            f"Telegram asked to wait {seconds} seconds ({seconds // 3600} h), above the ceiling of {limit}; "
            f"stopping for now. Re-run later: the export resumes where it stopped.")
        self.seconds = seconds
