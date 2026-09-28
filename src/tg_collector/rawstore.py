"""On-disk store for the raw (sensitive) export.

Layout under ``root``::

    chats.json            {marked_chat_id: RawChat}
    users.json            {user_id: RawUser}
    state.json            per-chat export cursor (last message id, count, timestamp)
    inspections.json      member lists fetched while planning, with fetch times
    messages/<chat>.jsonl one RawMessage per line, append-only

The store is the seam between the Telegram adapter (writer) and the
anonymizer (reader). It hides atomic writes, append-only journaling, the
resume cursor, and de-duplication of messages that were appended twice after
a crash. Callers never touch files directly.

``write_private_json`` is the one writer for every private JSON file of the
tool (this store, the id mapping, the scrub and verify reports): mode 600,
atomic. Files the store appends to are created under the process umask,
which the CLI sets to owner-only. ``restrict_private_paths`` repairs what an
older version left readable, and touches only paths the tool itself creates.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .model import ChatDetails, RawChat, RawMessage, RawUser

log = logging.getLogger(__name__)


OWNER_ONLY_FILE = 0o600
OWNER_ONLY_DIR = 0o700

# Telethon stores the authorization key in "<base>.session" (SQLite) and lets
# SQLite put its rollback and write-ahead files next to it, with the same mode.
SESSION_SUFFIXES = (".session", ".session-journal", ".session-wal", ".session-shm")


def write_private_json(path: Path, payload: Any) -> None:
    """Write ``payload`` as JSON to a file only the owner can read (mode
    600), atomically: a reader sees the old file or the complete new one.
    The temporary file is created fresh with that mode before the first byte
    is written (a leftover from a crash, or a link planted in its place, is
    removed first), and a failed write leaves no temporary file behind.
    Every private file of the tool goes through here: the raw store, the
    mapping and both reports."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, OWNER_ONLY_FILE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), OWNER_ONLY_FILE)  # exactly 600, whatever the umask
            json.dump(payload, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def restrict_to_owner(directory: Path) -> None:
    """Remove group and other permissions from an existing directory
    (755 becomes 700), so files written before the tool created everything
    private (a raw export at mode 644) are out of reach of other local
    users. A path that is missing, unreachable or not a directory is left
    alone: new directories are created private by the process umask."""
    try:
        mode = os.stat(directory).st_mode
    except OSError as exc:  # missing, not a directory, or behind a closed parent
        log.debug("cannot inspect %s: %s", directory, exc)
        return
    if not stat.S_ISDIR(mode):
        return
    perms = mode & 0o777
    if perms & ~OWNER_ONLY_DIR:
        try:
            os.chmod(directory, perms & OWNER_ONLY_DIR)
        except OSError as exc:  # not ours to change: say so, do not stop the command
            log.warning("cannot restrict %s to its owner (mode %o): %s", directory, perms, exc)


def restrict_file_to_owner(path: Path) -> None:
    """Remove group and other permissions from an existing regular file
    (644 becomes 600), so a session key or an export written by an older
    version is out of reach of other local users.

    The mode is changed through an open descriptor, and the path is opened
    without following symlinks and without blocking, so a link or a device
    planted at the path cannot redirect the change or stall the command.
    Anything that is not a regular file is left alone."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:  # missing, a symlink, or not readable by us
        log.debug("cannot inspect %s: %s", path, exc)
        return
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return
        perms = info.st_mode & 0o777
        if not perms & ~OWNER_ONLY_FILE:
            return
        try:
            os.fchmod(fd, perms & OWNER_ONLY_FILE)
        except OSError as exc:
            log.warning("cannot restrict %s to its owner (mode %o): %s", path, perms, exc)
    finally:
        os.close(fd)


def restrict_private_paths(*directories: Path, session: Optional[Path] = None) -> None:
    """Close the tool's own directories and session files to other local users.

    Everything the tool creates is private from birth (the CLI sets a 077
    umask), but a tree or a session file left by an older version can still
    be group- or world-readable. Only paths the tool itself owns are
    touched -- never the directory that happens to hold them, which may be
    the project directory or the operator's home.

    ``session`` is Telethon's session base path, with or without the
    ``.session`` suffix; every file SQLite keeps beside it is restricted too.
    """
    for directory in directories:
        restrict_to_owner(Path(directory))
    if session is None:
        return
    base = str(session)
    if base.endswith(".session"):
        base = base[: -len(".session")]
    for suffix in SESSION_SUFFIXES:
        restrict_file_to_owner(Path(base + suffix))


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _merge_user(old: Optional[RawUser], new: RawUser) -> RawUser:
    """Prefer the newest non-empty value for every field."""
    if old is None:
        return new
    return RawUser(
        id=new.id,
        first_name=new.first_name or old.first_name,
        last_name=new.last_name or old.last_name,
        username=new.username or old.username,
        phone=new.phone or old.phone,
        is_bot=new.is_bot or old.is_bot,
        is_deleted=new.is_deleted or old.is_deleted,
        usernames=tuple(dict.fromkeys((*new.usernames, *old.usernames))),
    )


class RawStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)

    # --- paths -------------------------------------------------------------

    @property
    def _chats_path(self) -> Path:
        return self.root / "chats.json"

    @property
    def _users_path(self) -> Path:
        return self.root / "users.json"

    @property
    def _state_path(self) -> Path:
        return self.root / "state.json"

    @property
    def _inspections_path(self) -> Path:
        return self.root / "inspections.json"

    def _messages_path(self, chat_id: int) -> Path:
        name = f"m{-chat_id}" if chat_id < 0 else f"u{chat_id}"
        return self.root / "messages" / f"{name}.jsonl"

    def exists(self) -> bool:
        return self._chats_path.exists()

    # --- chats & users -------------------------------------------------------

    def chats(self) -> dict[int, RawChat]:
        raw = _read_json(self._chats_path, {})
        return {int(k): RawChat.from_json(v) for k, v in raw.items()}

    def put_chats(self, chats: Iterable[RawChat]) -> None:
        """Upsert catalogue entries. A record without a member list keeps the
        list already stored (a partial run must not erase what a full run knew)."""
        current = self.chats()
        for chat in chats:
            old = current.get(chat.id)
            if old is not None and not chat.participant_ids and old.participant_ids:
                chat = dataclasses.replace(chat, participant_ids=old.participant_ids)
            current[chat.id] = chat
        write_private_json(self._chats_path, {str(k): v.to_json() for k, v in current.items()})

    def users(self) -> dict[int, RawUser]:
        raw = _read_json(self._users_path, {})
        return {int(k): RawUser.from_json(v) for k, v in raw.items()}

    def put_users(self, users: Iterable[RawUser]) -> None:
        current = self.users()
        for user in users:
            current[user.id] = _merge_user(current.get(user.id), user)
        write_private_json(self._users_path, {str(k): v.to_json() for k, v in current.items()})

    # --- member lists fetched while planning ------------------------------------

    def inspections(self, me_id: int) -> dict[int, tuple[datetime, ChatDetails]]:
        """Member lists saved for the account ``me_id``, with the time each was
        fetched. Lists fetched by another account, or an unreadable file,
        count as none: they are only a shortcut and can always be fetched again."""
        try:
            raw = _read_json(self._inspections_path, {})
            if raw.get("me_id") != me_id:
                return {}
            return {int(k): (datetime.fromisoformat(v["inspected_at"]), ChatDetails.from_json(v["details"]))
                    for k, v in raw.get("chats", {}).items()}
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("%s is unreadable (%s); member lists will be fetched again", self._inspections_path.name, exc)
            return {}

    def put_inspections(self, me_id: int, entries: dict[int, tuple[datetime, ChatDetails]]) -> None:
        """Replace the saved member lists with ``entries``."""
        write_private_json(self._inspections_path, {
            "me_id": me_id,
            "chats": {str(k): {"inspected_at": at.isoformat(), "details": d.to_json()} for k, (at, d) in entries.items()},
        })

    # --- messages ------------------------------------------------------------

    def state(self) -> dict[str, Any]:
        return _read_json(self._state_path, {"chats": {}})

    def set_me_id(self, user_id: int) -> None:
        """Remember which account performed the export (it plays the support role)."""
        state = self.state()
        state["me_id"] = user_id
        write_private_json(self._state_path, state)

    def me_id(self) -> Optional[int]:
        value = self.state().get("me_id")
        return int(value) if value else None

    def last_message_id(self, chat_id: int) -> int:
        return int(self.state()["chats"].get(str(chat_id), {}).get("last_id", 0))

    def append_messages(self, chat_id: int, messages: Iterable[RawMessage]) -> int:
        """Append messages and advance the cursor. Returns how many were written.

        The cursor is updated only after the file is flushed, so a crash in
        between re-fetches (and re-appends) at most one batch; ``messages()``
        de-duplicates by id when reading.
        """
        path = self._messages_path(chat_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        max_id = 0
        with open(path, "ab+") as fh:
            # A crash mid-line leaves a torn record; start on a fresh line so
            # the next record is not glued onto it (the torn one is skipped on read).
            fh.seek(0, os.SEEK_END)
            if fh.tell() > 0:
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":
                    fh.write(b"\n")
        with open(path, "a", encoding="utf-8") as fh:
            for msg in messages:
                fh.write(json.dumps(msg.to_json(), ensure_ascii=False) + "\n")
                written += 1
                max_id = max(max_id, msg.id)
            fh.flush()
            os.fsync(fh.fileno())
        if written:
            state = self.state()
            entry = state["chats"].setdefault(str(chat_id), {"last_id": 0, "appended": 0})
            entry["last_id"] = max(int(entry.get("last_id", 0)), max_id)
            entry["appended"] = int(entry.get("appended", 0)) + written  # lines, not distinct messages
            entry["updated_at"] = datetime.now(timezone.utc).isoformat()
            write_private_json(self._state_path, state)
        return written

    def messages(self, chat_id: int) -> Iterator[RawMessage]:
        """Messages of one chat, de-duplicated by id and sorted ascending."""
        path = self._messages_path(chat_id)
        if not path.exists():
            return iter(())
        seen: dict[int, RawMessage] = {}
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = RawMessage.from_json(json.loads(line))
                except (ValueError, KeyError, TypeError):
                    log.warning("%s:%s: skipping unreadable record", path.name, lineno)
                    continue
                current = seen.get(msg.id)
                # The most recently edited copy wins; ties go to the later line.
                if current is None or (msg.edit_date or msg.date) >= (current.edit_date or current.date):
                    seen[msg.id] = msg
        return iter(sorted(seen.values(), key=lambda m: m.id))

    def message_chat_ids(self) -> list[int]:
        return sorted(int(k) for k in self.state()["chats"])

    def reset_chat(self, chat_id: int) -> None:
        """Forget everything exported for a chat (used by ``--full``)."""
        # Cursor first, file second: a crash in between leaves an orphan file
        # that the next export simply re-fetches over, never a stale cursor.
        state = self.state()
        state["chats"].pop(str(chat_id), None)
        write_private_json(self._state_path, state)
        path = self._messages_path(chat_id)
        if path.exists():
            path.unlink()
