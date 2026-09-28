"""Shared record types for the raw (un-anonymized) export.

Everything the Telegram adapter emits and the raw store persists is one of the
frozen dataclasses below. They are deliberately plain: JSON-serializable via
``to_json``/``from_json`` and free of Telethon types, so every later stage
(anonymize, verify, tests) works without a network or a Telethon session.

Identifiers use Telethon's *marked* peer ids (negative for groups/channels),
which are unique across users, chats and channels.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

# Chat kinds as classified by the Telegram adapter.
KIND_PRIVATE = "private"      # 1:1 dialog with a user
KIND_BOT = "bot"              # 1:1 dialog with a bot
KIND_GROUP = "group"          # legacy basic group (types.Chat)
KIND_SUPERGROUP = "supergroup"  # megagroup channel
KIND_CHANNEL = "channel"      # broadcast channel
KIND_SELF = "self"            # Saved Messages
CHAT_KINDS = frozenset({KIND_PRIVATE, KIND_BOT, KIND_GROUP, KIND_SUPERGROUP, KIND_CHANNEL, KIND_SELF})

# Sender kinds on a message.
SENDER_USER = "user"
SENDER_CHAT = "chat"          # anonymous admin posting as the group
SENDER_CHANNEL = "channel"    # post signed by a linked channel
SENDER_NONE = "none"

# Roles assigned to participants (see ``Roles``).
ROLE_SUPPORT = "support"
ROLE_SALES = "sales"
ROLE_OTHER = "other"          # colleagues who mostly read along (observers)
ROLE_CLIENT = "client"
ROLE_BOT = "bot"
ROLE_ANONYMOUS = "anonymous"  # sender was the chat itself
ROLE_DELETED = "deleted"

STAFF_ROLES = frozenset({ROLE_SUPPORT, ROLE_SALES, ROLE_OTHER})

# Coarse sides rendered in transcripts (see ``side_of``).
SIDE_STAFF = "STAFF"
SIDE_CLIENT = "CLIENT"
SIDE_BOT = "BOT"
SIDE_UNKNOWN = "UNKNOWN"


def _dt_to_json(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dt_from_json(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class RawUser:
    id: int
    first_name: str = ""
    last_name: str = ""
    username: str = ""
    phone: str = ""
    is_bot: bool = False
    is_deleted: bool = False
    # Extra usernames (Telegram allows several via collectible usernames).
    usernames: tuple[str, ...] = ()

    @property
    def all_usernames(self) -> tuple[str, ...]:
        seen: list[str] = []
        for name in (self.username, *self.usernames):
            if name and name.lower() not in {s.lower() for s in seen}:
                seen.append(name)
        return tuple(seen)

    @property
    def display_name(self) -> str:
        return " ".join(p for p in (self.first_name, self.last_name) if p).strip()

    def to_json(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["usernames"] = list(self.usernames)
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "RawUser":
        return cls(
            id=int(d["id"]),
            first_name=d.get("first_name") or "",
            last_name=d.get("last_name") or "",
            username=d.get("username") or "",
            phone=d.get("phone") or "",
            is_bot=bool(d.get("is_bot", False)),
            is_deleted=bool(d.get("is_deleted", False)),
            usernames=tuple(d.get("usernames") or ()),
        )


@dataclass(frozen=True)
class RawChat:
    id: int
    kind: str
    title: str = ""
    username: str = ""
    is_archived: bool = False
    is_forum: bool = False
    # Set on a legacy group that was upgraded to a supergroup: the marked id of
    # the supergroup that now owns the conversation. Both peers keep history.
    migrated_to: Optional[int] = None
    # Set when the account no longer has read access (left/kicked/forbidden).
    is_accessible: bool = True
    participant_count: Optional[int] = None
    # Participant ids as returned by the members list (may be empty when the
    # member list is hidden; senders are collected from messages separately).
    participant_ids: tuple[int, ...] = ()

    def to_json(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["participant_ids"] = list(self.participant_ids)
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "RawChat":
        return cls(
            id=int(d["id"]),
            kind=d["kind"],
            title=d.get("title") or "",
            username=d.get("username") or "",
            is_archived=bool(d.get("is_archived", False)),
            is_forum=bool(d.get("is_forum", False)),
            migrated_to=d.get("migrated_to"),
            is_accessible=bool(d.get("is_accessible", True)),
            participant_count=d.get("participant_count"),
            participant_ids=tuple(int(x) for x in d.get("participant_ids") or ()),
        )


@dataclass(frozen=True)
class Entity:
    """A Telegram message entity. ``offset``/``length`` are in UTF-16 code
    units exactly as Telegram reports them (see ``scrub`` for handling)."""

    type: str  # e.g. "Mention", "MentionName", "Email", "Phone", "Url", "TextUrl", "Code"
    offset: int
    length: int
    url: Optional[str] = None
    user_id: Optional[int] = None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type, "offset": self.offset, "length": self.length}
        if self.url is not None:
            d["url"] = self.url
        if self.user_id is not None:
            d["user_id"] = self.user_id
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Entity":
        return cls(
            type=d["type"], offset=int(d["offset"]), length=int(d["length"]),
            url=d.get("url"), user_id=d.get("user_id"),
        )


@dataclass(frozen=True)
class Media:
    kind: str  # photo, document, voice, audio, video, video_note, gif, sticker, contact, location, poll, other
    ext: str = ""  # file extension without the dot, lowercase, if known
    mime: str = ""
    size: Optional[int] = None
    duration: Optional[int] = None  # seconds, for audio/voice/video
    file_name: str = ""  # raw only; exported only when the policy says so, scrubbed

    def to_json(self) -> dict[str, Any]:
        return {k: v for k, v in dataclasses.asdict(self).items() if v not in (None, "")}

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Media":
        return cls(
            kind=d["kind"], ext=d.get("ext") or "", mime=d.get("mime") or "",
            size=d.get("size"), duration=d.get("duration"), file_name=d.get("file_name") or "",
        )


# Forward origin kinds.
FWD_USER = "user"
FWD_CHAT = "chat"
FWD_CHANNEL = "channel"
FWD_HIDDEN = "hidden"      # origin chose to hide their account; only a display name is known
FWD_IMPORTED = "imported"  # history imported from another messenger


@dataclass(frozen=True)
class Forward:
    kind: str = FWD_HIDDEN
    from_id: Optional[int] = None    # marked peer id of the origin, if visible
    from_name: str = ""              # origin display name (raw only, never exported)
    date: Optional[datetime] = None

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "from_id": self.from_id, "from_name": self.from_name, "date": _dt_to_json(self.date)}

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Forward":
        return cls(kind=d.get("kind") or FWD_HIDDEN, from_id=d.get("from_id"), from_name=d.get("from_name") or "",
                   date=_dt_from_json(d.get("date")))


@dataclass(frozen=True)
class RawMessage:
    chat_id: int
    id: int
    date: datetime
    sender_id: Optional[int] = None
    sender_kind: str = SENDER_NONE
    text: str = ""  # raw text (no markdown), as Telegram stores it
    entities: tuple[Entity, ...] = ()
    reply_to_id: Optional[int] = None
    topic_id: Optional[int] = None  # forum topic root id (General = 1) when the chat is a forum
    forward: Optional[Forward] = None
    media: Optional[Media] = None
    action: Optional[str] = None  # service message class name, e.g. "MessageActionChatAddUser"
    edit_date: Optional[datetime] = None
    grouped_id: Optional[int] = None  # album grouping
    via_bot_id: Optional[int] = None
    post_author: str = ""

    @property
    def is_service(self) -> bool:
        return self.action is not None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "chat_id": self.chat_id,
            "id": self.id,
            "date": _dt_to_json(self.date),
            "sender_id": self.sender_id,
            "sender_kind": self.sender_kind,
            "text": self.text,
        }
        if self.entities:
            d["entities"] = [e.to_json() for e in self.entities]
        if self.reply_to_id is not None:
            d["reply_to_id"] = self.reply_to_id
        if self.topic_id is not None:
            d["topic_id"] = self.topic_id
        if self.forward is not None:
            d["forward"] = self.forward.to_json()
        if self.media is not None:
            d["media"] = self.media.to_json()
        if self.action is not None:
            d["action"] = self.action
        if self.edit_date is not None:
            d["edit_date"] = _dt_to_json(self.edit_date)
        if self.grouped_id is not None:
            d["grouped_id"] = self.grouped_id
        if self.via_bot_id is not None:
            d["via_bot_id"] = self.via_bot_id
        if self.post_author:
            d["post_author"] = self.post_author
        return d

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "RawMessage":
        return cls(
            chat_id=int(d["chat_id"]),
            id=int(d["id"]),
            date=_dt_from_json(d["date"]),
            sender_id=d.get("sender_id"),
            sender_kind=d.get("sender_kind") or SENDER_NONE,
            text=d.get("text") or "",
            entities=tuple(Entity.from_json(e) for e in d.get("entities") or ()),
            reply_to_id=d.get("reply_to_id"),
            topic_id=d.get("topic_id"),
            forward=Forward.from_json(d["forward"]) if d.get("forward") else None,
            media=Media.from_json(d["media"]) if d.get("media") else None,
            action=d.get("action"),
            edit_date=_dt_from_json(d.get("edit_date")),
            grouped_id=d.get("grouped_id"),
            via_bot_id=d.get("via_bot_id"),
            post_author=d.get("post_author") or "",
        )


@dataclass(frozen=True)
class Roles:
    """Decides which role a participant plays.

    ``me_id`` is the logged-in support account. Staff lists come from config
    and may be given as user ids or usernames (with or without ``@``).
    Everyone else who is not a bot is a client.
    """

    me_id: Optional[int] = None
    support: frozenset[str | int] = frozenset()
    sales: frozenset[str | int] = frozenset()
    other: frozenset[str | int] = frozenset()

    @staticmethod
    def _norm(item: str | int) -> str | int:
        if isinstance(item, int):
            return item
        s = str(item).strip().lstrip("@").lower()
        return int(s) if s.lstrip("-").isdigit() else s

    @classmethod
    def build(cls, me_id: Optional[int], support: Iterable[str | int] = (), sales: Iterable[str | int] = (),
              other: Iterable[str | int] = ()) -> "Roles":
        return cls(
            me_id=me_id,
            support=frozenset(cls._norm(x) for x in support),
            sales=frozenset(cls._norm(x) for x in sales),
            other=frozenset(cls._norm(x) for x in other),
        )

    def _matches(self, user: RawUser, group: frozenset[str | int]) -> bool:
        if user.id in group:
            return True
        return any(u.lower() in group for u in user.all_usernames)

    def of(self, user: RawUser) -> str:
        if user.is_bot:
            return ROLE_BOT
        # Staff configured by id stays staff even after the account is deleted;
        # usernames of deleted accounts are gone, so only id matches apply there.
        if user.id == self.me_id or self._matches(user, self.support):
            return ROLE_SUPPORT
        if self._matches(user, self.sales):
            return ROLE_SALES
        if self._matches(user, self.other):
            return ROLE_OTHER
        if user.is_deleted:
            return ROLE_DELETED
        return ROLE_CLIENT

    def is_staff(self, user: RawUser) -> bool:
        return self.of(user) in STAFF_ROLES

    def configured(self) -> frozenset[str | int]:
        return self.support | self.sales | self.other

    def matched_entries(self, users: Iterable[RawUser]) -> frozenset[str | int]:
        """Which configured staff entries matched at least one known user."""
        hit: set[str | int] = set()
        for user in users:
            names = {u.lower() for u in user.all_usernames}
            for entry in self.configured():
                if entry == user.id or (isinstance(entry, str) and entry in names):
                    hit.add(entry)
        return frozenset(hit)


def side_of(role: str) -> str:
    """Coarse side for the LLM: who speaks for the client and who for the vendor."""
    if role in STAFF_ROLES or role == ROLE_ANONYMOUS:
        return SIDE_STAFF
    if role == ROLE_CLIENT:
        return SIDE_CLIENT
    if role == ROLE_BOT:
        return SIDE_BOT
    return SIDE_UNKNOWN
