"""The anonymized dataset and its on-disk form.

``Dataset`` is the in-memory result of anonymization: virtual users, logical
chats and messages that carry no raw identifiers. ``write_dataset`` renders it
for LLM consumption::

    dataset/
      README.md               format description for whoever feeds the LLM
      manifest.json           counts, date range, policy snapshot, notes
      users.json              {"U04217": {"name": ..., "role": ..., "side": ...}}
      chats.json              {"C01735": {"participants": [...], "episodes": ..., ...}}
      messages.jsonl          one message per line (programmatic use)
      episodes.jsonl          one line per episode: chat, span, sides, size
      transcripts/C01735.md   readable per-chat transcript (split into parts
                              when larger than ``max_chars``)
      chunks/chunk-001.md     transcript parts packed to ``max_chars`` so small
                              chats do not become hundreds of tiny files

The unit the downstream LLM should reason about is the *episode*: a run of
messages without a long inactivity gap (and, in forum chats, within one
topic), which usually holds one request and its resolution. Episodes are
numbered per chat, carried in JSONL and rendered as sections in transcripts.

The directory is written atomically: everything goes to a temporary sibling
and is swapped in only when complete.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path, PurePath
from typing import Any, Iterable, Optional
from zoneinfo import ZoneInfo

from .config import Output
from .model import ROLE_ANONYMOUS, STAFF_ROLES

FORMAT_VERSION = 2


@dataclass(frozen=True)
class AnonUser:
    vid: str
    name: str
    role: str
    side: str


@dataclass
class AnonChat:
    vid: str
    title: str
    kind: str
    is_forum: bool = False
    participants: list[str] = field(default_factory=list)
    message_count: int = 0
    first_date: Optional[datetime] = None
    last_date: Optional[datetime] = None
    by_side: dict[str, int] = field(default_factory=dict)
    episodes: int = 0


@dataclass(frozen=True)
class AnonMessage:
    chat: str
    seq: int
    date: datetime  # aware, UTC
    sender: Optional[str]
    role: str
    side: str
    text: str
    episode: int = 0
    reply_to: Optional[int] = None
    topic: Optional[int] = None
    media: Optional[dict[str, Any]] = None   # kind, ext?, size?, duration?, name?
    edited: bool = False
    forwarded: Optional[str] = None          # U#####, C#####, external_*, hidden, imported
    action: Optional[str] = None             # kept service messages only
    code: bool = False                       # mostly a code/log block

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "chat": self.chat,
            "episode": self.episode,
            "seq": self.seq,
            "date": self.date.isoformat().replace("+00:00", "Z"),
            "sender": self.sender,
            "role": self.role,
            "side": self.side,
            "text": self.text,
        }
        for key in ("reply_to", "topic", "media", "forwarded", "action"):
            value = getattr(self, key)
            if value is not None:
                d[key] = value
        for flag in ("edited", "code"):
            if getattr(self, flag):
                d[flag] = True
        return d


@dataclass
class Dataset:
    users: dict[str, AnonUser] = field(default_factory=dict)
    chats: dict[str, AnonChat] = field(default_factory=dict)
    messages: list[AnonMessage] = field(default_factory=list)  # grouped by chat, ordered by seq
    notes: dict[str, Any] = field(default_factory=dict)        # shareable (goes into manifest)
    private: dict[str, Any] = field(default_factory=dict)      # operator-only report, never written here

    def messages_of(self, chat_vid: str) -> list[AnonMessage]:
        return [m for m in self.messages if m.chat == chat_vid]

    def texts(self) -> Iterable[tuple[str, str]]:
        """Every free-text field that ends up in the output, with a location
        label. Attachment fields count: both the name and the extension are
        cut out of a file name and can hold whatever the sender typed.

        This is the free-text half of the split ``COMPOSED_JSON_KEYS`` makes
        on the written files, and the only thing the anonymizer's self-check
        sees: a new field that carries what somebody typed has to be yielded
        here, and a new composed one listed there."""
        for u in self.users.values():
            yield f"users:{u.vid}", u.name
        for c in self.chats.values():
            yield f"chats:{c.vid}", c.title
        for m in self.messages:
            yield f"{m.chat}#{m.seq}", m.text
            media = m.media or {}
            for key in ("name", "ext"):
                if media.get(key):
                    yield f"{m.chat}#{m.seq}:media.{key}", media[key]

    def assign_episodes(self, gap_hours: float) -> None:
        """Number episodes per chat: a new one starts after an inactivity gap
        or when the forum topic changes. Also refreshes per-chat counters."""
        gap = timedelta(hours=gap_hours)
        out: list[AnonMessage] = []
        for chat in self.chats.values():
            msgs = self.messages_of(chat.vid)
            episode = 0
            prev: Optional[AnonMessage] = None
            by_side: dict[str, int] = {}
            for m in msgs:
                if prev is None or m.topic != prev.topic or m.date - prev.date > gap:
                    episode += 1
                out.append(dataclasses.replace(m, episode=episode))
                by_side[m.side] = by_side.get(m.side, 0) + 1
                prev = m
            chat.episodes = episode
            chat.by_side = by_side
            chat.message_count = len(msgs)
            if msgs:
                chat.first_date, chat.last_date = msgs[0].date, msgs[-1].date
        self.messages = out


# --- rendering ---------------------------------------------------------------------

@dataclass(frozen=True)
class WriteReport:
    files: int
    transcript_parts: int
    chunks: int
    messages: int


def _speaker(ds: Dataset, msg: AnonMessage) -> str:
    if msg.sender is None:
        return "SYSTEM"
    user = ds.users.get(msg.sender)
    if user is None:
        return f"{msg.side} {msg.sender}"
    if user.role == ROLE_ANONYMOUS:
        return f"{user.side} {user.vid} (anonymous admin)"
    label = f"{user.side} {user.vid}"
    if user.name:
        label += f" {user.name}"
    if user.role in STAFF_ROLES or user.role not in ("client",):
        label += f" ({user.role})"
    return label


def media_label(media: dict[str, Any]) -> str:
    parts = [media["kind"] + (f":{media['ext']}" if media.get("ext") else "")]
    if media.get("duration"):
        d = int(media["duration"])
        parts.append(f"{d // 60}:{d % 60:02d}")
    if media.get("size"):
        size = int(media["size"])
        parts.append(f"{size / 1_000_000:.1f} MB" if size >= 1_000_000 else f"{max(1, size // 1000)} KB")
    if media.get("name"):
        parts.append(f'"{media["name"]}"')
    return "[" + " ".join(parts) + "]"


def _word_end(text: str, pos: int) -> int:
    """Where a cut may end without falling inside a word: ``pos`` itself when
    it already sits on whitespace or past the end, else the start of the word
    it lands in. Truncating inside a placeholder or a number would leave text
    that reads like the value it replaced (``<url:shop.example.com>`` cut to
    ``shop.example.co``). A word filling the whole window is cut hard."""
    if pos >= len(text) or text[pos].isspace():
        return pos
    cut = pos
    while cut > 0 and not text[cut - 1].isspace():
        cut -= 1
    return cut if cut > 0 else pos


def _word_start(text: str, pos: int) -> int:
    """The mirror image of ``_word_end``: where a tail may start without
    beginning inside a word."""
    if pos <= 0 or text[pos - 1].isspace():
        return pos
    cut = pos
    while cut < len(text) and not text[cut].isspace():
        cut += 1
    return cut if cut < len(text) else pos


def _shorten(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    head = text[:_word_end(text, limit * 3 // 4)].rstrip()
    tail = text[_word_start(text, len(text) - limit // 4):].lstrip()
    return f"{head}\n[... {len(text) - len(head) - len(tail)} chars omitted ...]\n{tail}"


# What a line break of the quoted message becomes in a one-line quote. A
# space would join the two lines into values neither the scrubber nor
# ``messages.jsonl`` ever saw ("карта 4000 0000" + "0000 0002").
QUOTE_LINE_BREAK = " ⏎ "


def _quote(ds_index: dict[int, AnonMessage], seq: int) -> str:
    target = ds_index.get(seq)
    if target is None:
        return f"↳#{seq}"
    snippet = QUOTE_LINE_BREAK.join(" ".join(line.split()) for line in target.text.splitlines() if line.strip())
    if len(snippet) > 60:
        snippet = snippet[:_word_end(snippet, 57)].rstrip() + "..."
    who = target.sender or "SYSTEM"
    return f'↳#{seq} {who} "{snippet}"' if snippet else f"↳#{seq} {who}"


class _TranscriptRenderer:
    """Turns one chat's messages into markdown blocks (one block per episode)."""

    def __init__(self, ds: Dataset, chat: AnonChat, output: Output):
        self.ds, self.chat, self.output = ds, chat, output
        self.tz = ZoneInfo(output.timezone)
        self.msgs = ds.messages_of(chat.vid)
        self.index = {m.seq: m for m in self.msgs}

    def header(self, part: Optional[tuple[int, int]] = None) -> str:
        chat, ds = self.chat, self.ds
        lines = [f"# {chat.vid}" + (f" (part {part[0]} of {part[1]})" if part else "")]
        if chat.title and chat.title != chat.vid:
            lines.append(f"Title: {chat.title}")
        if chat.is_forum:
            lines.append("Forum chat: episodes never cross topics; topic ids are shown in episode headers.")
        parts = []
        for vid in chat.participants:
            user = ds.users.get(vid)
            if user:
                parts.append(f"{vid} {user.side}" + (f" {user.name}" if user.name else "") + f" ({user.role})")
        lines.append("Participants: " + (", ".join(parts) if parts else "unknown"))
        if chat.first_date and chat.last_date:
            sides = ", ".join(f"{k}: {v}" for k, v in sorted(chat.by_side.items()))
            lines.append(
                f"Period: {chat.first_date.astimezone(self.tz):%Y-%m-%d} .. {chat.last_date.astimezone(self.tz):%Y-%m-%d}, "
                f"{chat.message_count} messages ({sides}), {chat.episodes} episodes, times in {self.tz.key}"
            )
        lines.append("Line format: `[time] #seq SIDE U##### Name (role) ↳#N U##### \"quote\": text`.")
        return "\n".join(lines) + "\n\n"

    def _line(self, m: AnonMessage, prev: Optional[AnonMessage]) -> str:
        stamp = m.date.astimezone(self.tz).strftime("%Y-%m-%d %H:%M")
        continuation = (
            prev is not None and m.sender is not None and m.sender == prev.sender
            and m.reply_to is None and m.forwarded is None and m.action is None
            and (m.date - prev.date).total_seconds() <= self.output.turn_merge_seconds
        )
        head = f"    #{m.seq}" if continuation else f"[{stamp}] #{m.seq} {_speaker(self.ds, m)}"
        if m.reply_to is not None:
            head += " " + _quote(self.index, m.reply_to)
        if m.forwarded is not None:
            head += f" (forwarded from {m.forwarded})"
        if m.action is not None:
            return f"{head}: [{m.action}]"
        body = _shorten(m.text.strip(), self.output.max_message_chars)
        if m.media:
            body = f"{media_label(m.media)} {body}".strip()
        if not body:
            body = "[empty]"
        if m.code and "\n" in body or m.code and len(body) > 80:
            return f"{head}:\n```\n{body}\n```"
        body = body.replace("\n", "\n    ")
        return f"{head}: {body}"

    def blocks(self) -> list[str]:
        episodes: dict[int, list[AnonMessage]] = {}
        for m in self.msgs:
            episodes.setdefault(m.episode, []).append(m)
        out = []
        for number, msgs in episodes.items():
            start, end = msgs[0].date.astimezone(self.tz), msgs[-1].date.astimezone(self.tz)
            span = f"{start:%Y-%m-%d %H:%M} .. {end:%H:%M}" if start.date() == end.date() else f"{start:%Y-%m-%d %H:%M} .. {end:%Y-%m-%d %H:%M}"
            title = f"## Episode {number} - {span} ({len(msgs)} messages"
            if self.chat.is_forum and msgs[0].topic is not None:
                title += f", topic {msgs[0].topic}"
            lines = [title + ")", ""]
            prev = None
            for m in msgs:
                lines.append(self._line(m, prev))
                prev = m
            out.append("\n".join(lines) + "\n\n")
        return out


# A transcript part or chunk file name as this module composes it, out of a
# virtual id, a part number and a counter.
_OWN_FILE_NAME = re.compile(r"chunk-\d+\.md|C\d+(?:\.part\d+)?\.md")


def is_own_file_name(text: str) -> bool:
    """Whether a string is a file name this module composed. Such a name
    holds a virtual id and a counter and nothing else, while reading as a
    host in the Moldovan '.md' domain, so the leak audit passes it by."""
    return bool(_OWN_FILE_NAME.fullmatch(text))


# A message line as ``_TranscriptRenderer._line`` composes it: the head (time,
# sequence number, speaker, reply reference), the quoted snippet of the
# message replied to, the forward note and the body. The quotation marks and
# the colon between them are layout and carry nothing. The head is bounded,
# so the match stays linear.
_TRANSCRIPT_LINE = re.compile(
    r"(?P<head>(?:\[[^\]\n]{1,40}\] #\d+ [^\n\"]{0,120}?|[ \t]+#\d+)(?: ↳#\d+(?: \S{1,40})?)?)"
    r"(?: \"(?P<quote>[^\n]*)\")?"
    r"(?P<forwarded>(?: \(forwarded from [^ )\n]{1,40}\))?)"
    r":(?: (?P<body>[^\n]*))?"
)


def split_transcript_line(line: str) -> tuple[str, ...]:
    """The parts of a rendered transcript line. The leak audit scans them
    separately, so a keyword ending one part never claims a value out of the
    next: the writer's own layout turns a message asking for a "пароль" and
    the reply quoted after it into `пароль": Добрый`, and a display name into
    `Nick: Hello`. Each part is scanned the way the scrubber saw it, the body
    from its own start, so a pasted chat header is still recognised there. A
    line of any other shape (a header, an episode title, a fenced code line)
    is one part."""
    m = _TRANSCRIPT_LINE.fullmatch(line)
    if m is None:
        return (line,)
    return tuple(part for part in m.group("head", "quote", "forwarded", "body") if part)


def render_transcript(ds: Dataset, chat: AnonChat, output: Output) -> list[str]:
    """Markdown transcript of one chat, split into parts of at most
    ``output.max_chars`` characters (0 = never split). Splits happen on
    episode boundaries; an episode larger than the budget is split on
    message boundaries."""
    r = _TranscriptRenderer(ds, chat, output)
    blocks = r.blocks()
    if not output.max_chars:
        return [r.header() + "".join(blocks)]
    budget = max(output.max_chars, 10_000)
    pieces: list[str] = []
    for block in blocks:
        if len(block) <= budget:
            pieces.append(block)
        else:
            lines = block.split("\n")
            pieces.extend(line + "\n" for line in lines)
    parts: list[list[str]] = [[]]
    size = 0
    for piece in pieces:
        if size and size + len(piece) > budget:
            parts.append([])
            size = 0
        parts[-1].append(piece)
        size += len(piece)
    parts = [p for p in parts if any(x.strip() for x in p)] or [[]]
    total = len(parts)
    return [r.header((i + 1, total) if total > 1 else None) + "".join(p) for i, p in enumerate(parts)]


def pack_chunks(parts: list[tuple[str, str]], max_chars: int) -> list[list[tuple[str, str]]]:
    """Greedily pack (name, text) transcript parts into chunks of about
    ``max_chars``; a part is never split further."""
    chunks: list[list[tuple[str, str]]] = [[]]
    size = 0
    for name, text in parts:
        if size and size + len(text) > max_chars:
            chunks.append([])
            size = 0
        chunks[-1].append((name, text))
        size += len(text)
    return [c for c in chunks if c]


DATASET_README = """# Anonymized Telegram support dataset

Format version {version}. Generated by tg-collector.

Units: a **chat** (`C#####`) is one client organisation's support group; an
**episode** is a run of messages in a chat without a long inactivity gap
(and within one forum topic), which usually holds one request and its
resolution. Use episodes as the unit for extracting typical requests.

* `chunks/chunk-NNN.md` - transcripts packed into files of roughly equal size;
  feed these one by one. Each contains whole chats or whole parts of a chat.
* `transcripts/C#####.md` - one readable transcript per chat (split into
  `C#####.partNN.md` when large). Sections `## Episode N - <span> (<n> messages)`
  hold lines `[YYYY-MM-DD HH:MM] #seq SIDE U##### Name (role) ↳#N U##### "quote": text`.
  `SIDE` is `CLIENT` (the customer), `STAFF` (vendor: support/sales/admins),
  `BOT` or `UNKNOWN`. Indented `#seq:` lines continue the previous speaker's
  turn. A quote is one line, with a line break of the quoted message shown as
  `⏎`. Long messages are shortened with `[... N chars omitted ...]`;
  both cuts fall on word boundaries, so a placeholder is never cut in half.
  Log/code messages are fenced.
* `messages.jsonl` - the same messages, one JSON object per line:
  `chat, episode, seq, date (UTC), sender, role, side, text, reply_to?, topic?,
  media?, edited?, forwarded?, action?` (a kept service message), `code?`.
  Messages are complete here.
* `episodes.jsonl` - one line per episode: `chat, episode, topic` (always
  present, `null` outside a forum), `start, end, messages, participants, sides`.
* `users.json` - `U#####` -> `name` (may be empty), `role` (`support`, `sales`,
  `other` = vendor colleagues who mostly read along, `client`, `bot`, `anonymous`,
  `deleted`), `side`.
* `chats.json` - `C#####` -> participants (sorted by id), message count, period,
  episodes.
* `manifest.json` - counts, date range, anonymization policy, notes.

Identifiers are virtual, random, of one fixed width per mapping (a
`mapping.json` written by an older version may mix widths) and stable across
exports; they are not derived from Telegram ids and their order means
nothing. Placeholders in text keep the *kind* of data:

* people and contacts: `@U#####` (mention), `@C#####` (a chat of this dataset
  named by its public username), `@user` (unknown mention), `<name>` (last
  names, full names, name + patronymic, people named next to a keyword),
  `<cardholder>`, `<email>`, `<phone>`, `<address>`, `<postcode>`, `<dob>`,
  `<org>`, `<domain>`, `<id>` (a raw Telegram chat or user id written out in
  the text, `-1001234567890` included)
* links: `<url>`, `<url:host>` (`<url:[::1]>` for an IPv6 host), `<tg-link>`,
  `<ip>`, `<proxy>`, `<user-agent>`, `<sub>` (the hidden subdomain of an
  allowed host: `<sub>.example.com`); a link kept by the policy carries
  placeholders where it held identifiers, percent-encoded ones included
  (`?password=<password>`, `?q=<name>`)
* cards and payments: `424242**********` (bank card: BIN kept, rest masked;
  `<card>` when the BIN is unreadable), `<exp>`, `<cvv>`, `<pin>`, `<otp>`
  (SMS / 3-D Secure / backup code), `<iban>`, `<account>`, `<bank-code>`
  (routing / sort code), `<txn-ref>` (RRN/ARN/auth code)
* crypto: `<wallet>`, `<txid>`, `<seed-phrase>`, `<id>` (exchange memo / uid,
  messenger id, ad-platform id), `<ad-account>`
* documents: `<passport>`, `<driver-licence>`, `<iin>`, `<rnokpp>`, `<inn>`,
  `<ogrn>`, `<snils>`, `<tax-id>`, `<personal-id>`, `<company-id>`, `<device-id>`
* secrets: `<password>`, `<credentials>` (login:password pairs and dumps),
  `<2fa-secret>`, `<token>`, `<private-key>` (the body of a PEM block; its
  BEGIN/END lines stay), `<cookie>`, `<redacted>` (custom patterns)

Keywords next to a value stay ("cvv <cvv>", "IIN <iin>", or in Russian
"ИИН <iin>"), and so does the markup around one
("<Password><password></Password>"), so requests can still be classified. Amounts, dates, version
and clause numbers (also four-part ones after a version or clause word) and
loopback addresses (`127.0.0.1`, `0.0.0.0`, `::1`) are left as written. Message text is in Unicode
NFC form; invisible formatting characters and Russian stress marks are
removed. Media appear as `[photo]`, `[document:pdf 1.2 MB]`,
`[voice 0:41]` etc.; no files are included. The extension is shown only when it
is one (a file name ending in something else, as Russian document names often
do, falls back to the extension of its MIME type, or to none). Forwarded messages carry
`(forwarded from U#####|C#####|external_user|external_chat|external_channel|hidden|imported)`.
"""


# --- what the writer composes itself --------------------------------------------------
#
# The leak audit hunts people's names and chat-title terms only in scrubbed
# free text. Everything named here the writer composed out of virtual ids,
# roles, dates and policy values, so a surname that transliterates onto one
# of its labels ("Бот" -> "BOT") is layout and not a leak. The knowledge
# lives beside the writer: a field added below has to be classified here in
# the same edit, and ``Dataset.texts`` lists the free-text side of the split.

TRANSCRIPT_DIR = "transcripts"
CHUNK_DIR = "chunks"
# The directories of rendered transcripts. Their lines quote the JSON files
# around the writer's own English labels, so they hold no free text of their
# own and are scanned part by part (``split_transcript_line``).
TRANSCRIPT_DIRS = (TRANSCRIPT_DIR, CHUNK_DIR)
# The chunk index: both its keys (chunk files) and its values (the transcript
# parts they hold) are file names this module composed.
CHUNK_INDEX = str(PurePath(CHUNK_DIR) / "index.json")
# The strings composed per JSON file (ids, roles, sides, dates, policy
# values). Every other string in these files is free text: message text,
# attachment names and extensions (copied from the file name as is), chat
# titles, a row of unexpected shape.
COMPOSED_JSON_KEYS = {
    rel: re.compile(keys) for rel, keys in {
        "messages.jsonl": r"chat|date|sender|role|side|forwarded|action|media\.kind",
        "episodes.jsonl": r"chat|start|end|participants\[\d+\]",
        "users.json": r"U\d+\.(?:role|side)",
        "chats.json": r"C\d+\.(?:kind|first_date|last_date|participants\[\d+\])",
        "manifest.json": r"first_date|last_date|policy\..+|notes\.suspect_staff\[\d+\]\.(?:vid|role)",
    }.items()
}
# The one string of users.json that is a kept display name rather than free
# text or a composed value: people's names are not hunted in it.
DISPLAY_NAME_KEY = re.compile(r"U\d+\.name")


def write_dataset(ds: Dataset, out_dir: Path, output: Output, policy_snapshot: dict[str, Any]) -> WriteReport:
    out_dir = Path(out_dir)
    ds.assign_episodes(output.episode_gap_hours)
    tmp = out_dir.with_name(out_dir.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / TRANSCRIPT_DIR).mkdir(parents=True)
    files = 0

    parts_all: list[tuple[str, str]] = []
    for chat in sorted(ds.chats.values(), key=lambda c: c.vid):
        parts = render_transcript(ds, chat, output)
        for i, text in enumerate(parts, 1):
            name = f"{chat.vid}.md" if len(parts) == 1 else f"{chat.vid}.part{i:02d}.md"
            (tmp / TRANSCRIPT_DIR / name).write_text(text, encoding="utf-8")
            parts_all.append((name, text))
            files += 1

    chunks = []
    if output.max_chars:
        (tmp / CHUNK_DIR).mkdir()
        chunks = pack_chunks(parts_all, max(output.max_chars, 10_000))
        index = {}
        for i, chunk in enumerate(chunks, 1):
            name = f"chunk-{i:03d}.md"
            (tmp / CHUNK_DIR / name).write_text("\n\n".join(text for _, text in chunk), encoding="utf-8")
            index[name] = [n for n, _ in chunk]
            files += 1
        (tmp / CHUNK_INDEX).write_text(json.dumps(index, indent=1), encoding="utf-8")
        files += 1

    with open(tmp / "messages.jsonl", "w", encoding="utf-8") as fh:
        for msg in ds.messages:
            fh.write(json.dumps(msg.to_json(), ensure_ascii=False) + "\n")
    with open(tmp / "episodes.jsonl", "w", encoding="utf-8") as fh:
        for chat in sorted(ds.chats.values(), key=lambda c: c.vid):
            episodes: dict[int, list[AnonMessage]] = {}
            for m in ds.messages_of(chat.vid):
                episodes.setdefault(m.episode, []).append(m)
            for number, msgs in episodes.items():
                sides: dict[str, int] = {}
                for m in msgs:
                    sides[m.side] = sides.get(m.side, 0) + 1
                fh.write(json.dumps({
                    "chat": chat.vid, "episode": number, "topic": msgs[0].topic,
                    "start": msgs[0].date.isoformat().replace("+00:00", "Z"),
                    "end": msgs[-1].date.isoformat().replace("+00:00", "Z"),
                    "messages": len(msgs),
                    "participants": sorted({m.sender for m in msgs if m.sender}),
                    "sides": sides,
                }, ensure_ascii=False) + "\n")
    files += 2

    (tmp / "users.json").write_text(json.dumps(
        {u.vid: {"name": u.name, "role": u.role, "side": u.side}
         for u in sorted(ds.users.values(), key=lambda u: u.vid)},
        ensure_ascii=False, indent=1), encoding="utf-8")
    (tmp / "chats.json").write_text(json.dumps(
        {c.vid: {
            "title": c.title, "kind": c.kind, "is_forum": c.is_forum, "participants": c.participants,
            "message_count": c.message_count, "by_side": c.by_side, "episodes": c.episodes,
            "first_date": c.first_date.isoformat() if c.first_date else None,
            "last_date": c.last_date.isoformat() if c.last_date else None,
        } for c in sorted(ds.chats.values(), key=lambda c: c.vid)},
        ensure_ascii=False, indent=1), encoding="utf-8")
    files += 2

    dates = [m.date for m in ds.messages]
    roles: dict[str, int] = {}
    for u in ds.users.values():
        roles[u.role] = roles.get(u.role, 0) + 1
    manifest = {
        "format_version": FORMAT_VERSION,
        "chats": len(ds.chats),
        "users": len(ds.users),
        "users_by_role": roles,
        "messages": len(ds.messages),
        "episodes": sum(c.episodes for c in ds.chats.values()),
        "first_date": min(dates).isoformat() if dates else None,
        "last_date": max(dates).isoformat() if dates else None,
        "transcript_parts": len(parts_all),
        "chunks": len(chunks),
        "policy": policy_snapshot,
        "notes": ds.notes,
    }
    (tmp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    (tmp / "README.md").write_text(DATASET_README.format(version=FORMAT_VERSION), encoding="utf-8")
    files += 2

    old = out_dir.with_name(out_dir.name + ".old")
    if old.exists():
        shutil.rmtree(old)
    if out_dir.exists():
        os.replace(out_dir, old)
    os.replace(tmp, out_dir)
    if old.exists():
        shutil.rmtree(old)
    return WriteReport(files=files, transcript_parts=len(parts_all), chunks=len(chunks), messages=len(ds.messages))
