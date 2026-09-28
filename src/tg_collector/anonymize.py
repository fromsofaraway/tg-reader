"""Raw export -> anonymized ``Dataset``.

``anonymize(store, mapping, roles, policy)`` is the single entry point. It
hides: merging migrated groups into one logical chat, stable random virtual
ids via ``Mapping``, role and side assignment, the display-name policy (a
Telegram "first name" is free text and is scrubbed like any other text),
building the scrubber's vocabulary (usernames of people and of exported
public chats, ids of participants, exported chats and third parties, names,
chat-title tokens of every merged peer, forward-header names and the contact
names of catalogued private dialogs; frequent title words are only suggested
for ``keep_terms``), message sequencing and reply re-linking,
dropping service/empty/bot messages, and a fail-fast self-check that no raw
id, username or phone survived.

``Mapping`` is the only piece of state that ties virtual ids back to
Telegram. Ids are drawn at random from a fixed-width space (so neither
their order nor their width reveals account age, chat activity or the run
that first saw them) and persisted so that re-running after an incremental
export keeps them stable. It lives outside the shareable dataset.
"""

from __future__ import annotations

import json
import mimetypes
import re
import secrets
from collections import Counter, defaultdict
# ``Mapping`` is this module's virtual-id store, so the read-only dict
# annotations use the abstract type under a name of its own.
from collections.abc import Mapping as ReadOnlyMap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Container, Iterable, Optional, Sequence
from urllib.parse import urlsplit

from .config import AnonPolicy
from .dataset import AnonChat, AnonMessage, AnonUser, Dataset
from .model import (
    FWD_CHANNEL, FWD_CHAT, FWD_USER, KIND_CHANNEL, KIND_PRIVATE, KIND_SUPERGROUP, ROLE_ANONYMOUS, ROLE_BOT,
    ROLE_CLIENT, ROLE_DELETED, ROLE_OTHER, ROLE_SALES, ROLE_SUPPORT, SIDE_BOT, SIDE_CLIENT, SIDE_STAFF, SIDE_UNKNOWN,
    STAFF_ROLES, SENDER_USER, Media, RawChat, RawMessage, RawUser, Roles, side_of,
)
from .rawstore import RawStore, write_private_json
from .scrub import (
    TITLE_STOPWORDS, Known, Leak, LeakScanner, Roster, Scrubber, fold, generic_title_word,
    org_terms_from_titles, plain_text,
)

SUSPECT_STAFF_MIN_CHATS = 3
MAX_NAME_LENGTH = 30
# First names that are also ordinary words; under ``name_mode = "none"`` they
# are not scrubbed from message text (they would eat "тема закрыта", "max").
FIRST_NAME_STOPWORDS = frozenset(
    "тема тёма света люба вера надежда роман лев марк мира мила лида слава "
    "max mark bill will sam tom don art may june grace gene pat guy rob ray sue ann".split())


class AnonymizationError(RuntimeError):
    """A condition that aborts the run. The message is safe to show: it names
    kinds, counts and virtual locations, never a raw value, because it is the
    line an operator pastes into a bug report. ``leaks`` carries the raw
    matches behind it for the caller's private report."""

    def __init__(self, message: str, leaks: Iterable[Leak] = ()):
        super().__init__(message)
        self.leaks: tuple[Leak, ...] = tuple(leaks)


class MappingError(AnonymizationError):
    """``mapping.json`` cannot be used: it is corrupted, or its id space is
    exhausted. Nothing was anonymized, so this is not a leak and the caller
    reports it apart from the self-check's abort."""


class Mapping:
    """Stable virtual ids. New ids are random unused numbers drawn from a
    space fixed when the mapping is created (``DIGITS`` digits per prefix):
    every id has the same width and value range whenever it was allocated,
    so neither the order of appearance nor the underlying Telegram id can be
    inferred. The width is saved with the mapping and never changes. A
    mapping saved before the width was stored is pinned, per prefix, to the
    widest id it already holds; existing ids are never re-padded, because
    they must stay stable across incremental runs."""

    # 99 999 ids per prefix: ample for one support account. Must stay below
    # ``LeakScanner.MIN_ID_DIGITS``: the raw-id sweeps hunt numbers that long
    # without stopping at a preceding letter, so a virtual id as wide as a raw
    # Telegram id could coincide with it and abort the self-check.
    DIGITS = 5
    _ID_SHAPE = re.compile(r"[UC]\d+")

    def __init__(self, path: Path, users: Optional[dict[int, str]] = None, chats: Optional[dict[int, str]] = None,
                 digits: Optional[dict[str, int]] = None):
        """``digits`` is the stored width per prefix (``{"U": 5, "C": 5}``);
        without it each prefix takes the width of its widest existing id,
        or ``DIGITS`` when it has none."""
        self.path = Path(path)
        self._users: dict[int, str] = dict(users or {})
        self._chats: dict[int, str] = dict(chats or {})
        self._taken: dict[str, set[str]] = {"U": set(self._users.values()), "C": set(self._chats.values())}
        self._digits: dict[str, int] = {
            prefix: digits[prefix] if digits is not None else max((len(v) - 1 for v in taken), default=self.DIGITS)
            for prefix, taken in self._taken.items()
        }

    @classmethod
    def load(cls, path: Path) -> "Mapping":
        path = Path(path)
        if not path.exists():
            return cls(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            users = {int(k): str(v) for k, v in data.get("users", {}).items()}
            chats = {int(k): str(v) for k, v in data.get("chats", {}).items()}
            digits = {p: int(data["digits"][p]) for p in ("U", "C")} if "digits" in data else None
        except (ValueError, AttributeError, TypeError, KeyError) as exc:
            raise cls._corrupted(path, "not the JSON this tool writes") from exc
        cls._check(path, users, chats, digits)
        return cls(path, users=users, chats=chats, digits=digits)

    @classmethod
    def _corrupted(cls, path: Path, reason: str) -> MappingError:
        """The reason describes the shape of the damage and never quotes the
        file: it holds raw Telegram ids, and this line is what an operator
        pastes into a bug report."""
        return MappingError(f"{path} is corrupted ({reason}); restore it from a backup or delete it "
                            "to start with fresh virtual ids")

    @classmethod
    def _check(cls, path: Path, users: dict[int, str], chats: dict[int, str],
               digits: Optional[dict[str, int]]) -> None:
        """Every stored id must be well-formed, and a stored width must hold
        every existing id: a narrower one would make newcomers stand out."""
        for prefix, ids in (("U", users.values()), ("C", chats.values())):
            if not all(cls._ID_SHAPE.fullmatch(v) and v[0] == prefix for v in ids):
                raise cls._corrupted(path, f"malformed {prefix} ids")
            if digits is not None and (digits[prefix] < 1 or any(len(v) - 1 > digits[prefix] for v in ids)):
                raise cls._corrupted(path, f"digits[{prefix}] = {digits[prefix]} does not fit the stored ids")

    def save(self) -> None:
        """Write the mapping (mode 600, atomically)."""
        payload = {
            "warning": "SECRET: links virtual ids to Telegram ids. Never share together with the dataset.",
            "digits": dict(self._digits),
            "users": {str(k): v for k, v in sorted(self._users.items(), key=lambda kv: kv[1])},
            "chats": {str(k): v for k, v in sorted(self._chats.items(), key=lambda kv: kv[1])},
        }
        write_private_json(self.path, payload)
        # Remove a stale "mapping.tmp": a write path that set the mode only
        # after writing could leave the raw ids world-readable there.
        self.path.with_suffix(".tmp").unlink(missing_ok=True)

    def _fresh(self, prefix: str) -> str:
        taken, digits = self._taken[prefix], self._digits[prefix]
        space = 10 ** digits - 1
        if len(taken) >= space:
            raise MappingError(f"all {space} virtual ids {prefix}{'#' * digits} of {self.path} are taken; "
                               "start a new mapping to continue")
        while True:
            candidate = f"{prefix}{secrets.randbelow(space) + 1:0{digits}d}"
            if candidate not in taken:
                taken.add(candidate)
                return candidate

    def user(self, tg_id: int) -> str:
        if tg_id not in self._users:
            self._users[tg_id] = self._fresh("U")
        return self._users[tg_id]

    def chat(self, tg_id: int) -> str:
        if tg_id not in self._chats:
            self._chats[tg_id] = self._fresh("C")
        return self._chats[tg_id]

    def chat_for(self, peers: Sequence[int]) -> str:
        """The virtual id of one conversation, given every raw id its
        messages live under (a legacy group and the supergroup it migrated
        to, oldest first). The first peer that already has an id keeps it and
        lends it to the others, so a migration that only shows up in a later
        export does not renumber the chat and does not move its history to a
        second id. Several peers therefore share one virtual id."""
        vid = next((self._chats[p] for p in peers if p in self._chats), None) or self._fresh("C")
        for p in peers:
            self._chats.setdefault(p, vid)
        return vid

    def users(self) -> dict[int, str]:
        return dict(self._users)

    def chats(self) -> dict[int, str]:
        return dict(self._chats)


# --- logical chats --------------------------------------------------------------------

@dataclass(frozen=True)
class LogicalChat:
    """A client conversation, possibly spread over a legacy group and the
    supergroup it migrated to."""

    primary: RawChat
    peers: tuple[int, ...]  # raw chat ids whose messages belong here (oldest first)


def logical_chats(chats: dict[int, RawChat], exported_ids: Iterable[int]) -> list[LogicalChat]:
    groups: dict[int, list[int]] = defaultdict(list)
    for cid in set(exported_ids):
        chat = chats.get(cid)
        if chat is None:
            continue
        target = chat.migrated_to if chat.migrated_to in chats else None
        groups[target or cid].append(cid)
    result = []
    for primary_id, members in groups.items():
        members.sort(key=lambda cid: (chats[cid].migrated_to is None, cid))  # legacy group first
        result.append(LogicalChat(primary=chats[primary_id], peers=tuple(members)))
    return result


# --- names ----------------------------------------------------------------------------------

# A name token is letters only, with an inner apostrophe or hyphen allowed
# ("Анна-Мария", "O'Brien"); two words glued together ("VasyaPupkin") are not.
_NAME_TOKEN = re.compile(r"[^\W\d_]+(?:['’-][^\W\d_]+)*")
_NAME_WORD = re.compile(r"[^\W\d_]+")  # the letter runs a name token is made of
_CAMEL = re.compile(r"[a-zа-яё][A-ZА-ЯЁ]")
# Endings that mark a Russian surname with high precision. Deliberately
# without -ин/-ина/-ук: Ирина, Марина, Константин, Валентин are given names.
_SURNAME_SUFFIX = re.compile(r"(?:ов|ев|ёв|ова|ева|ёва|ский|ская|цкий|цкая|енко|ич)$", re.IGNORECASE)
# The same endings in the Latin transliteration the scrubber also hunts for.
# Used only where a known person's name has already matched, since they are
# far less exclusive than the Cyrillic ones ("Yakov" is a given name).
_LATIN_SURNAME_SUFFIX = re.compile(r"(?:ov|ev|ova|eva|sky|skiy|skaya|enko|ich)$", re.IGNORECASE)


def _name_shaped(token: str) -> bool:
    return bool(_NAME_TOKEN.fullmatch(token)) and not _CAMEL.search(token)


def _capitalised(token: str) -> bool:
    return all(p[:1].isupper() and p[1:].islower() for p in re.split(r"['’-]", token) if p)


def _surname_shaped(token: str) -> bool:
    return len(token) >= 5 and bool(_SURNAME_SUFFIX.search(token))


def _surname_spelling(token: str) -> bool:
    """Whether a word is spelled like a surname in either alphabet. Only for
    a word the people vocabulary has already matched: on its own the Latin
    half would read given names as surnames."""
    return _surname_shaped(token) or (len(token) >= 5 and bool(_LATIN_SURNAME_SUFFIX.search(token)))


# Words that label a role, a side or a team rather than name a person: the
# generic chat-title words, the labels the dataset prints on every line
# ("STAFF", "(support)", "client", "system") and the usual Russian name of a
# support account ("Служба поддержки").
_LABEL_WORDS = frozenset(fold(w) for w in (
    *TITLE_STOPWORDS, ROLE_SUPPORT, ROLE_SALES, ROLE_OTHER, ROLE_CLIENT, ROLE_BOT, ROLE_ANONYMOUS, ROLE_DELETED,
    SIDE_STAFF, SIDE_CLIENT, SIDE_BOT, SIDE_UNKNOWN, "system", "staff", "admin", "служба", "поддержки"))


def is_label(text: str, keep_terms: Iterable[str] = ()) -> bool:
    """Whether ``text`` is made only of label words and whole keep terms:
    "Support", "(Support)", "Support Team", or "Northwind Pay Support" with
    "Northwind Pay" kept. Such a text names a team or a role, never a
    person, so it is not a surname and not a name to scrub. A keep term
    counts only as the whole phrase: the surname "Белый" is no label because
    "Белый список" is kept."""
    words = [fold(w) for w in _NAME_WORD.findall(plain_text(text))]
    phrases = {tuple(fold(w) for w in _NAME_WORD.findall(plain_text(t))) for t in keep_terms} - {()}
    longest_first = sorted(phrases, key=len, reverse=True)
    i = 0
    while i < len(words):
        phrase = next((p for p in longest_first if tuple(words[i:i + len(p)]) == p), None)
        if phrase is not None:
            i += len(phrase)
        elif words[i] in _LABEL_WORDS:
            i += 1
        else:
            return False
    return bool(words)


def _surname_field(user: RawUser) -> str:
    """The last-name field, unless it is a label: support accounts are often
    named "Acme" / "Support" or "Анна" / "Поддержка", and the dataset prints
    its own role labels on every line. A label is never a surname (the rule
    ``split_free_text_name`` applies to free-text names), so it is neither
    scrubbed from messages nor hunted for by verify."""
    last_name = plain_text(user.last_name).strip()
    return "" if is_label(last_name) else last_name


def split_free_text_name(user: RawUser) -> tuple[str, tuple[str, ...]]:
    """``(given name, surname tokens)`` of a first-name field that carries a
    whole name while the last-name field is empty (or a label such as
    "Support"): "Иван Петров", "Иванов Сергей", "Anna Smirnova". Two or three
    capitalised letter-only tokens
    qualify; the given name is the first token without a surname ending, the
    other tokens are surnames (labels such as "Support" or "Staff" are
    not). Anything else ("Sergey CEO", "+7 999 ...", "Иван (Ромашка)")
    yields the first token and no surnames. Known residual: "Сорокин Иван"
    (an -ин surname written first) reads as the given name Сорокин."""
    toks = plain_text(user.first_name).split()
    given = toks[0] if toks else ""
    if user.is_bot or _surname_field(user) or not 2 <= len(toks) <= 3:
        return given, ()
    if not all(_name_shaped(t) and _capitalised(t) for t in toks):
        return given, ()
    given = next((t for t in toks if not _surname_shaped(t)), toks[0])
    surnames = tuple(t for t in toks if t != given and len(t) >= 3 and not is_label(t))
    return given, surnames


def _lone_surname(user: RawUser, candidate: str) -> bool:
    """Whether a profile's first-name field holds nothing but a surname
    ("Кузнецов", "Смирнова", "Кузнецов А."): one word with a high-precision
    Russian surname ending, no last-name field and no second name token
    beside it. Such a name would otherwise head every transcript line. Only
    the Cyrillic endings count: "Petrov" is told from "Yakov" by the people
    vocabulary instead (``_drop_names_of_others``). A misfire costs an empty
    display name, never an exposed surname."""
    return (not user.is_bot and not _surname_field(user) and not split_free_text_name(user)[1]
            and " " not in candidate and _surname_shaped(candidate))


def _fields_swapped(user: RawUser, candidate: str, given_names: ReadOnlyMap[str, int]) -> bool:
    """Whether a profile with both fields filled has them the wrong way
    round ("Сидоров" / "Иван"): the last-name field holds a word other
    people use as a given name while nobody else uses the first-name field's
    word as one. A misfire costs an empty display name, never an exposed
    surname."""
    last_name = _surname_field(user)
    if not last_name:
        return False
    last, first = fold(last_name), fold(candidate)
    others_use_last = given_names.get(last, 0) - (1 if first == last else 0)
    return others_use_last >= 1 and given_names.get(first, 0) <= 1


def _spells_a_username(candidate: str, user: RawUser, checker: Optional[Scrubber]) -> bool:
    """Whether a word of the name is a username: the user's own or any in
    the checker's roster (people and exported chats), except keep_terms.
    The checker leaves short plain usernames ("kotik") alone because in
    free text they collide with words, but a name that is a handle links
    the virtual id straight to t.me/<username>. Words are the letter runs
    a name token is made of, so "Kotik-Smith" counts as well."""
    own = {u.lower() for u in user.all_usernames}
    known = checker.roster.by_username if checker is not None else {}
    keep = {k.lower() for k in checker.roster.keep_terms} if checker is not None else set()
    words = {w.lower() for w in _NAME_WORD.findall(candidate)} - keep
    return any(w in own or w in known for w in words)


def display_name(user: RawUser, mode: str, checker: Optional[Scrubber] = None,
                 last_names: frozenset[str] = frozenset(), given_names: ReadOnlyMap[str, int] = {}) -> str:
    """The name a virtual user keeps. Telegram names are free text, so the
    candidate is run through ``checker`` (a scrubber without the people
    vocabulary) and dropped entirely if anything in it had to go, if it
    is not shaped like a name (nicknames such as "Vasya_Pupkin"), or if a
    word of it is a known username (the user's own or anybody's, in every
    mode). In ``first`` mode a 2-3 word first name with an empty last name
    is read as "First Last" / "Last First" and only the given name is kept;
    a candidate that is a known last name is dropped too, and so is a
    first-name field that looks like a surname next to a last-name field
    that looks like a given name (swapped fields) or that holds nothing but
    a surname ("Кузнецов")."""
    if user.is_deleted:
        return "Deleted"
    if mode == "none":
        return ""
    if mode == "full" or user.is_bot:
        candidate = user.display_name
    else:
        candidate, _ = split_free_text_name(user)
    candidate = " ".join(plain_text(candidate).split())  # the form the scrubber and verify compare
    if not candidate or len(candidate) > MAX_NAME_LENGTH:
        return ""
    if re.search(r"[@<>\d]|https?:", candidate):
        return ""
    if not all(_name_shaped(t) for t in candidate.split()):
        return ""
    if checker is not None and checker.scrub(candidate) != candidate:
        return ""
    if _spells_a_username(candidate, user, checker):
        return ""
    if mode == "first" and not user.is_bot:
        if (fold(candidate) in last_names or _fields_swapped(user, candidate, given_names)
                or _lone_surname(user, candidate)):
            return ""
    return candidate


def forward_surnames(forward_names: Iterable[str], kept: set[str], first_names: set[str]) -> dict[str, str]:
    """The last token of every multi-word forward-header name ("Иван Петров"
    -> "Петров"), keyed by the header it was read from. The scrubber removes
    the whole phrase and, under ``scrub_last_names``, the surnames of this
    set that are spelled like one; the fuzzy audit hunts for all of them, so
    the operator judges the rest."""
    out: dict[str, str] = {}
    for name in forward_names:
        toks = name.split()
        if len(toks) < 2:
            continue
        last = toks[-1]
        if (len(last) >= 5 and last.isalpha() and last[:1].isupper() and not is_label(last)
                and fold(last) not in kept and fold(last) not in first_names):
            out[name] = last
    return out


def _standalone_forward_surnames(forward_names: Iterable[str], kept: frozenset[str],
                                 first_names: set[str]) -> list[str]:
    """Forward-header surnames the scrubber removes wherever they stand alone
    ("Громов сказал" after a forward from "Геннадий Громов"). The header must
    name a person: the last token is spelled like a surname and no other
    token is a role word or a kind of business, so a shop or a team keeps its
    word ("Магазин Цветов", "Отдел Продаж", "Служба Доставки")."""
    return [last for name, last in forward_surnames(forward_names, set(kept), first_names).items()
            if _surname_shaped(last)
            and not any(is_label(t) or generic_title_word(t) for t in name.split()[:-1])]


def _person_terms(users: Iterable[RawUser], policy: AnonPolicy, extra: Iterable[str] = (),
                  kept_names: frozenset[str] = frozenset(), given_names: ReadOnlyMap[str, int] = {},
                  phrase_only: Iterable[str] = ()) -> list[str]:
    """Names that must not survive in text. ``extra`` are forward headers and
    post authors (free text): a "First Last" string is identifying in every
    mode, a bare first name only when the policy scrubs first names, and the
    surname alone when the policy scrubs last names. ``phrase_only`` are
    contact names read from the dialog catalogue: the whole phrase is
    removed, never a token of it on its own, because nothing says which of
    its words is the surname. A term made only of labels and whole keep terms
    ("Support Team", "Northwind Support") names a team and is left out
    (``is_label``)."""
    terms: list[str] = []
    for name in (*extra, *phrase_only):
        toks = name.split()
        if not toks:
            continue
        if policy.name_mode == "none":
            if fold(name) not in FIRST_NAME_STOPWORDS:
                terms.append(name)
        elif len(toks) >= 2 and fold(name) not in kept_names:
            terms.append(name)
    if policy.scrub_last_names:
        terms.extend(_standalone_forward_surnames(extra, kept_names, set(given_names)))
    for u in users:
        standalone, full = _user_name_terms(u, policy, given_names)
        terms.extend((*standalone, *full))
    return [t for t in terms if not is_label(t, policy.keep_terms)]


def _user_name_terms(u: RawUser, policy: AnonPolicy, given_names: ReadOnlyMap[str, int]) -> tuple[list[str], list[str]]:
    """``(standalone, full)`` name terms of one profile. Standalone terms are
    removed wherever they stand on their own (last names; first names in
    ``none`` mode); full terms only as a whole phrase, since "First Last"
    together is identifying in every mode."""
    standalone: list[str] = []
    full: list[str] = []
    if u.is_bot:
        return standalone, full
    given, surnames = split_free_text_name(u)
    first_name, last_name = plain_text(u.first_name).strip(), _surname_field(u)
    if policy.scrub_last_names:
        if last_name:
            standalone.append(last_name)
        standalone.extend(surnames)
        if _fields_swapped(u, given, given_names) or _lone_surname(u, given):
            standalone.append(given)  # the first-name field holds the surname
    if (first_name and last_name) or surnames:
        full.append(" ".join(p for p in (first_name, last_name) if p))
        if first_name and last_name:
            full.append(f"{last_name} {first_name}")  # surname-first order, common in CIS forms
    elif u.last_name.strip() and len(first_name.split()) >= 2:
        full.append(u.display_name)  # an unsplit whole name next to a label: the phrase as shown
    if policy.name_mode == "none" and first_name and fold(given) not in FIRST_NAME_STOPWORDS:
        standalone.append(first_name)
    return standalone, full


def _drop_names_of_others(kept_names: dict[int, str], users: ReadOnlyMap[int, RawUser],
                          person_terms: Iterable[str], policy: AnonPolicy) -> dict[int, str]:
    """Blank a display name that shows somebody else's name. The people
    vocabulary is the pattern the scrubber removes from message text, so a
    name the text never keeps is not kept in ``users.json`` either: a bot
    named after a person ("Олег Северов", "Petrov Assistant") loses its name
    entirely, and under ``name_mode = "first"`` so does a first-name field
    that is nothing but a participant's surname in some spelling ("Петрова",
    "Petrov"). A given name that merely inflects onto a surname ("Марина"
    next to the surname "Марин") is kept: it has to be spelled like a surname
    as well."""
    pattern = Roster(person_terms=tuple(person_terms), keep_terms=tuple(policy.keep_terms)).person_pattern()
    if pattern is None:
        return kept_names
    out = dict(kept_names)
    for uid, name in kept_names.items():
        user = users.get(uid)
        if not name or name == "Deleted" or user is None:
            continue
        if user.is_bot:
            if pattern.search(name):
                out[uid] = ""
        elif policy.name_mode == "first" and _surname_spelling(name) and pattern.fullmatch(name):
            out[uid] = ""
    return out


def _keep_term_suggestions(candidates: Iterable[str], users: Iterable[RawUser], policy: AnonPolicy,
                           given_names: ReadOnlyMap[str, int]) -> tuple[str, ...]:
    """Frequent chat-title words worth offering for ``keep_terms``: not
    configured already (``keep_terms``, ``custom_terms``) and not a word of a
    name the people vocabulary removes on its own. An account manager's
    surname sits in every client chat title just like a product name, and
    whitelisting it would expose it everywhere, so it is never suggested; the
    check uses the person pattern itself, so every spelling it hunts for
    (inflected, Latin, "yo" for ё) counts."""
    configured = {fold(t) for t in (*policy.keep_terms, *policy.custom_terms)}
    words = {w for u in users for term in _user_name_terms(u, policy, given_names)[0] for w in term.split()}
    named = Roster(person_terms=tuple(sorted(words))).person_pattern()
    return tuple(c for c in candidates if fold(c) not in configured and not (named and named.fullmatch(c)))


def _chat_title(lc: LogicalChat, chats: ReadOnlyMap[int, RawChat]) -> str:
    """The title text of a logical chat for the org vocabulary: the current
    title, then the titles of merged legacy groups, whose old name is still
    quoted in the history ("Лютик стал Ромашкой"). One string per logical
    chat, so a chat counts once towards the keep_terms suggestion threshold."""
    titles = (lc.primary.title, *(chats[p].title for p in lc.peers if p != lc.primary.id))
    return " ".join(t for t in titles if t)


def _contact_names(chats: ReadOnlyMap[int, RawChat], exported: Container[int]) -> list[str]:
    """Names of people the export does not contain, read from the titles of
    the catalogued private dialogs: the account's contact list spells a
    client's employee in full ("Мария Кузнецова"), and the messages that were
    exported name that person. Only a title of two or three capitalised
    letter-only words qualifies, so a nickname ("Мама"), a label ("Отдел
    продаж") and a bot dialog are left out; the phrase is removed as a whole,
    never a token of it, because a guess about which word is the surname
    would erase an ordinary one."""
    names = []
    for cid, chat in chats.items():
        if cid in exported or chat.kind != KIND_PRIVATE:
            continue
        toks = plain_text(chat.title).split()
        if 2 <= len(toks) <= 3 and all(_name_shaped(t) and _capitalised(t) for t in toks):
            names.append(" ".join(toks))
    return names


def _username_vids(users: dict[int, RawUser], chat_usernames: dict[str, int],
                   user_vid: Callable[[int], str], chat_vid: Callable[[int], str]) -> dict[str, str]:
    """Lowercase username -> virtual id, for the scrubber's roster. People
    are merged last, so a person's username always renders as their own id."""
    return {**{name: chat_vid(cid) for name, cid in chat_usernames.items()},
            **{name.lower(): user_vid(user.id) for user in users.values() for name in user.all_usernames}}


@dataclass(frozen=True)
class Vocabulary:
    """Everything derived from the raw store that both the scrubber and the
    verifier need, computed once so the two can never disagree."""

    users: dict[int, RawUser]
    chats: dict[int, RawChat]           # exported peers only (not the whole catalogue)
    # Public usernames (lowercase) of the exported supergroups and channels ->
    # the raw id of the logical chat they name: "romashka_support_chat"
    # names the client as surely as the chat title does.
    chat_usernames: dict[str, int]
    # Raw ids of peers the export names only in passing: a linked channel or
    # an anonymous admin posting into an exported chat, and the source of a
    # forwarded message. They have no virtual id, so their numbers are
    # removed as "<id>" rather than mapped.
    third_party_ids: frozenset[int]
    logical: list[tuple[LogicalChat, list[RawMessage]]]
    person_terms: tuple[str, ...]
    org_terms: tuple[str, ...]          # every title token plus custom_terms (keep_terms win later)
    # Frequent title words (usually the product name) not configured yet:
    # scrubbed like every other title word, suggested to the operator.
    keep_term_candidates: tuple[str, ...]
    forward_names: frozenset[str]
    domains: Counter[str]
    # The display name actually shown per raw user id ('' when dropped): one
    # decision, consumed by both the anonymizer and the verifier.
    kept_names: dict[int, str]
    first_names_kept_as_words: tuple[str, ...]

    def username_vids(self, user_vid: Callable[[int], str], chat_vid: Callable[[int], str]) -> dict[str, str]:
        """Every known username (people and exported chats) -> its virtual id."""
        return _username_vids(self.users, self.chat_usernames, user_vid, chat_vid)

    def usernames(self) -> frozenset[str]:
        """Every known username, lowercase: what the output must not contain."""
        return frozenset(self.chat_usernames) | {n.lower() for u in self.users.values() for n in u.all_usernames}

    def known_ids(self) -> frozenset[int]:
        """Every raw Telegram id the export mentions: participants, exported
        chats and third parties alike. What the scrubber removes from text
        and the self-check hunts for."""
        return frozenset((*self.users, *self.chats, *self.third_party_ids))

    def phones(self) -> frozenset[str]:
        """Every participant's own number from their profile, digits only:
        what the scrubber removes and the self-check hunts for."""
        return frozenset(u.phone.lstrip("+") for u in self.users.values() if u.phone)

    def known(self) -> Known:
        """The high-precision identifiers to hunt for in the output: raw ids,
        usernames and the participants' own phone numbers. A hit on one of
        them is a bug, so the anonymizer's self-check scans for exactly these
        and ``verify`` layers the fuzzy vocabulary (names, title terms,
        keep_terms, card BINs) on top of the very same set."""
        return Known(
            user_ids=frozenset(self.users),
            chat_ids=self.known_ids() - frozenset(self.users),
            usernames=self.usernames(),
            chat_usernames=frozenset(self.chat_usernames),
            phones=self.phones(),
        )


def vocabulary(store: RawStore, policy: AnonPolicy) -> Vocabulary:
    raw_chats = store.chats()
    raw_users = store.users()
    loaded: list[tuple[LogicalChat, list[RawMessage]]] = []
    for lc in logical_chats(raw_chats, store.message_chat_ids()):
        msgs: list[RawMessage] = []
        for peer in lc.peers:
            msgs.extend(store.messages(peer))
        if lc.primary.is_forum:
            msgs.sort(key=lambda m: (m.topic_id or 0, m.date, m.chat_id, m.id))  # topics stay contiguous
        else:
            msgs.sort(key=lambda m: (m.date, m.chat_id, m.id))
        if msgs:
            loaded.append((lc, msgs))
    loaded.sort(key=lambda item: (min(m.date for m in item[1]), item[0].primary.id))

    forward_names: set[str] = set()
    third_party_ids: set[int] = set()
    domains: Counter[str] = Counter()
    for _, msgs in loaded:
        for m in msgs:
            if m.sender_kind == SENDER_USER and m.sender_id is not None and m.sender_id not in raw_users:
                raw_users[m.sender_id] = RawUser(id=m.sender_id)  # seen only as a sender
            elif m.sender_id is not None:
                third_party_ids.add(m.sender_id)  # a linked channel or an anonymous admin
            if m.forward is not None:
                if m.forward.from_id is not None:
                    third_party_ids.add(m.forward.from_id)
                if m.forward.from_name:
                    forward_names.add(m.forward.from_name)
            if m.post_author:
                forward_names.add(m.post_author)
            for e in m.entities:
                if e.url:
                    domains[_host(e.url)] += 1
            for url in _URL_IN_TEXT.findall(m.text):
                domains[_host(url)] += 1

    exported = {peer: raw_chats[peer] for lc, _ in loaded for peer in lc.peers}
    # Only a supergroup or channel username names a chat: the username of a
    # private or bot dialog is the person's (or bot's) own.
    chat_usernames = {raw_chats[peer].username.lower(): lc.primary.id for lc, _ in loaded for peer in lc.peers
                      if raw_chats[peer].username and raw_chats[peer].kind in (KIND_SUPERGROUP, KIND_CHANNEL)}
    org_terms: list[str] = []
    candidates: list[str] = []
    if policy.scrub_chat_titles and not policy.keep_chat_titles:
        org_terms, candidates = org_terms_from_titles(
            [_chat_title(lc, raw_chats) for lc, _ in loaded], policy.generic_title_share)
    org_all = (*org_terms, *policy.custom_terms)
    # A name is kept only if a scrubber without the people vocabulary leaves
    # it alone; the virtual ids in this roster are placeholders, the check
    # only asks whether the candidate changes. As everywhere, only the
    # operator's keep_terms protect a word: nothing derived from the export
    # is whitelisted by a guess.
    checker = Scrubber(policy, Roster(
        by_username=_username_vids(raw_users, chat_usernames, lambda _: "U0000", lambda _: "C0000"),
        chat_usernames=frozenset(chat_usernames),
        by_user_id={uid: "U0000" for uid in raw_users},
        known_ids=tuple((*raw_users, *exported, *third_party_ids)),
        org_terms=org_all,
        keep_terms=tuple(policy.keep_terms),
    ))
    given_names = Counter(fold(u.first_name.split()[0]) for u in raw_users.values() if u.first_name.split() and not u.is_bot)
    last_names = frozenset(fold(t) for u in raw_users.values() for t in (_surname_field(u), *split_free_text_name(u)[1]) if t)
    kept_names = {uid: display_name(u, policy.name_mode, checker, last_names, given_names) for uid, u in raw_users.items()}
    kept = frozenset(fold(n) for n in kept_names.values() if n and n != "Deleted")
    contacts = _contact_names(raw_chats, set(exported))
    person_terms = _person_terms(raw_users.values(), policy, forward_names, kept, given_names, contacts)
    # Dropping a name that shows somebody else's grows the vocabulary (a
    # forward header equal to a kept name stops being an exception), which
    # can expose one more such name. Each round blanks at least one name, so
    # the loop ends.
    while True:
        filtered = _drop_names_of_others(kept_names, raw_users, person_terms, policy)
        if filtered == kept_names:
            break
        kept_names = filtered
        kept = frozenset(fold(n) for n in kept_names.values() if n and n != "Deleted")
        person_terms = _person_terms(raw_users.values(), policy, forward_names, kept, given_names, contacts)
    kept_as_words: list[str] = []
    if policy.name_mode == "none":
        kept_as_words = sorted({u.first_name.split()[0] for u in raw_users.values()
                                if u.first_name.split() and fold(u.first_name.split()[0]) in FIRST_NAME_STOPWORDS})
    return Vocabulary(
        users=raw_users,
        chats=exported,
        chat_usernames=chat_usernames,
        third_party_ids=frozenset(third_party_ids - set(raw_users) - set(exported)),
        logical=loaded,
        person_terms=tuple(person_terms),
        org_terms=tuple(org_all),
        keep_term_candidates=_keep_term_suggestions(candidates, raw_users.values(), policy, given_names),
        forward_names=frozenset(forward_names),
        domains=domains,
        kept_names=kept_names,
        first_names_kept_as_words=tuple(kept_as_words),
    )


def _host(url: str) -> str:
    try:
        return (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+|(?<![\w@.])www\.[^\s<>\"')\]]+", re.IGNORECASE)

# An attachment extension: up to twelve ASCII letters and digits with at
# least one letter ("pdf", "7z", "m4a", "safetensors"), or a split-archive
# number ("001"). A longer tail, one with a space, an underscore or a
# non-Latin letter, is part of the file name, not an extension.
_FILE_EXTENSION = re.compile(r"(?=[a-z0-9]*[a-z])[a-z0-9]{1,12}|[0-9]{1,3}", re.IGNORECASE)


def _shown_extension(media: Media, scrubber: Scrubber) -> str:
    """The attachment extension the dataset may show. Telegram derives it
    from the file name, so a name whose last dot starts no real extension
    ("Счёт 12. Петров Иван", "договор.+79991234567", "скан.ivan_petrov")
    carries a surname, a phone or a username in that field - in every mode,
    since ``keep_file_names`` guards the name and not this. An extension is
    therefore kept only when it is shaped like one and the scrubber leaves it
    alone; failing that the MIME type supplies one ("pdf" instead of the
    surname), and failing that the field is dropped."""
    for candidate in (media.ext, (mimetypes.guess_extension(media.mime) or "").lstrip(".")):
        if candidate and _FILE_EXTENSION.fullmatch(candidate) and scrubber.scrub(candidate) == candidate:
            return candidate
    return ""


# --- main -----------------------------------------------------------------------------------

def anonymize(store: RawStore, mapping: Mapping, roles: Roles, policy: AnonPolicy) -> Dataset:
    """Build the dataset. The caller owns ``mapping`` and must ``save()`` it
    afterwards, otherwise the next run assigns fresh virtual ids."""
    vocab = vocabulary(store, policy)
    raw_users, raw_chats, loaded = vocab.users, store.chats(), vocab.logical
    exported_peers = set(vocab.chats)
    org_terms = [t for t in vocab.org_terms if t not in policy.custom_terms]
    # One virtual id per logical chat, resolved before anything is written:
    # every peer of a merged conversation, and a forward that names one of
    # them, renders as that id.
    chat_vids: dict[int, str] = {}
    for lc, _ in loaded:
        peers = (*lc.peers, lc.primary.id)
        chat_vids.update(dict.fromkeys(peers, mapping.chat_for(peers)))

    roster = Roster(
        by_username=vocab.username_vids(mapping.user, lambda cid: chat_vids.get(cid) or mapping.chat(cid)),
        chat_usernames=frozenset(vocab.chat_usernames),
        by_user_id={uid: mapping.user(uid) for uid in raw_users},
        known_ids=tuple(vocab.known_ids()),
        phones=tuple(sorted(vocab.phones())),
        person_terms=vocab.person_terms,
        org_terms=vocab.org_terms,
        keep_terms=tuple(policy.keep_terms),
    )
    scrubber = Scrubber(policy, roster)

    ds = Dataset()
    chats_per_sender: dict[int, set[str]] = defaultdict(set)
    dropped: Counter[str] = Counter()

    def ensure_user(uid: int, chat_vid: str) -> AnonUser:
        vid = mapping.user(uid)
        if vid not in ds.users:
            user = raw_users.get(uid) or RawUser(id=uid)
            role = roles.of(user)
            ds.users[vid] = AnonUser(vid=vid, name=vocab.kept_names.get(uid, ""), role=role, side=side_of(role))
        return ds.users[vid]

    def ensure_anonymous(peer_id: int) -> AnonUser:
        vid = mapping.user(peer_id)
        if vid not in ds.users:
            ds.users[vid] = AnonUser(vid=vid, name="", role=ROLE_ANONYMOUS, side=side_of(ROLE_ANONYMOUS))
        return ds.users[vid]

    def forwarded_label(m: RawMessage) -> Optional[str]:
        f = m.forward
        if f is None:
            return None
        if f.kind == FWD_USER and f.from_id is not None:
            if f.from_id in raw_users:
                return mapping.user(f.from_id)
            return "external_user"
        if f.kind in (FWD_CHAT, FWD_CHANNEL):
            if f.from_id in chat_vids:
                return chat_vids[f.from_id]
            return f"external_{f.kind}"
        return f.kind  # hidden / imported

    for lc, msgs in loaded:
        chat_vid = chat_vids[lc.primary.id]
        title = scrubber.scrub(lc.primary.title) if policy.keep_chat_titles else chat_vid
        chat = AnonChat(vid=chat_vid, title=title, kind=lc.primary.kind, is_forum=lc.primary.is_forum)
        ds.chats[chat_vid] = chat
        participants: dict[str, None] = {}
        for uid in lc.primary.participant_ids:
            participants[ensure_user(uid, chat_vid).vid] = None

        seq_of: dict[tuple[int, int], int] = {}
        seq = 0
        for m in msgs:
            if m.is_service and not policy.keep_service_messages:
                dropped["service"] += 1
                continue
            if not m.is_service and not m.text.strip() and m.media is None:
                dropped["empty"] += 1
                continue
            sender: Optional[str] = None
            if m.sender_kind == SENDER_USER and m.sender_id is not None:
                user = ensure_user(m.sender_id, chat_vid)
                if user.role == ROLE_BOT and not policy.keep_bot_messages:
                    dropped["bot"] += 1
                    continue
                sender, role = user.vid, user.role
                participants[user.vid] = None
                chats_per_sender[m.sender_id].add(chat_vid)
            elif m.sender_id is not None:
                user = ensure_anonymous(m.sender_id)
                sender, role = user.vid, user.role
            else:
                role = "system"
            seq += 1
            seq_of[(m.chat_id, m.id)] = seq

            forwarded = forwarded_label(m)
            if m.forward is not None and m.forward.kind == FWD_USER and m.forward.from_id in raw_users:
                ensure_user(m.forward.from_id, chat_vid)

            media = None
            if m.media is not None:
                media = {"kind": m.media.kind}
                ext = _shown_extension(m.media, scrubber)
                if ext:
                    media["ext"] = ext
                if m.media.size:
                    media["size"] = m.media.size
                if m.media.duration:
                    media["duration"] = m.media.duration
                if policy.keep_file_names and m.media.file_name:
                    media["name"] = scrubber.scrub(m.media.file_name)

            code_units = sum(e.length for e in m.entities if e.type in ("Pre", "Code"))
            ds.messages.append(AnonMessage(
                chat=chat_vid,
                seq=seq,
                date=m.date,
                sender=sender,
                role=role,
                side=side_of(role),
                text=scrubber.scrub(m.text, m.entities) if not m.is_service else "",
                reply_to=seq_of.get((m.chat_id, m.reply_to_id)) if m.reply_to_id is not None else None,
                topic=m.topic_id if lc.primary.is_forum else None,
                media=media,
                edited=m.edit_date is not None,
                forwarded=forwarded,
                action=m.action if m.is_service else None,
                code=bool(m.text) and code_units * 2 >= len(m.text),
            ))
        # Sorted by virtual id: ids are random, so the order in which Telegram
        # listed the members (creator, admins, recent activity) does not survive.
        chat.participants = sorted(participants)
        chat.message_count = seq

    suspects = []
    for uid, vids in chats_per_sender.items():
        user = raw_users.get(uid)
        if user and len(vids) >= SUSPECT_STAFF_MIN_CHATS and roles.of(user) not in STAFF_ROLES | {ROLE_BOT}:
            suspects.append({"vid": mapping.user(uid), "chats": len(vids), "role": roles.of(user)})
    ds.notes = {
        "suspect_staff": sorted(suspects, key=lambda s: -s["chats"]),
        "dropped_messages": dict(dropped),
        "merged_legacy_groups": sum(1 for lc, _ in loaded if len(lc.peers) > 1),
    }
    matched = roles.matched_entries(raw_users.values())
    ds.private = {
        "warning": "Contains raw tokens from the export. Do not share with the dataset.",
        "scrub": scrubber.report(),
        "domains": dict(vocab.domains.most_common(100)),
        "unmatched_staff_entries": sorted(str(e) for e in roles.configured() - matched),
        "org_terms_scrubbed": [t for t in org_terms if fold(t) not in {fold(k) for k in roster.keep_terms}],
        # Public chat usernames that were removed from text as a bare word,
        # not only after '@'. One that is a product term belongs in
        # keep_terms; the '@' form and t.me links are replaced either way.
        "chat_usernames_scrubbed_bare": sorted(u for u in scrubber.surfaces("bare_username")
                                               if u in vocab.chat_usernames),
        # Title words present in many chats: probably the product name, but a
        # guess (it can be a big client), so the operator confirms it by
        # adding it to keep_terms. Never written into the shareable manifest.
        "keep_terms_suggested": list(vocab.keep_term_candidates),
        # Real first names of participants, kept in text because they are also
        # ordinary words. Reported to the operator, never into the shareable
        # manifest: under ``name_mode = "none"`` it would publish exactly what
        # that mode promises to hide.
        "first_names_kept_as_words": list(vocab.first_names_kept_as_words),
        # Third-party names that entered the vocabulary from forward headers.
        "forward_names": sorted(vocab.forward_names)[:200],
    }

    _self_check(ds, vocab)
    return ds


def _self_check(ds: Dataset, vocab: Vocabulary) -> None:
    """High-precision check only (ids, @usernames, phones): a hit here is a bug,
    not a false positive, so it aborts the run. The fuzzier checks live in verify.

    The error names the kind and the virtual location of each hit but never
    quotes it: this is the line the operator pastes into a bug report, and
    the raw values travel on the exception for a private report instead."""
    scanner = LeakScanner(vocab.known(), regex_rules=False)
    leaks = []
    for location, text in ds.texts():
        for leak in scanner.scan(text, location):
            if leak.kind == "username" and not leak.match.startswith("@"):
                continue  # bare-word username hits are judged by verify
            leaks.append(leak)
    if leaks:
        sample = "; ".join(f"{l.kind} at {l.location}" for l in leaks[:10])
        raise AnonymizationError(f"{len(leaks)} raw identifiers survived scrubbing: {sample}", leaks)
