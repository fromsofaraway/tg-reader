"""Configuration: secrets from ``.env``, policy from ``config.toml``.

``Settings.load(project_dir)`` is the only entry point. It hides file lookup,
parsing, defaults and validation, and returns an immutable ``Settings`` tree.
Missing files are fine: every policy field has a sensible default and only the
Telegram credentials are required (and only when a command talks to Telegram).
A section or setting the tool does not know is an error, not a default: a
misspelled privacy switch must never pass for "not configured".
"""

from __future__ import annotations

import difflib
import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Iterable, Optional

from .model import CHAT_KINDS, KIND_GROUP, KIND_SUPERGROUP

NAME_MODES = ("first", "full", "none")
URL_MODES = ("drop", "domain", "keep")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Telegram:
    api_id: Optional[int] = None
    api_hash: str = ""
    phone: str = ""
    session: Path = Path("data/session/support")

    def require(self) -> "Telegram":
        missing = [k for k, v in (("TG_API_ID", self.api_id), ("TG_API_HASH", self.api_hash)) if not v]
        if missing:
            raise ConfigError(
                "Missing Telegram credentials: " + ", ".join(missing)
                + ". Put them into .env (see .env.example); get them at https://my.telegram.org."
            )
        return self


@dataclass(frozen=True)
class ChatFilter:
    include_types: frozenset[str] = frozenset({KIND_GROUP, KIND_SUPERGROUP})
    include_ids: frozenset[int] = frozenset()
    exclude_ids: frozenset[int] = frozenset()
    exclude_title_regex: tuple[str, ...] = ()
    include_archived: bool = True
    exclude_internal: bool = True  # skip chats where every member is staff/bot

    def title_excluded(self, title: str) -> bool:
        return any(re.search(p, title, re.IGNORECASE) for p in self.exclude_title_regex)


@dataclass(frozen=True)
class Staff:
    support: tuple[str | int, ...] = ()
    sales: tuple[str | int, ...] = ()
    other: tuple[str | int, ...] = ()  # colleagues who mostly read along


@dataclass(frozen=True)
class AnonPolicy:
    name_mode: str = "first"
    keep_chat_titles: bool = False
    keep_service_messages: bool = False
    url_mode: str = "drop"
    allow_domains: tuple[str, ...] = ()
    keep_terms: tuple[str, ...] = ()       # never scrubbed (product names)
    custom_terms: tuple[str, ...] = ()     # always scrubbed as <org>
    custom_patterns: tuple[str, ...] = ()  # regexes scrubbed as <redacted>
    scrub_last_names: bool = True
    scrub_chat_titles: bool = True
    keep_bot_messages: bool = True
    keep_file_names: bool = False  # attachment names, scrubbed like text
    # Card BINs (first 6 digits) of the product's own cards. Card numbers are
    # always masked to "BIN**********"; numbers starting with these BINs are
    # recognised even when mistyped or already partly masked by hand.
    card_bins: tuple[str, ...] = ()
    scrub_domains: bool = True  # bare domains ("acme.ru") become <domain>; allow_domains are kept
    # A title word present in at least this share of chat titles (and in at
    # least 3 titles) is probably the product name: the run suggests it for
    # keep_terms. It is scrubbed like every title word until it is added there.
    generic_title_share: float = 0.2


@dataclass(frozen=True)
class Output:
    timezone: str = "UTC"
    episode_gap_hours: float = 6.0
    max_chars: int = 200_000       # transcript part / chunk size; 0 disables splitting and chunks
    max_message_chars: int = 2000  # longer messages are shortened in transcripts (JSONL keeps them whole)
    turn_merge_seconds: int = 120  # consecutive messages of one sender within this window render as one turn


@dataclass(frozen=True)
class ExportTuning:
    """Pacing. Defaults are deliberately slow: the account must never look
    like an abusive client. A full first export may take hours or days."""

    wait_time: float = 1.0            # seconds between history pages (100 messages each)
    chat_wait: float = 3.0            # seconds before starting the next chat's history
    participants_wait: float = 2.0    # seconds between member-list / full-info requests
    flood_sleep_threshold: int = 3600 # honour FloodWait automatically up to this many seconds
    max_flood_wait: int = 7200        # a longer FloodWait stops the run (resume later)
    max_retries: int = 5              # transient network/server errors per chat before giving up
    flush_every: int = 500
    takeout: bool = False             # read history through Telegram's official data-export session


@dataclass(frozen=True)
class Settings:
    project_dir: Path
    data_dir: Path
    telegram: Telegram = field(default_factory=Telegram)
    chats: ChatFilter = field(default_factory=ChatFilter)
    staff: Staff = field(default_factory=Staff)
    anon: AnonPolicy = field(default_factory=AnonPolicy)
    output: Output = field(default_factory=Output)
    export: ExportTuning = field(default_factory=ExportTuning)

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def anon_dir(self) -> Path:
        return self.data_dir / "anon"

    @property
    def dataset_dir(self) -> Path:
        return self.anon_dir / "dataset"

    @property
    def mapping_path(self) -> Path:
        return self.anon_dir / "mapping.json"

    @classmethod
    def load(
        cls,
        project_dir: Path | str = ".",
        config_path: Optional[Path | str] = None,
        env_path: Optional[Path | str] = None,
    ) -> "Settings":
        project_dir = Path(project_dir).resolve()
        env = dict(os.environ)
        env.update(_read_env_file(Path(env_path) if env_path else project_dir / ".env"))
        if config_path and not Path(config_path).exists():
            raise ConfigError(f"config file not found: {config_path}")
        cfg = _sections(_read_toml(Path(config_path) if config_path else project_dir / "config.toml"))

        data_dir = Path(env.get("TG_DATA_DIR") or "data")
        if not data_dir.is_absolute():
            data_dir = project_dir / data_dir
        session = Path(env.get("TG_SESSION") or "data/session/support")
        if not session.is_absolute():
            session = project_dir / session

        api_id_raw = (env.get("TG_API_ID") or "").strip()
        if api_id_raw and not api_id_raw.isdigit():
            raise ConfigError("TG_API_ID must be an integer")

        return cls(
            project_dir=project_dir,
            data_dir=data_dir,
            telegram=Telegram(
                api_id=int(api_id_raw) if api_id_raw else None,
                api_hash=(env.get("TG_API_HASH") or "").strip(),
                phone=(env.get("TG_PHONE") or "").strip(),
                session=session,
            ),
            chats=_chat_filter(cfg["chats"]),
            staff=_staff(cfg["staff"]),
            anon=_anon(cfg["anonymize"]),
            output=_output(cfg["output"]),
            export=_export(cfg["export"]),
        )

    def public_snapshot(self) -> dict[str, Any]:
        """Policy fields safe to embed in the shareable manifest (no secrets, no paths, no ids)."""
        return {
            "chats": {
                "include_types": sorted(self.chats.include_types),
                "include_archived": self.chats.include_archived,
                "exclude_internal": self.chats.exclude_internal,
            },
            "anonymize": {
                "name_mode": self.anon.name_mode,
                "keep_chat_titles": self.anon.keep_chat_titles,
                "keep_service_messages": self.anon.keep_service_messages,
                "url_mode": self.anon.url_mode,
                "scrub_last_names": self.anon.scrub_last_names,
                "scrub_chat_titles": self.anon.scrub_chat_titles,
            },
            "output": {
                "timezone": self.output.timezone,
                "episode_gap_hours": self.output.episode_gap_hours,
                "max_chars": self.output.max_chars,
                "max_message_chars": self.output.max_message_chars,
                "turn_merge_seconds": self.output.turn_merge_seconds,
            },
        }


# --- parsing helpers -------------------------------------------------------

def _read_env_file(path: Path) -> dict[str, str]:
    """Minimal .env reader: KEY=VALUE lines, '#' comments, optional quotes."""
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key.strip()] = value
    return result


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc


class _Section:
    """One ``[name]`` table of config.toml, with typed readers.

    Every reader names both the section and the key in its error, so a
    message reads ``[anonymize] keep_terms must be ...`` and a key never
    looks like a section of its own.
    """

    def __init__(self, name: str, data: dict[str, Any]):
        self.name = name
        self.data = data

    def _bad(self, key: str, expected: str, value: Any) -> ConfigError:
        return ConfigError(f"[{self.name}] {key} must be {expected}, got {value!r}")

    def str_list(self, key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
        value = self.data.get(key, list(default))
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise self._bad(key, "a list of strings", value)
        return tuple(value)

    def id_list(self, key: str) -> frozenset[int]:
        value = self.data.get(key, [])
        if not isinstance(value, list):
            raise self._bad(key, "a list of integer chat ids", value)
        out: set[int] = set()
        for v in value:
            if isinstance(v, bool) or not isinstance(v, (int, str)) or (isinstance(v, str) and not v.lstrip("-").isdigit()):
                raise ConfigError(f"[{self.name}] {key}: {v!r} is not an integer chat id")
            out.add(int(v))
        return frozenset(out)

    def people(self, key: str) -> tuple[str | int, ...]:
        value = self.data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in value):
            raise self._bad(key, "a list of usernames or user ids", value)
        return tuple(value)

    def flag(self, key: str, default: bool) -> bool:
        value = self.data.get(key, default)
        if not isinstance(value, bool):
            raise self._bad(key, "true or false (unquoted)", value)
        return value

    def number(self, key: str, default: float, integer: bool = False) -> float | int:
        value = self.data.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise self._bad(key, "a number", value)
        return int(value) if integer else float(value)

    def choice(self, key: str, choices: tuple[str, ...], default: str) -> str:
        value = self.data.get(key, default)
        if value not in choices:
            raise self._bad(key, f"one of {choices}", value)
        return value


# Every setting of a section is a field of its dataclass under the same name,
# which is what makes the settings below the single list of what config.toml
# may contain.
_SECTION_TYPES: dict[str, type] = {
    "chats": ChatFilter,
    "staff": Staff,
    "anonymize": AnonPolicy,
    "output": Output,
    "export": ExportTuning,
}


def _did_you_mean(name: str, candidates: Iterable[str], shown: str = "{}") -> str:
    close = difflib.get_close_matches(name, sorted(candidates), n=1, cutoff=0.6)
    return f"; did you mean {shown.format(close[0])}?" if close else ""


def _sections(cfg: dict[str, Any]) -> dict[str, _Section]:
    """Split a parsed config.toml into its sections, rejecting any name the
    tool does not know.

    An ignored name is a privacy hole, not a harmless typo: ``[anonymise]``
    or ``keep_term`` silently turns a scrubbing policy back to its default,
    and the run then keeps in the dataset what the operator meant to remove.
    Each error names the closest setting that does exist.
    """
    known = {name: frozenset(f.name for f in fields(cls)) for name, cls in _SECTION_TYPES.items()}
    for name, body in cfg.items():
        if not isinstance(body, dict):
            raise ConfigError(f"{name} is outside any section; every setting belongs in one of: "
                              + ", ".join(f"[{s}]" for s in known))
        if name not in known:
            raise ConfigError(f"[{name}] is not a config section (valid: "
                              + ", ".join(f"[{s}]" for s in known) + ")"
                              + _did_you_mean(name, known, "[{}]"))
        for key in body:
            if key in known[name]:
                continue
            elsewhere = [s for s, keys in known.items() if key in keys]
            if elsewhere:
                raise ConfigError(f"[{name}] {key} is not a setting there; it belongs in [{elsewhere[0]}]")
            raise ConfigError(f"[{name}] {key} is not a setting{_did_you_mean(key, known[name])}")
    return {name: _Section(name, cfg.get(name, {})) for name in known}


def _chat_filter(s: _Section) -> ChatFilter:
    types = frozenset(s.str_list("include_types", (KIND_GROUP, KIND_SUPERGROUP)))
    unknown = types - CHAT_KINDS
    if unknown:
        raise ConfigError(f"[chats] include_types: unknown kinds {sorted(unknown)}; valid: {sorted(CHAT_KINDS)}")
    for p in s.str_list("exclude_title_regex"):
        try:
            re.compile(p)
        except re.error as exc:
            raise ConfigError(f"[chats] exclude_title_regex {p!r}: {exc}") from exc
    return ChatFilter(
        include_types=types,
        include_ids=s.id_list("include_ids"),
        exclude_ids=s.id_list("exclude_ids"),
        exclude_title_regex=s.str_list("exclude_title_regex"),
        include_archived=s.flag("include_archived", True),
        exclude_internal=s.flag("exclude_internal", True),
    )


def _staff(s: _Section) -> Staff:
    return Staff(support=s.people("support"), sales=s.people("sales"), other=s.people("other"))


def _anon(s: _Section) -> AnonPolicy:
    for p in s.str_list("custom_patterns"):
        try:
            compiled = re.compile(p)
        except re.error as exc:
            raise ConfigError(f"[anonymize] custom_patterns {p!r}: {exc}") from exc
        # A pattern that matches nothing at all would fire between every pair
        # of characters and replace the whole message with placeholders.
        if compiled.fullmatch("") is not None:
            raise ConfigError(f"[anonymize] custom_patterns {p!r} matches the empty string; "
                              "anchor the value, e.g. '\\d+' instead of '\\d*'")
    share = s.number("generic_title_share", 0.2)
    if not 0 < share <= 1:
        raise ConfigError("[anonymize] generic_title_share must be in (0, 1]")
    bins = []
    raw_bins = s.data.get("card_bins", [])
    if not isinstance(raw_bins, list):
        raise ConfigError(f"[anonymize] card_bins must be a list of 6-8 digit BINs, got {raw_bins!r}")
    for b in raw_bins:
        if isinstance(b, bool) or not isinstance(b, (int, str)) or not re.fullmatch(r"\d{6,8}", str(b).strip()):
            raise ConfigError(f"[anonymize] card_bins: {b!r} is not a 6-8 digit BIN")
        bins.append(str(b).strip())
    return AnonPolicy(
        name_mode=s.choice("name_mode", NAME_MODES, "first"),
        keep_chat_titles=s.flag("keep_chat_titles", False),
        keep_service_messages=s.flag("keep_service_messages", False),
        url_mode=s.choice("url_mode", URL_MODES, "drop"),
        allow_domains=tuple(d.lower().strip() for d in s.str_list("allow_domains")),
        keep_terms=s.str_list("keep_terms"),
        custom_terms=s.str_list("custom_terms"),
        custom_patterns=s.str_list("custom_patterns"),
        scrub_last_names=s.flag("scrub_last_names", True),
        scrub_chat_titles=s.flag("scrub_chat_titles", True),
        keep_bot_messages=s.flag("keep_bot_messages", True),
        keep_file_names=s.flag("keep_file_names", False),
        card_bins=tuple(bins),
        scrub_domains=s.flag("scrub_domains", True),
        generic_title_share=share,
    )


def _output(s: _Section) -> Output:
    tz = str(s.data.get("timezone", "UTC"))
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(tz)
    except Exception as exc:  # ZoneInfoNotFoundError or invalid key
        raise ConfigError(f"[output] timezone {tz!r} is not a valid IANA zone") from exc
    gap = s.number("episode_gap_hours", 6.0)
    if gap <= 0:
        raise ConfigError("[output] episode_gap_hours must be positive")
    return Output(
        timezone=tz,
        episode_gap_hours=gap,
        max_chars=max(0, s.number("max_chars", 200_000, integer=True)),
        max_message_chars=max(0, s.number("max_message_chars", 2000, integer=True)),
        turn_merge_seconds=max(0, s.number("turn_merge_seconds", 120, integer=True)),
    )


def _export(s: _Section) -> ExportTuning:
    tuning = ExportTuning(
        wait_time=s.number("wait_time", 1.0),
        chat_wait=s.number("chat_wait", 3.0),
        participants_wait=s.number("participants_wait", 2.0),
        flood_sleep_threshold=s.number("flood_sleep_threshold", 3600, integer=True),
        max_flood_wait=s.number("max_flood_wait", 7200, integer=True),
        max_retries=s.number("max_retries", 5, integer=True),
        flush_every=max(1, s.number("flush_every", 500, integer=True)),
        takeout=s.flag("takeout", False),
    )
    if min(tuning.wait_time, tuning.chat_wait, tuning.participants_wait) < 0:
        raise ConfigError("[export] wait times must be non-negative")
    return tuning
