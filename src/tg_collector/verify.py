"""Leak audit of a written dataset directory.

``verify(dataset_dir, store, policy)`` scans every file the dataset contains
for anything that ties it back to Telegram or to real people: raw user/chat
ids, usernames (of people and of exported public chats), phone numbers, last
names and full names, chat titles, plus the scrubber's regex classes
(emails, links, cards, tokens ...). It returns a
``VerifyReport``; the CLI turns a non-empty report into a non-zero exit.

Unlike the anonymizer's fail-fast self-check, this pass is deliberately
fuzzy (names, title tokens, regex classes) and may produce false positives;
the report shows the exact matches so the operator can judge them and tune
``keep_terms`` / ``custom_terms``.

Every file under the directory is scanned, whoever wrote it. JSON files are
scanned as decoded strings (every string and every dict key of every row),
so the scanner sees exactly the text the scrubber saw; any other file is
scanned line by line. The dataset's own README is the one exception, and
only while it is unchanged: it names every placeholder.

People's names and chat-title terms are hunted only where the dataset
carries scrubbed free text: message text, attachment names and extensions,
chat titles, and (for chat-title terms only) the kept display names.
Everything else - the writer's own fields (roles, sides, policy values) and
the transcripts, which repeat those JSON fields around fixed English labels
- is scanned for raw ids, usernames, phone numbers and the regex classes.
Otherwise a surname or title word that transliterates onto a label
("Бот" -> "BOT", "Формат" -> "Line format", "Форум" -> "Forum chat") would flag every
file of a clean dataset, and the only remedy, ``keep_terms``, would stop
scrubbing that word. A transcript line is scanned in the parts the writer
composed it from, so its own layout never glues a keyword to the next
part's value.
"""

from __future__ import annotations

import dataclasses
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Iterator, Optional

from .config import AnonPolicy
from .rawstore import RawStore, write_private_json
from .anonymize import forward_surnames, vocabulary
from .dataset import (
    CHUNK_INDEX, COMPOSED_JSON_KEYS, DATASET_README, DISPLAY_NAME_KEY, FORMAT_VERSION, TRANSCRIPT_DIRS,
    is_own_file_name, split_transcript_line,
)
from .scrub import Known, Leak, LeakScanner, Roster, Scrubber, fold


@dataclass
class VerifyReport:
    files_scanned: int = 0
    leaks: list[Leak] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.leaks

    def by_kind(self) -> dict[str, int]:
        return dict(Counter(l.kind for l in self.leaks))

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "files_scanned": self.files_scanned,
            "leaks_by_kind": self.by_kind(),
            "leaks": [{"kind": l.kind, "match": l.match, "location": l.location} for l in self.leaks[:2000]],
        }


def known_from_store(store: RawStore, policy: AnonPolicy) -> Known:
    """Raw identifiers to hunt for, derived from the same vocabulary the
    scrubber used: every person term it removes (a short surname inside a
    kept given name, "Ким" in "Аким", included) and exactly the exceptions
    it makes, the operator's keep_terms (title words suggested for keep_terms
    are still hunted). Kept display names are no exception: ``verify`` does
    not hunt people's names in the fields that show them on purpose - the
    anonymizer has already dropped every display name the vocabulary spells.

    A forward author's surname on its own is hunted only under
    ``scrub_last_names``: the scrubber removes the ones spelled like a
    surname, and the operator judges the rest ("Иван Коваль")."""
    vocab = vocabulary(store, policy)
    kept_folded = {fold(n) for n in vocab.kept_names.values() if n and n != "Deleted"}
    names = set(vocab.person_terms)
    first_names = {fold(u.first_name.split()[0]) for u in vocab.users.values() if u.first_name.split()}
    if policy.scrub_last_names:
        names |= set(forward_surnames(vocab.forward_names, kept_folded, first_names).values())
    return dataclasses.replace(
        vocab.known(),
        names=frozenset(names),
        titles=frozenset(vocab.org_terms),
        keep_terms=frozenset(policy.keep_terms),
        card_bins=frozenset(policy.card_bins),
    )


def _strings(value: Any, path: str) -> Iterator[tuple[str, str, bool]]:
    """Every string of a decoded JSON value - leaves and dict keys alike -
    with its dotted path and whether it is a key. A key carries data as
    readily as a value: another tool's export may well index by name."""
    if isinstance(value, str):
        yield path, value, False
    elif isinstance(value, dict):
        for k, v in value.items():
            child = f"{path}.{k}" if path else str(k)
            yield child, k, True
            yield from _strings(v, child)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")


# What a scanned string is, which decides the vocabulary hunted in it.
_TEXT = "text"                  # scrubbed free text: every check
_DISPLAY_NAME = "display_name"  # a kept display name: every check but people's names
_COMPOSED = "composed"          # written by the dataset writer: no names, no title terms


def _json_kind(rel: str, key: str, is_key: bool) -> str:
    """Which vocabulary a JSON string is hunted with. ``dataset`` names the
    strings its writer composes; every other string in a dataset is free
    text, whichever tool wrote the file."""
    if rel == CHUNK_INDEX:
        return _COMPOSED
    composed = COMPOSED_JSON_KEYS.get(rel)
    if composed is None:
        return _TEXT            # a file the writer does not produce: all free text
    if is_key:
        return _COMPOSED        # virtual ids and the writer's own field names
    if rel == "users.json" and DISPLAY_NAME_KEY.fullmatch(key):
        return _DISPLAY_NAME
    return _COMPOSED if composed.fullmatch(key) else _TEXT


def _lines(path: Path) -> Iterator[tuple[int, str]]:
    """Physical lines of a file that may well not be text at all: an
    unreadable byte is replaced rather than ending the audit."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            yield lineno, line.rstrip("\n")


def _units(path: Path, rel: str) -> Iterator[tuple[str, str, str]]:
    """(location, text, kind) triples to scan: decoded JSON strings for
    .json/.jsonl, physical lines otherwise. A row or file that is not valid
    JSON is scanned raw as free text. A transcript line is scanned in the
    parts the writer composed it from - everything it quotes is audited in
    the JSON files - so no keyword of one part claims a value out of the
    next."""
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        for lineno, line in _lines(path):
            try:
                row = json.loads(line)
            except ValueError:
                yield f"{rel}:{lineno}", line, _TEXT
                continue
            for key, text, is_key in _strings(row, ""):
                yield f"{rel}:{lineno}:{key}", text, _json_kind(rel, key, is_key)
        return
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except ValueError:
            data = None
        if data is not None:
            for key, text, is_key in _strings(data, ""):
                if rel == CHUNK_INDEX and is_own_file_name(text):
                    continue
                yield f"{rel}:{key}", text, _json_kind(rel, key, is_key)
            return
    if suffix == ".md" and PurePath(rel).parts[0] in TRANSCRIPT_DIRS:
        for lineno, line in _lines(path):
            for part in split_transcript_line(line):
                yield f"{rel}:{lineno}", part, _COMPOSED
        return
    for lineno, line in _lines(path):
        yield f"{rel}:{lineno}", line, _TEXT


def verify(dataset_dir: Path, store: RawStore, policy: AnonPolicy, report_path: Optional[Path] = None) -> VerifyReport:
    """Scan every file under ``dataset_dir``. The report (which quotes the
    leaking text) is written to ``report_path``, outside the dataset, with
    mode 600 like every other private file.

    Raises ``FileNotFoundError`` when the raw export is gone: every raw id,
    username, phone and name to hunt for comes from it, so a scan without it
    would find nothing and certify the dataset falsely. Deleting the export
    is a sound privacy step, but it has to come after the audit."""
    dataset_dir = Path(dataset_dir)
    if not store.exists():
        raise FileNotFoundError(f"no raw export in {store.root}: verify needs it to hunt for raw ids, "
                                "usernames, phones and names")
    known = known_from_store(store, policy)
    url_policy = Scrubber(policy, Roster(keep_terms=tuple(known.keep_terms)))

    def scanner(known: Known) -> LeakScanner:
        return LeakScanner(known, url_allowed=lambda url: url_policy.url_placeholder(url) == url,
                           domain_allowed=lambda host: url_policy.domain_placeholder(host) == host,
                           custom_patterns=policy.custom_patterns)

    scanners = {
        _TEXT: scanner(known),
        _DISPLAY_NAME: scanner(dataclasses.replace(known, names=frozenset())),
        _COMPOSED: scanner(dataclasses.replace(known, names=frozenset(), titles=frozenset())),
    }
    report = VerifyReport()
    # A scan is a pure function of the text and the scanner, and a dataset
    # repeats both: the chunk files are verbatim copies of the transcripts,
    # and the composed JSON strings (roles, sides, chat ids) recur on every
    # row. Each distinct pair is therefore scanned once and the leaks are
    # reported again under each location they were found at.
    scanned: dict[tuple[str, str], list[Leak]] = {}
    own_readme = DATASET_README.format(version=FORMAT_VERSION)
    for path in sorted(p for p in dataset_dir.rglob("*") if p.is_file()):
        rel = str(path.relative_to(dataset_dir))
        # The dataset's own format description is the only file skipped, and
        # only while it is untouched: it names every placeholder, so scanning
        # it would report the vocabulary back at the operator.
        if rel == "README.md" and path.read_text(encoding="utf-8", errors="replace") == own_readme:
            continue
        report.files_scanned += 1
        for location, text, kind in _units(path, rel):
            leaks = scanned.get((kind, text))
            if leaks is None:
                leaks = scanned[kind, text] = scanners[kind].scan(text)
            report.leaks.extend(dataclasses.replace(leak, location=location) for leak in leaks)
    report_path = Path(report_path) if report_path else dataset_dir.parent / "verify_report.json"
    write_private_json(report_path, report.to_json())
    return report
