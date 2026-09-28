"""Command-line interface: the composition root.

    tg-collector login                 authorize the support account (creates the session)
    tg-collector chats [--refresh]     list dialogs and show which ones will be exported
    tg-collector export [--full] [--only ID ...] [--refresh]
    tg-collector anonymize
    tg-collector verify
    tg-collector run                   export + anonymize + verify

Every command reads ``.env`` (credentials) and ``config.toml`` (policy) from
the project directory (``--project``). Nothing here contains logic; it wires
the modules together and reports.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Optional

from .anonymize import AnonymizationError, Mapping, MappingError, anonymize
from .config import ConfigError, Settings
from .dataset import write_dataset
from .errors import ExportHalt
from .export import ChatDecision, InspectionCache, export, plan
from .model import Roles
from .rawstore import RawStore, restrict_private_paths, write_private_json
from .verify import verify


def _say(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _roles(settings: Settings, me_id: Optional[int]) -> Roles:
    return Roles.build(me_id, support=settings.staff.support, sales=settings.staff.sales, other=settings.staff.other)


async def _plan(src, settings: Settings, args) -> list[ChatDecision]:
    """The chat plan, reusing member lists an earlier `chats` or `export` saved."""
    me = await src.me()
    hours = settings.export.members_cache_hours
    cache = None
    if hours > 0:
        cache = InspectionCache(RawStore(settings.raw_dir), me.id, timedelta(hours=hours),
                                refresh=bool(getattr(args, "refresh", False)))
    return await plan(src, settings.chats, _roles(settings, me.id), cache=cache, log=_say)


def _print_plan(decisions: list[ChatDecision]) -> None:
    width = max((len(d.chat.title) for d in decisions), default=10)
    width = min(max(width, 10), 50)
    print(f"{'INCL':<5} {'ID':<16} {'KIND':<11} {'MEMB':>5}  {'TITLE':<{width}}  REASON")
    for d in decisions:
        title = d.chat.title[:width]
        memb = d.chat.participant_count if d.chat.participant_count is not None else len(d.participants) or ""
        print(f"{'yes' if d.included else '-':<5} {d.chat.id:<16} {d.chat.kind:<11} {memb!s:>5}  {title:<{width}}  {d.reason}")
    inc = sum(1 for d in decisions if d.included)
    _say(f"\n{inc} of {len(decisions)} dialogs selected for export")


# --- commands ------------------------------------------------------------------------

async def cmd_login(settings: Settings, args) -> int:
    from .telegram import TelegramSource
    async with TelegramSource(settings.telegram, settings.export, interactive=True) as src:
        me = await src.login(qr=bool(getattr(args, "qr", False)))
    _say(f"Logged in as {me.display_name} (@{me.username}) id={me.id}; session: {settings.telegram.session}")
    return 0


async def cmd_chats(settings: Settings, args) -> int:
    from .telegram import TelegramSource
    async with TelegramSource(settings.telegram, settings.export) as src:
        decisions = await _plan(src, settings, args)
    _print_plan(decisions)
    return 0


async def cmd_export(settings: Settings, args) -> int:
    from .telegram import TelegramSource
    store = RawStore(settings.raw_dir)
    async with TelegramSource(settings.telegram, settings.export) as src:
        decisions = await _plan(src, settings, args)
        report = await export(
            src, store, decisions, settings.export, log=_say,
            full=bool(getattr(args, "full", False)), only=getattr(args, "only", None),
        )
    _say(f"Export finished: {report.chats} chats, {report.messages} new messages, {report.users} users seen")
    if report.failures:
        _say(f"{len(report.failures)} chats failed (re-run export to resume):")
        for cid, err in report.failures.items():
            _say(f"  {cid}: {err}")
        return 2
    return 0


def cmd_anonymize(settings: Settings, args) -> int:
    store = RawStore(settings.raw_dir)
    if not store.exists():
        _say(f"No raw export found in {settings.raw_dir}. Run: tg-collector export")
        return 1
    me_id = _me_id(store)
    try:
        mapping = Mapping.load(settings.mapping_path)
        ds = anonymize(store, mapping, _roles(settings, me_id), settings.anon)
    except MappingError as exc:
        _say(f"Mapping error: {exc}")
        return 1
    except AnonymizationError as exc:
        _say(f"ABORTED: {exc}")
        if exc.leaks:
            path = settings.anon_dir / "anonymize_abort.json"
            write_private_json(path, {
                "warning": "SECRET: raw identifiers that survived scrubbing. Never share or paste them.",
                "leaks": [{"kind": l.kind, "match": l.match, "location": l.location} for l in exc.leaks[:2000]],
            })
            _say(f"The raw matches (SECRET) are in {path}; report the abort without them.")
        return 3
    mapping.save()
    report = write_dataset(ds, settings.dataset_dir, settings.output, settings.public_snapshot())
    private_path = settings.anon_dir / "anonymize_report.json"
    write_private_json(private_path, ds.private)
    _say(f"Dataset written to {settings.dataset_dir}: {len(ds.chats)} chats, {len(ds.users)} users, "
         f"{report.messages} messages, {report.transcript_parts} transcript parts, {report.chunks} chunks")
    _say(f"Mapping (SECRET) saved to {settings.mapping_path}; scrub report (private) in {private_path}")
    notes = ds.notes
    suggested = ds.private.get("keep_terms_suggested") or []
    if suggested:
        _say("Words found in the titles of many chats were scrubbed as <org> everywhere: " + ", ".join(suggested))
        _say("  If one of them is your product or company name, add it to keep_terms in the [anonymize] "
             "section of config.toml and re-run anonymize. Never add a client's name there.")
    scrubbed = ds.private.get("org_terms_scrubbed") or []
    if scrubbed:
        shown = ", ".join(scrubbed[:40]) + (f" ... ({len(scrubbed)} in total, see the scrub report)" if len(scrubbed) > 40 else "")
        _say("Chat-title terms scrubbed as <org> (add product words to keep_terms): " + shown)
    bare_usernames = ds.private.get("chat_usernames_scrubbed_bare") or []
    if bare_usernames:
        _say("Public chat usernames removed from text as a bare word as well: " + ", ".join(bare_usernames))
        _say("  If one of them is a product or API term, add it to keep_terms; '@' mentions and t.me links "
             "of that chat are replaced either way. Never add a client's name there.")
    kept_as_words = ds.private.get("first_names_kept_as_words") or []
    if kept_as_words:
        _say("First names that are ordinary words and stay in text under name_mode=none: "
             + ", ".join(kept_as_words))
    if ds.private.get("unmatched_staff_entries"):
        _say("Configured [staff] entries that matched nobody in the export: "
             + ", ".join(ds.private["unmatched_staff_entries"]))
    if notes.get("suspect_staff"):
        _say("Users present in several chats but not configured as staff (check [staff] in config.toml):")
        for s in notes["suspect_staff"]:
            _say(f"  {s['vid']} ({s['role']}) in {s['chats']} chats")
    return 0


def _me_id(store: RawStore) -> Optional[int]:
    me = store.me_id()
    if me is None:
        _say("Warning: the raw export does not record the exporting account; "
             "configure [staff] support explicitly so the support role is assigned.")
    return me


def cmd_verify(settings: Settings, args) -> int:
    store = RawStore(settings.raw_dir)
    if not (settings.dataset_dir / "manifest.json").exists():
        _say(f"No dataset in {settings.dataset_dir}. Run: tg-collector anonymize")
        return 1
    if not store.exists():
        # Every identifier to hunt for comes from the raw export; without it
        # the audit would find nothing and certify the dataset falsely.
        _say(f"No raw export found in {settings.raw_dir}; verify needs it to hunt for raw ids, "
             "usernames, phones and names. Run: tg-collector export")
        return 1
    report_path = settings.anon_dir / "verify_report.json"
    report = verify(settings.dataset_dir, store, settings.anon, report_path)
    if report.ok:
        _say(f"OK: no leaks found in {report.files_scanned} files")
        return 0
    _say(f"{len(report.leaks)} possible leaks in {report.files_scanned} files: {report.by_kind()}")
    for leak in report.leaks[:40]:
        _say(f"  [{leak.kind}] {leak.match!r} at {leak.location}")
    if len(report.leaks) > 40:
        _say(f"  ... see {report_path}")
    _say("Review the matches: tune [anonymize] keep_terms / custom_terms / custom_patterns and re-run anonymize.")
    _say("The matches above quote raw data: do not paste them into an issue or a chat.")
    return 4


async def cmd_run(settings: Settings, args) -> int:
    rc = await cmd_export(settings, args)
    if rc not in (0, 2):
        return rc
    rc2 = cmd_anonymize(settings, args)
    if rc2:
        return rc2
    return cmd_verify(settings, args) or rc


# --- entry point ------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tg-collector", description="Export Telegram support chats and anonymize them.")
    p.add_argument("--project", default=".", help="directory with .env and config.toml (default: current)")
    p.add_argument("--config", help="path to config.toml (default: <project>/config.toml)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    lg = sub.add_parser("login", help="authorize the Telegram account interactively")
    lg.add_argument("--qr", action="store_true", help="log in by scanning a QR code in the official app (no login code needed)")
    c = sub.add_parser("chats", help="list dialogs and the export decision for each")
    e = sub.add_parser("export", help="export raw messages (incremental)")
    e.add_argument("--full", action="store_true", help="re-export selected chats from scratch")
    e.add_argument("--only", type=int, nargs="+", metavar="ID", help="export only these chat ids")
    sub.add_parser("anonymize", help="build the anonymized dataset from the raw export")
    sub.add_parser("verify", help="scan the dataset for leaked identifiers")
    r = sub.add_parser("run", help="export, anonymize and verify")
    r.add_argument("--full", action="store_true")
    r.add_argument("--only", type=int, nargs="+", metavar="ID")
    for cmd in (c, e, r):
        cmd.add_argument("--refresh", action="store_true",
                         help="ask Telegram for every member list again instead of reusing saved ones")
    return p


COMMANDS = {
    "login": cmd_login, "chats": cmd_chats, "export": cmd_export,
    "anonymize": cmd_anonymize, "verify": cmd_verify, "run": cmd_run,
}


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    # Everything the tool writes is for the operator only: the session, the
    # raw export, the mapping, the reports, and the dataset until the
    # operator copies it somewhere to share it. The umask keeps new files
    # private; restrict_private_paths below repairs the tool's own paths
    # when an older version left them readable.
    os.umask(0o077)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    # Telethon sleeps through flood waits below flood_sleep_threshold itself and
    # reports them only at INFO; show them so a long silent pause is explained.
    if not args.verbose:
        logging.getLogger("telethon.client.users").setLevel(logging.INFO)
    try:
        settings = Settings.load(Path(args.project), config_path=args.config)
        restrict_private_paths(
            settings.raw_dir, settings.anon_dir, settings.data_dir / "session",
            session=settings.telegram.session,
        )
        handler = COMMANDS[args.command]
        result = handler(settings, args)
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)
        return int(result)
    except ConfigError as exc:
        _say(f"Config error: {exc}")
        return 1
    except KeyboardInterrupt:
        _say("Interrupted")
        return 130
    except ExportHalt as exc:  # session/account/takeout conditions the operator must handle
        _say(f"STOPPED: {exc}")
        return 2
