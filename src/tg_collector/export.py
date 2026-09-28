"""Chat selection and incremental raw export.

Two entry points:

``plan(source, chat_filter, roles)``
    Lists every dialog, applies the configured filter and returns one
    ``ChatDecision`` per dialog saying whether it will be exported and why.
    Candidates are inspected once (members + lineage): the member list feeds
    the "internal chat" rule and is kept on the decision so ``export`` does
    not fetch it twice, and a supergroup's legacy group is attached as an
    extra peer even when it no longer appears in the dialog list.

``export(source, store, decisions, tuning, log)``
    Pulls messages newer than the store's cursor for every included chat
    (and for legacy groups merged into an included supergroup), records
    senders and members, and returns an ``ExportReport``. Safe to re-run:
    it resumes from the cursor; ``full=True`` re-exports from scratch.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .config import ChatFilter, ExportTuning
from .errors import ExportHalt
from .model import KIND_GROUP, KIND_SUPERGROUP, RawChat, RawUser, Roles
from .rawstore import RawStore

Log = Callable[[str], None]


@dataclass
class ChatDecision:
    chat: RawChat
    included: bool
    reason: str
    merged_into: Optional[int] = None  # legacy group exported under this supergroup
    participants: list[RawUser] = field(default_factory=list)
    roster_complete: bool = False


def _decide_static(chat: RawChat, flt: ChatFilter) -> tuple[bool, str]:
    """Rules that need nothing but the dialog itself."""
    if chat.id in flt.exclude_ids:
        return False, "excluded by id"
    if flt.include_ids and chat.id not in flt.include_ids:
        return False, "not in include_ids"
    if chat.kind not in flt.include_types:
        return False, f"type {chat.kind}"
    if not chat.is_accessible:
        return False, "no access (left/forbidden)"
    if chat.is_archived and not flt.include_archived:
        return False, "archived"
    if chat.title and flt.title_excluded(chat.title):
        return False, "title matches exclude_title_regex"
    return True, "included"


def is_internal(participants: Iterable[RawUser], roles: Roles, complete: bool = True) -> bool:
    """True when the member list is complete and every member is staff or a
    bot (a chat without clients). An incomplete list proves nothing."""
    members = [p for p in participants if not p.is_bot]
    return complete and bool(members) and all(roles.is_staff(p) for p in members)


def _attach_legacy(decisions: dict[int, ChatDecision], legacy_id: int, target: ChatDecision, flt: ChatFilter) -> None:
    d = decisions.get(legacy_id)
    if d is None:
        legacy = RawChat(id=legacy_id, kind=KIND_GROUP, title=f"{target.chat.title} (legacy)",
                         migrated_to=target.chat.id, is_archived=target.chat.is_archived)
        d = decisions[legacy_id] = ChatDecision(legacy, False, "")
    else:
        d.chat = dataclasses.replace(d.chat, migrated_to=target.chat.id)
    d.merged_into = target.chat.id
    if legacy_id in flt.exclude_ids:
        d.included, d.reason = False, "excluded by id"
        return
    d.included = target.included and d.chat.is_accessible
    d.reason = f"merged into {target.chat.id}" if target.included else f"target: {target.reason}"


async def plan(source, flt: ChatFilter, roles: Roles) -> list[ChatDecision]:
    chats = await source.list_chats()
    decisions: dict[int, ChatDecision] = {}
    for chat in chats:
        included, reason = _decide_static(chat, flt)
        decisions[chat.id] = ChatDecision(chat, included, reason)

    # Legacy groups follow the supergroup they migrated to (forward pointer
    # from the dialog list; the backward pointer comes from inspect below).
    for chat in chats:
        if chat.kind == KIND_GROUP and chat.migrated_to in decisions:
            _attach_legacy(decisions, chat.id, decisions[chat.migrated_to], flt)

    for d in list(decisions.values()):
        if not d.included or d.merged_into is not None:
            continue
        details = await source.inspect(d.chat)
        d.participants = details.users
        d.roster_complete = details.complete
        if details.participants_count is not None:
            d.chat = dataclasses.replace(d.chat, participant_count=details.participants_count)
        if d.chat.kind == KIND_SUPERGROUP and details.migrated_from_id is not None:
            _attach_legacy(decisions, details.migrated_from_id, d, flt)
        if flt.exclude_internal and is_internal(details.users, roles, details.complete):
            d.included = False
            d.reason = "internal (all members are staff)"
            for other in decisions.values():
                if other.merged_into == d.chat.id:
                    other.included, other.reason = False, d.reason
        elif d.included and not details.complete:
            d.reason = "included (member list " + (details.error or "incomplete") + ")"

    return sorted(decisions.values(), key=lambda d: (not d.included, d.chat.kind, d.chat.title.lower()))


@dataclass
class ExportReport:
    chats: int = 0
    messages: int = 0
    users: int = 0
    failures: dict[int, str] = field(default_factory=dict)


async def export(
    source,
    store: RawStore,
    decisions: list[ChatDecision],
    tuning: ExportTuning,
    log: Log = lambda s: None,
    full: bool = False,
    only: Optional[Iterable[int]] = None,
) -> ExportReport:
    report = ExportReport()
    selected = [d for d in decisions if d.included]
    if only is not None:
        wanted = set(only)
        selected = [d for d in selected if d.chat.id in wanted or d.merged_into in wanted]
        for missing in sorted(wanted - {d.chat.id for d in selected} - {d.merged_into for d in selected}):
            log(f"--only {missing}: not an included chat (see `tg-collector chats`), skipped")

    me = await source.me()
    store.put_users([me])
    store.set_me_id(me.id)
    store.put_chats(d.chat for d in decisions)  # catalogue everything, even excluded

    for d in selected:
        chat = d.chat
        if full:
            store.reset_chat(chat.id)
        after = store.last_message_id(chat.id)
        label = f"{chat.title!r} ({chat.id})" + (" [legacy part]" if d.merged_into else "")
        log(f"{label}: exporting after id {after}")
        users: dict[int, RawUser] = {u.id: u for u in d.participants}
        batch = []
        count = 0
        try:
            async for msg, sender in source.messages(chat, after_id=after):
                if sender is not None:
                    users[sender.id] = sender
                batch.append(msg)
                if len(batch) >= tuning.flush_every:
                    count += store.append_messages(chat.id, batch)
                    store.put_users(users.values())
                    batch.clear()
                    log(f"{label}: {count} new messages")
            if batch:
                count += store.append_messages(chat.id, batch)
        except ExportHalt:
            if batch:
                store.append_messages(chat.id, batch)
            raise  # the account/session needs the operator; the cursor is safe
        except Exception as exc:  # keep going with the other chats
            if batch:
                count += store.append_messages(chat.id, batch)
            report.failures[chat.id] = f"{type(exc).__name__}: {exc}"
            log(f"{label}: FAILED after {count} messages: {exc}")
        store.put_users(users.values())
        store.put_chats([dataclasses.replace(chat, participant_ids=tuple(u.id for u in d.participants))])
        report.chats += 1
        report.messages += count
        report.users += len(users)
        log(f"{label}: done, {count} new messages")
    return report
