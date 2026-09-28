"""Plan + export against a fake Telegram source (no network)."""

import asyncio
from datetime import datetime, timedelta, timezone

from tg_collector.config import ChatFilter, ExportTuning, Settings
from tg_collector.export import InspectionCache, export, is_internal, plan
from tg_collector.telegram import ChatDetails
from tg_collector.model import (
    KIND_BOT, KIND_CHANNEL, KIND_GROUP, KIND_PRIVATE, KIND_SELF, KIND_SUPERGROUP,
    SENDER_USER, RawChat, RawMessage, RawUser, Roles,
)
from tg_collector.rawstore import RawStore

T0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Support", username="sup")
SALES = RawUser(id=2, first_name="Sales", username="sal")
CLIENT = RawUser(id=3, first_name="Client")

CHATS = [
    RawChat(id=-100_1, kind=KIND_SUPERGROUP, title="Acme support"),
    RawChat(id=-100_2, kind=KIND_SUPERGROUP, title="[INT] sales sync"),
    RawChat(id=-100_3, kind=KIND_SUPERGROUP, title="Staff only"),
    RawChat(id=-100_4, kind=KIND_SUPERGROUP, title="Left one", is_accessible=False),
    RawChat(id=-100_5, kind=KIND_CHANNEL, title="News"),
    RawChat(id=-100_6, kind=KIND_SUPERGROUP, title="Archived client", is_archived=True),
    RawChat(id=-7, kind=KIND_GROUP, title="Acme (legacy)", migrated_to=-100_1),
    RawChat(id=-8, kind=KIND_GROUP, title="Orphan legacy", migrated_to=-100_999),
    RawChat(id=42, kind=KIND_PRIVATE, title="Some person"),
    RawChat(id=43, kind=KIND_BOT, title="Some bot"),
    RawChat(id=1, kind=KIND_SELF, title="Saved"),
]
MEMBERS = {
    -100_1: [ME, SALES, CLIENT],
    -100_2: [ME, SALES],
    -100_3: [ME, SALES],
    -100_6: [ME, CLIENT],
    -8: [ME, CLIENT],
}


class FakeSource:
    def __init__(self, chats, members, history, fail_at=None, migrated_from=None, hidden=()):
        self.chats, self.members, self.history = chats, members, history
        self.fail_at = fail_at  # (chat_id, message_id) -> raise after yielding it
        self.migrated_from = migrated_from or {}  # supergroup id -> legacy group id
        self.hidden = set(hidden)
        self.participant_calls = []

    async def me(self):
        return ME

    async def list_chats(self):
        return list(self.chats)

    async def inspect(self, chat):
        self.participant_calls.append(chat.id)
        if chat.id in self.hidden:
            return ChatDetails(error="participants hidden", migrated_from_id=self.migrated_from.get(chat.id))
        users = list(self.members.get(chat.id, []))
        return ChatDetails(users=users, complete=True, participants_count=len(users),
                           migrated_from_id=self.migrated_from.get(chat.id))

    async def messages(self, chat, after_id=0):
        for m, sender in self.history.get(chat.id, []):
            if m.id > after_id:
                yield m, sender
                if self.fail_at == (chat.id, m.id):
                    raise RuntimeError("boom")


def m(chat_id, mid, sender, text):
    return RawMessage(chat_id=chat_id, id=mid, date=T0 + timedelta(minutes=mid), sender_id=sender.id,
                      sender_kind=SENDER_USER, text=text), sender


def settings(tmp_path, **chat_filter) -> Settings:
    return Settings(project_dir=tmp_path, data_dir=tmp_path / "data",
                    chats=ChatFilter(**chat_filter) if chat_filter else ChatFilter())


def run(coro):
    return asyncio.run(coro)


def test_plan_applies_rules(tmp_path):
    src = FakeSource(CHATS, MEMBERS, {})
    s = settings(tmp_path, exclude_title_regex=(r"^\[INT\]",))
    roles = Roles.build(ME.id, sales=["@sal"])
    decisions = {d.chat.id: d for d in run(plan(src, s.chats, roles))}
    assert decisions[-100_1].included
    assert not decisions[-100_2].included and "regex" in decisions[-100_2].reason
    assert not decisions[-100_3].included and decisions[-100_3].reason.startswith("internal")
    assert not decisions[-100_4].included and "no access" in decisions[-100_4].reason
    assert not decisions[-100_5].included and decisions[-100_5].reason == "type channel"
    assert decisions[-100_6].included  # archived included by default
    assert decisions[-7].included and decisions[-7].merged_into == -100_1
    assert decisions[-8].included and decisions[-8].merged_into is None  # target unknown: standalone
    for cid in (42, 43, 1):
        assert not decisions[cid].included
    # Members fetched only for candidates, never for merged legacy peers.
    assert set(src.participant_calls) == {-100_1, -100_3, -100_6, -8}


def test_plan_include_ids_and_archived(tmp_path):
    src = FakeSource(CHATS, MEMBERS, {})
    s = settings(tmp_path, include_ids=frozenset({-100_6}), include_archived=False)
    decisions = {d.chat.id: d for d in run(plan(src, s.chats, Roles.build(ME.id)))}
    assert not decisions[-100_6].included and decisions[-100_6].reason == "archived"
    assert all(not d.included for d in decisions.values())


def test_internal_rule_ignores_bots_and_needs_members():
    roles = Roles.build(ME.id, sales=[SALES.id])
    bot = RawUser(id=9, is_bot=True)
    assert is_internal([ME, SALES, bot], roles)
    assert not is_internal([ME, SALES], roles, complete=False)  # a partial list proves nothing
    assert not is_internal([ME, CLIENT], roles)
    assert not is_internal([], roles)
    assert not is_internal([bot], roles)


def test_plan_hidden_members_and_legacy_discovery(tmp_path):
    src = FakeSource(CHATS, MEMBERS, {}, migrated_from={-100_6: -99}, hidden={-100_3})
    decisions = {d.chat.id: d for d in run(plan(src, settings(tmp_path).chats, Roles.build(ME.id, sales=["@sal"])))}
    # Hidden member list: cannot be judged internal, stays included with a note.
    assert decisions[-100_3].included and "hidden" in decisions[-100_3].reason
    # Legacy group discovered via full info although absent from the dialog list.
    legacy = decisions[-99]
    assert legacy.included and legacy.merged_into == -100_6 and legacy.chat.migrated_to == -100_6
    assert legacy.chat.kind == KIND_GROUP and "legacy" in legacy.chat.title


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


def cache(tmp_path, clock, me_id=ME.id, hours=24, refresh=False):
    return InspectionCache(RawStore(tmp_path / "raw"), me_id, timedelta(hours=hours), refresh=refresh, clock=clock)


def test_a_second_plan_reuses_saved_member_lists(tmp_path):
    clock = Clock(T0)
    roles = Roles.build(ME.id, sales=["@sal"])
    first = FakeSource(CHATS, MEMBERS, {}, migrated_from={-100_6: -99})
    before = {d.chat.id: d for d in run(plan(first, settings(tmp_path).chats, roles, cache(tmp_path, clock)))}

    second = FakeSource(CHATS, {}, {})  # would report no members at all if asked
    after = {d.chat.id: d for d in run(plan(second, settings(tmp_path).chats, roles, cache(tmp_path, clock)))}
    assert second.participant_calls == []
    assert {k: (d.included, d.reason, d.merged_into) for k, d in after.items()} == \
           {k: (d.included, d.reason, d.merged_into) for k, d in before.items()}
    assert [u.id for u in after[-100_1].participants] == [1, 2, 3] and after[-100_1].roster_complete


def test_saved_member_lists_meet_the_current_config(tmp_path):
    clock = Clock(T0)
    run(plan(FakeSource(CHATS, MEMBERS, {}), settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, clock)))
    # Sales added to [staff] after the first plan: the saved list now makes -100_3 internal.
    src = FakeSource(CHATS, MEMBERS, {})
    decisions = {d.chat.id: d for d in run(plan(src, settings(tmp_path).chats, Roles.build(ME.id, sales=["@sal"]),
                                                cache(tmp_path, clock)))}
    assert src.participant_calls == []
    assert not decisions[-100_3].included and decisions[-100_3].reason.startswith("internal")


def test_stale_foreign_or_refreshed_member_lists_are_fetched_again(tmp_path):
    clock = Clock(T0)
    run(plan(FakeSource(CHATS, MEMBERS, {}), settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, clock)))
    candidates = {-100_1, -100_2, -100_3, -100_6, -8}

    other_account = FakeSource(CHATS, MEMBERS, {})
    run(plan(other_account, settings(tmp_path).chats, Roles.build(99), cache(tmp_path, clock, me_id=99)))
    assert set(other_account.participant_calls) == candidates

    run(plan(FakeSource(CHATS, MEMBERS, {}), settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, clock)))
    refreshed = FakeSource(CHATS, MEMBERS, {})
    run(plan(refreshed, settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, clock, refresh=True)))
    assert set(refreshed.participant_calls) == candidates

    clock.now = T0 + timedelta(hours=25)
    stale = FakeSource(CHATS, MEMBERS, {})
    run(plan(stale, settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, clock)))
    assert set(stale.participant_calls) == candidates


class Interrupting(FakeSource):
    def __init__(self, *a, stop_after, **kw):
        super().__init__(*a, **kw)
        self.stop_after = stop_after

    async def inspect(self, chat):
        if len(self.participant_calls) == self.stop_after:
            raise KeyboardInterrupt
        return await super().inspect(chat)


def test_an_interrupted_plan_keeps_what_it_fetched(tmp_path):
    clock = Clock(T0)
    first = Interrupting(CHATS, MEMBERS, {}, stop_after=2)
    try:
        run(plan(first, settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, clock)))
    except KeyboardInterrupt:
        pass
    second = FakeSource(CHATS, MEMBERS, {})
    run(plan(second, settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, clock)))
    assert len(second.participant_calls) == 3 and not set(second.participant_calls) & set(first.participant_calls)


def test_an_unreadable_saved_file_is_fetched_again(tmp_path):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "inspections.json").write_text("{not json", encoding="utf-8")
    src = FakeSource(CHATS, MEMBERS, {})
    run(plan(src, settings(tmp_path).chats, Roles.build(ME.id), cache(tmp_path, Clock(T0))))
    assert set(src.participant_calls) == {-100_1, -100_2, -100_3, -100_6, -8}


def test_plan_reports_its_progress(tmp_path):
    lines = []
    clock = Clock(T0)
    s = settings(tmp_path, exclude_title_regex=(r"^\[INT\]",))
    run(plan(FakeSource(CHATS, MEMBERS, {}), s.chats, Roles.build(ME.id), cache(tmp_path, clock), log=lines.append))
    assert lines[0] == "Checking members of 4 chats: 0 saved by an earlier run, 4 to ask Telegram"
    assert "  [1/4] members of supergroup 'Acme support' (-1001)" in lines
    assert len(lines) == 5 and lines[-1].startswith("  [4/4] ")

    lines.clear()  # everything saved: one summary line, no per-chat lines
    run(plan(FakeSource(CHATS, MEMBERS, {}), s.chats, Roles.build(ME.id), cache(tmp_path, clock), log=lines.append))
    assert lines == ["Checking members of 4 chats: 4 saved by an earlier run, 0 to ask Telegram"]


def test_export_is_incremental_and_merges_legacy(tmp_path):
    history = {
        -100_1: [m(-100_1, 1, CLIENT, "hi"), m(-100_1, 2, ME, "hello")],
        -7: [m(-7, 1, CLIENT, "old")],
    }
    src = FakeSource(CHATS, MEMBERS, history)
    s = settings(tmp_path)
    store = RawStore(s.raw_dir)
    decisions = run(plan(src, s.chats, Roles.build(ME.id)))
    tuning = ExportTuning(flush_every=1)

    report = run(export(src, store, decisions, tuning))
    assert report.messages == 3 and not report.failures
    assert store.me_id() == ME.id
    assert store.last_message_id(-100_1) == 2 and store.last_message_id(-7) == 1
    assert {u.id for u in store.users().values()} == {1, 2, 3}
    assert store.chats()[-100_1].participant_ids == (1, 2, 3)
    assert -100_5 in store.chats()  # excluded chats are catalogued too

    history[-100_1].append(m(-100_1, 3, CLIENT, "more"))
    report2 = run(export(src, store, decisions, tuning))
    assert report2.messages == 1
    assert [x.id for x in store.messages(-100_1)] == [1, 2, 3]

    report3 = run(export(src, store, decisions, tuning, full=True, only=[-100_1]))
    assert report3.messages == 4 and report3.chats == 2  # 3 + the legacy peer, which follows its target
    assert [x.id for x in store.messages(-100_1)] == [1, 2, 3]


def test_export_keeps_partial_progress_on_failure(tmp_path):
    history = {-100_1: [m(-100_1, i, CLIENT, f"m{i}") for i in range(1, 6)]}
    src = FakeSource(CHATS, MEMBERS, history, fail_at=(-100_1, 3))
    s = settings(tmp_path)
    store = RawStore(s.raw_dir)
    decisions = run(plan(src, s.chats, Roles.build(ME.id)))
    report = run(export(src, store, decisions, ExportTuning(flush_every=2)))
    assert -100_1 in report.failures and "boom" in report.failures[-100_1]
    assert store.last_message_id(-100_1) == 3
    src.fail_at = None
    report2 = run(export(src, store, decisions, ExportTuning(flush_every=2)))
    assert not report2.failures and [x.id for x in store.messages(-100_1)] == [1, 2, 3, 4, 5]


def test_rawstore_dedupes_duplicate_appends(tmp_path):
    store = RawStore(tmp_path)
    a, _ = m(-1, 1, CLIENT, "a")
    b, _ = m(-1, 2, CLIENT, "b")
    store.append_messages(-1, [a, b])
    store.append_messages(-1, [b])  # crash-replay
    assert [x.id for x in store.messages(-1)] == [1, 2]
    assert store.last_message_id(-1) == 2
    store.reset_chat(-1)
    assert list(store.messages(-1)) == [] and store.last_message_id(-1) == 0


def test_rawstore_merges_user_fields(tmp_path):
    store = RawStore(tmp_path)
    store.put_users([RawUser(id=5, first_name="A", username="a_user", phone="123")])
    store.put_users([RawUser(id=5, first_name="A2")])  # minimal sighting must not erase fields
    u = store.users()[5]
    assert (u.first_name, u.username, u.phone) == ("A2", "a_user", "123")
