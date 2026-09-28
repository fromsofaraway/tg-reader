"""Anonymize -> write -> verify on a synthetic raw store (no network)."""

import dataclasses
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from tg_collector.anonymize import AnonymizationError, Mapping, anonymize, logical_chats
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import render_transcript, write_dataset
from tg_collector.model import (
    FWD_USER, KIND_GROUP, KIND_SUPERGROUP, SENDER_CHANNEL, SENDER_USER, Entity, Forward, Media, RawChat, RawMessage, RawUser, Roles,
)
from tg_collector.rawstore import RawStore
from tg_collector.verify import verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)

ME = RawUser(id=1001, first_name="Олег", last_name="Северов", username="oleg_support", phone="79990000001")
SALES = RawUser(id=1002, first_name="Мария", last_name="Иванова", username="masha_sales")
CLIENT_A = RawUser(id=200001, first_name="Иван", last_name="Петров", username="ivan_petrov", phone="79991234567")
CLIENT_B = RawUser(id=200002, first_name="Ольга", last_name="Сидорова")
BOT = RawUser(id=300001, first_name="Northwind Bot", username="northwind_bot", is_bot=True)
GONE = RawUser(id=400001, is_deleted=True)

SUPER = RawChat(id=-1001000000001, kind=KIND_SUPERGROUP, title="ООО Ромашка × Northwind support",
                participant_ids=(1001, 1002, 200001, 200002, 300001))
LEGACY = RawChat(id=-2000000001, kind=KIND_GROUP, title="Ромашка (old)", migrated_to=SUPER.id)
OTHER = RawChat(id=-1001000000002, kind=KIND_SUPERGROUP, title="Beta Inc / Northwind", participant_ids=(1001, 200002))


TEXT_WITH_MENTION = "Не работает выгрузка в Excel, ошибка E1042. Мой тел +7 999 123-45-67, @oleg_support гляньте"


def utf16_offset(text: str, needle: str) -> int:
    return len(text[:text.index(needle)].encode("utf-16-le")) // 2


def msg(chat, mid, minutes, sender, text="", **kw):
    kind = kw.pop("sender_kind", SENDER_USER)
    return RawMessage(chat_id=chat.id, id=mid, date=T0 + timedelta(minutes=minutes),
                      sender_id=sender.id if sender is not None else kw.pop("sender_id", None),
                      sender_kind=kind, text=text, **kw)


@pytest.fixture
def store(tmp_path) -> RawStore:
    s = RawStore(tmp_path / "raw")
    s.put_chats([SUPER, LEGACY, OTHER])
    s.put_users([ME, SALES, CLIENT_A, CLIENT_B, BOT, GONE, OBSERVER])
    s.set_me_id(ME.id)
    s.append_messages(LEGACY.id, [
        msg(LEGACY, 5, -60 * 24 * 30, CLIENT_A, "Здравствуйте, мы Ромашка, начинаем внедрение"),
        msg(LEGACY, 6, -60 * 24 * 30 + 3, ME, "Добрый день, Иван Петров! Поехали"),
    ])
    s.append_messages(SUPER.id, [
        msg(SUPER, 1, 0, None, action="MessageActionChatCreate"),
        msg(SUPER, 2, 1, CLIENT_A, TEXT_WITH_MENTION,
            entities=(Entity("Mention", utf16_offset(TEXT_WITH_MENTION, "@oleg_support"), 13),)),
        msg(SUPER, 3, 5, ME, "Иван, смотрю. Пришлите лог", reply_to_id=2),
        msg(SUPER, 4, 6, CLIENT_A, "", media=Media(kind="document", ext="log", file_name="romashka_export.log")),
        msg(SUPER, 7, 9, ME, "Починили в версии 2.15.3, обновитесь", reply_to_id=2, edit_date=T0),
        msg(SUPER, 8, 60 * 10, SALES, "Коллеги, продлеваем договор? Сидорова, отпишитесь"),
        msg(SUPER, 9, 60 * 10 + 1, CLIENT_B, "Да", forward=Forward(kind=FWD_USER, from_id=CLIENT_A.id)),
        msg(SUPER, 10, 60 * 10 + 2, None, "Объявление", sender_id=SUPER.id, sender_kind=SENDER_CHANNEL),
        msg(SUPER, 11, 60 * 10 + 3, GONE, "Пока"),
        msg(SUPER, 13, 60 * 10 + 5, OBSERVER, "Подтверждаю"),
        msg(SUPER, 12, 60 * 10 + 4, CLIENT_B, "", media=None),  # empty, dropped
    ])
    s.append_messages(OTHER.id, [
        msg(OTHER, 1, 30, CLIENT_B, "Как настроить SLA?"),
        msg(OTHER, 2, 31, ME, "См. документацию https://docs.northwind.example/sla"),
    ])
    return s


OBSERVER = RawUser(id=1003, first_name="Пётр", last_name="Смирнов", username="petr_boss")


def roles():
    return Roles.build(ME.id, sales=["@masha_sales"], other=["@petr_boss"])


def test_logical_chats_merge_legacy_group(store):
    lcs = {lc.primary.id: lc for lc in logical_chats(store.chats(), store.message_chat_ids())}
    assert set(lcs) == {SUPER.id, OTHER.id}
    assert lcs[SUPER.id].peers == (LEGACY.id, SUPER.id)


def test_anonymize_end_to_end(store, tmp_path):
    mapping = Mapping(tmp_path / "anon" / "mapping.json")
    ds = anonymize(store, mapping, roles(), AnonPolicy(keep_terms=("Northwind",)))

    # Chats: legacy merged into the supergroup; ids are random but well-formed.
    assert set(ds.chats) == {mapping.chat(SUPER.id), mapping.chat(OTHER.id)}
    # Both peers of the merged conversation share that one virtual id.
    assert mapping.chats()[LEGACY.id] == mapping.chat(SUPER.id)
    romashka = ds.chats[mapping.chat(SUPER.id)]
    assert re.fullmatch(r"C\d{4,}", romashka.vid) and romashka.title == romashka.vid
    assert romashka.message_count == 11  # 13 raw - 1 service - 1 empty
    C1 = romashka.vid

    # Users and roles.
    by_vid = {u.vid: u for u in ds.users.values()}
    me = by_vid[mapping.user(ME.id)]
    assert (me.role, me.name) == ("support", "Олег")
    assert by_vid[mapping.user(SALES.id)].role == "sales"
    assert by_vid[mapping.user(CLIENT_A.id)].role == "client"
    assert by_vid[mapping.user(BOT.id)].role == "bot"
    assert by_vid[mapping.user(GONE.id)].role == "deleted"
    assert by_vid[mapping.user(SUPER.id)].role == "anonymous"
    observer = by_vid[mapping.user(OBSERVER.id)]
    assert (observer.role, observer.side, observer.name) == ("other", "STAFF", "Пётр")
    assert "Смирнов" not in "\n".join(m.text for m in ds.messages)

    texts = [m.text for m in ds.messages if m.chat == C1]
    joined = "\n".join(texts)
    assert "Ромашка" not in joined and "Петров" not in joined and "Сидорова" not in joined
    assert "+7 999" not in joined and "oleg_support" not in joined
    assert "E1042" in joined and "2.15.3" in joined and "Excel" in joined
    assert f"@{me.vid}" in joined
    assert "Иван, смотрю" in joined  # first names are kept

    # Sequencing, replies, media, forwards, edits, sides.
    m = {x.seq: x for x in ds.messages if x.chat == C1}
    assert m[1].text.startswith("Здравствуйте")  # legacy first
    assert m[4].reply_to == 3 and m[4].role == "support" and m[4].side == "STAFF"
    assert m[3].side == "CLIENT"
    assert m[5].media == {"kind": "document", "ext": "log"}
    assert m[6].edited and m[6].reply_to == 3
    assert m[8].forwarded == mapping.user(CLIENT_A.id)
    assert m[9].sender == mapping.user(SUPER.id) and m[9].role == "anonymous" and m[9].side == "STAFF"
    assert by_vid[mapping.user(CLIENT_A.id)].side == "CLIENT" and by_vid[mapping.user(BOT.id)].side == "BOT"

    other = ds.chats[mapping.chat(OTHER.id)]
    assert "<url>" in ds.messages_of(other.vid)[1].text
    assert ds.notes["merged_legacy_groups"] == 1
    assert "generic_title_terms_kept" not in ds.notes  # title words never reach the shareable manifest
    assert ds.private["keep_terms_suggested"] == []  # only 2 titles: below the 3-title minimum


def test_mapping_is_stable_and_secret(store, tmp_path):
    path = tmp_path / "anon" / "mapping.json"
    mapping = Mapping(path)
    ds1 = anonymize(store, mapping, roles(), AnonPolicy())
    mapping.save()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert "SECRET" in path.read_text()

    store.append_messages(OTHER.id, [msg(OTHER, 3, 40, RawUser(id=999999), "новый человек")])
    store.put_users([RawUser(id=999999, first_name="Новый")])
    ds2 = anonymize(store, Mapping.load(path), roles(), AnonPolicy())
    assert {u.vid for u in ds1.users.values()} <= {u.vid for u in ds2.users.values()}
    assert ds2.chats.keys() == ds1.chats.keys()
    assert mapping.user(ME.id) == Mapping.load(path).user(ME.id)
    # Ids are random: two fresh mappings of the same store almost surely differ.
    other = Mapping(tmp_path / "other.json")
    anonymize(store, other, roles(), AnonPolicy())
    assert other.user(ME.id) != mapping.user(ME.id) or other.chat(SUPER.id) != mapping.chat(SUPER.id)


def test_corrupted_mapping_is_reported(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text("{not json")
    with pytest.raises(AnonymizationError):
        Mapping.load(path)


def test_free_text_first_names_are_scrubbed(store, tmp_path):
    store.put_users([
        RawUser(id=700001, first_name="Ромашка Бухгалтерия"),
        RawUser(id=700002, first_name="Иван Петров"),
        RawUser(id=700003, first_name="+7 999 000-00-00"),
        RawUser(id=700004, first_name="Анна-Мария", last_name="Кузнецова"),
    ])
    store.append_messages(OTHER.id, [msg(OTHER, 5 + i, 50 + i, RawUser(id=700001 + i), "ok") for i in range(4)])
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, roles(), AnonPolicy())
    names = {uid: ds.users[mapping.user(uid)].name for uid in (700001, 700002, 700003, 700004)}
    assert names == {700001: "", 700002: "Иван", 700003: "", 700004: "Анна-Мария"}


def test_name_modes(store, tmp_path):
    full = anonymize(store, Mapping(tmp_path / "m1.json"), roles(), AnonPolicy(name_mode="full"))
    assert any(u.name == "Иван Петров" for u in full.users.values())
    none = anonymize(store, Mapping(tmp_path / "m2.json"), roles(), AnonPolicy(name_mode="none"))
    assert all(u.name in ("", "Deleted") for u in none.users.values())
    assert not any("Иван" in m.text for m in none.messages)
    no_bots = anonymize(store, Mapping(tmp_path / "m3.json"), roles(), AnonPolicy(keep_bot_messages=False))
    assert no_bots.notes["dropped_messages"].get("bot", 0) == 0  # the bot never wrote anything here


def test_keep_service_messages_and_titles(store, tmp_path):
    ds = anonymize(store, Mapping(tmp_path / "m.json"), roles(),
                   AnonPolicy(keep_service_messages=True, keep_chat_titles=True, scrub_chat_titles=False))
    assert any(m.action == "MessageActionChatCreate" for m in ds.messages)
    assert any(c.title.startswith("ООО Ромашка") for c in ds.chats.values())


def test_self_check_aborts_on_surviving_id(store, tmp_path, monkeypatch):
    import tg_collector.anonymize as mod
    monkeypatch.setattr(mod.Scrubber, "scrub", lambda self, text, entities=(): text)  # broken scrubber
    with pytest.raises(AnonymizationError):
        anonymize(store, Mapping(tmp_path / "m.json"), roles(), AnonPolicy())


def test_write_dataset_and_verify(store, tmp_path):
    mapping = Mapping(tmp_path / "anon" / "mapping.json")
    policy = AnonPolicy(keep_terms=("Northwind",))
    ds = anonymize(store, mapping, roles(), policy)
    out = tmp_path / "anon" / "dataset"
    C1 = mapping.chat(SUPER.id)
    report = write_dataset(ds, out, Output(timezone="Europe/Berlin", episode_gap_hours=6), {"x": 1})
    assert report.messages == len(ds.messages) and report.chunks >= 1
    assert (out / "transcripts" / f"{C1}.md").exists() and (out / "chunks" / "chunk-001.md").exists()
    assert not out.with_name("dataset.tmp").exists()
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["chats"] == 2 and manifest["episodes"] == 4
    users = json.loads((out / "users.json").read_text())
    assert all(set(v) == {"name", "role", "side"} for v in users.values())
    episodes = [json.loads(l) for l in (out / "episodes.jsonl").read_text().splitlines()]
    assert [e["episode"] for e in episodes if e["chat"] == C1] == [1, 2, 3]
    assert all("episode" in json.loads(l) for l in (out / "messages.jsonl").read_text().splitlines())

    transcript = (out / "transcripts" / f"{C1}.md").read_text()
    assert "Participants:" in transcript and "## Episode 3" in transcript  # 10h gap opens a new episode
    assert 'STAFF ' in transcript and 'CLIENT ' in transcript
    assert '↳#3 ' in transcript and '"Не работает выгрузка' in transcript  # reply quotes the target
    assert "[document:log]" in transcript and "(forwarded from U" in transcript
    assert "10:01]" in transcript  # 09:01 UTC rendered in Berlin time
    assert "anonymous admin" in transcript

    report_path = tmp_path / "anon" / "verify_report.json"
    vr = verify(out, store, policy, report_path)
    assert vr.ok, vr.leaks
    assert report_path.exists() and not (out / "verify_report.json").exists()

    # Plant leaks and make sure verify catches them.
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "contact @ivan_petrov or 200001 or Петров, Ромашка"}, ensure_ascii=False) + "\n")
    vr2 = verify(out, store, policy, report_path)
    assert {"username", "user_id", "name", "title"} <= set(vr2.by_kind())


def test_transcript_split_and_episodes(store, tmp_path):
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, roles(), AnonPolicy())
    ds.assign_episodes(6)
    chat = ds.chats[mapping.chat(SUPER.id)]
    assert chat.episodes == 3  # legacy -> super (30 days later) -> +10h gap
    single = render_transcript(ds, chat, Output(max_chars=0))
    assert len(single) == 1 and single[0].count("## Episode ") == 3
    assert len(render_transcript(ds, chat, Output(max_chars=1))) == 1  # 10k minimum budget

    big = ds.messages_of(chat.vid)[0]
    ds.messages = [dataclasses.replace(big, seq=i, text="x" * 3000) for i in range(1, 11)]
    ds.assign_episodes(6)
    parts = render_transcript(ds, chat, Output(max_chars=10_000))
    assert len(parts) > 1 and all(p.startswith(f"# {chat.vid} (part") for p in parts)


def test_transcript_turns_truncation_and_code(store, tmp_path):
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, roles(), AnonPolicy())
    chat = ds.chats[mapping.chat(OTHER.id)]
    base = ds.messages_of(chat.vid)[0]
    ds.messages = [
        dataclasses.replace(base, seq=1, text="первая мысль"),
        dataclasses.replace(base, seq=2, text="вторая мысль", date=base.date + timedelta(seconds=30)),
        dataclasses.replace(base, seq=3, text="y" * 5000, date=base.date + timedelta(seconds=60)),
        dataclasses.replace(base, seq=4, text="Traceback (most recent call last):\n  File x\nError", code=True,
                            date=base.date + timedelta(seconds=90)),
    ]
    ds.assign_episodes(6)
    text = render_transcript(ds, chat, Output(max_chars=0, max_message_chars=1000, turn_merge_seconds=120))[0]
    assert "\n    #2: вторая мысль" in text          # continuation of the same speaker
    assert "chars omitted" in text and "y" * 1000 not in text
    assert "```\nTraceback" in text
