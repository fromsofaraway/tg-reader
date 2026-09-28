"""Identifier hardening: public chat usernames join the vocabulary (bare,
after '@', after a keyword) and render as the chat's virtual id; a display
name that spells a username is dropped; participant lists carry no source
order; virtual ids have one fixed width whenever they were allocated."""

import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from tg_collector.anonymize import AnonymizationError, Mapping, anonymize, display_name
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import render_transcript, write_dataset
from tg_collector.model import (
    FWD_USER, KIND_BOT, KIND_CHANNEL, KIND_GROUP, KIND_PRIVATE, KIND_SUPERGROUP, SENDER_CHANNEL, SENDER_USER,
    Entity, Forward, RawChat, RawMessage, RawUser, Roles,
)
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 3, 4, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support", phone="79990000001")
IVAN = RawUser(id=2, first_name="Иван", last_name="Петров", username="ivan_petrov")
ANNA = RawUser(id=3, first_name="Anna", username="anna_support")
CHAT_VID = "C01735"
ROSTER = Roster(by_username={"romashka_support_chat": CHAT_VID, "ivan_petrov": "U04217", "acmes": "C02222"})


def msg(chat_id, mid, sender, text="", **kw):
    kind = kw.pop("sender_kind", SENDER_USER)
    return RawMessage(chat_id=chat_id, id=mid, date=T0 + timedelta(minutes=mid), sender_id=sender,
                      sender_kind=kind, text=text, **kw)


def make_store(tmp_path, chats, users, messages):
    store = RawStore(tmp_path / "raw")
    store.put_chats(chats)
    store.put_users(users)
    store.set_me_id(ME.id)
    for chat_id, rows in messages.items():
        store.append_messages(chat_id, rows)
    return store


def written_and_verified(ds, store, policy, tmp_path):
    out = tmp_path / "anon" / "dataset"
    write_dataset(ds, out, Output(timezone="Europe/Berlin"), {})
    return out, verify(out, store, policy, tmp_path / "anon" / "verify_report.json")


# --- chat usernames: scrubber and scanner ------------------------------------------------

@pytest.mark.parametrize("raw, scrubbed", [
    ("наш чат romashka_support_chat", f"наш чат @{CHAT_VID}"),
    ("наш чат @romashka_support_chat", f"наш чат @{CHAT_VID}"),
    ("тг: romashka_support_chat", f"тг: @{CHAT_VID}"),
    ("чат: romashka_support_chat.", f"чат: @{CHAT_VID}."),
    ("Romashka_Support_Chat пишите туда", f"@{CHAT_VID} пишите туда"),
    ("наш чат\nromashka_support_chat\nвот", f"наш чат\n@{CHAT_VID}\nвот"),
    ("our chat romashka_support_chat is public", f"our chat @{CHAT_VID} is public"),
    ("чат @romashka_support_chatу", f"чат @{CHAT_VID}"),
    # A short plain chat username collides with words: only after '@' or a keyword.
    ("ник acmes", "ник @C02222"),
    ("@acmes", "@C02222"),
])
def test_chat_username_becomes_the_chat_vid(raw, scrubbed):
    assert Scrubber(AnonPolicy(), ROSTER).scrub(raw) == scrubbed
    assert LeakScanner(Known(usernames=frozenset(ROSTER.by_username))).scan(raw)


@pytest.mark.parametrize("text", [
    "наш чат t.me/romashka_support_chat",     # a Telegram link stays a link
    "romashka_support_chat_2 и ivan_petrov_2",  # a following '_' is another handle
    "пишите в acmes",                          # short plain username, no keyword
    "decline 05, ошибка E1042, заказ 123456, версия 2.15.3",
])
def test_chat_username_rules_leave_other_text_alone(text):
    out = Scrubber(AnonPolicy(), ROSTER).scrub(text)
    if "t.me/" in text:
        assert out == "наш чат <tg-link>"
    else:
        assert out == text
        assert LeakScanner(Known(usernames=frozenset(ROSTER.by_username))).scan(text) == []


def test_mention_entity_of_a_chat_username():
    text = "пинг @romashka_support_chat"
    assert Scrubber(AnonPolicy(), ROSTER).scrub(text, [Entity("Mention", 5, 22)]) == f"пинг @{CHAT_VID}"


def test_scanner_flags_chat_username_and_ignores_the_chat_placeholder():
    scanner = LeakScanner(Known(usernames=frozenset({"romashka_support_chat"})))
    hits = {l.match for l in scanner.scan("наш чат romashka_support_chat и @romashka_support_chat")}
    assert hits == {"romashka_support_chat", "@romashka_support_chat"}
    own = (f"ник: @{CHAT_VID}, тг @{CHAT_VID}, scan_@{CHAT_VID}.pdf, @{CHAT_VID}у писали, чат @{CHAT_VID}, "
           f"логин: @{CHAT_VID}, login @{CHAT_VID}, cvv @C0123")
    assert scanner.scan(own) == []


@pytest.mark.parametrize("raw, scrubbed", [
    ("логин: C12345", "логин: @user"),
    ("login=C1234", "login=@user"),
    ("ник = C12345", "ник = @user"),
    ("нужен ник C12345 срочно", "нужен ник @user срочно"),
])
def test_bare_c_login_after_keyword_is_still_a_handle(raw, scrubbed):
    # A chat id is only ever written with '@', so the keyword-handle rule
    # keeps treating "C12345" as a login; scrubber and scanner agree.
    assert Scrubber(AnonPolicy(), Roster()).scrub(raw) == scrubbed
    assert [l.kind for l in LeakScanner(Known()).scan(raw)] == ["kw_handle"]


# --- chat usernames: pipeline -------------------------------------------------------------

ROMASHKA = RawChat(id=-1003001, kind=KIND_SUPERGROUP, title="Ромашка support", username="romashka_support_chat",
                   participant_ids=(1, 2))
ACME = RawChat(id=-1003002, kind=KIND_SUPERGROUP, title="Acme Ltd", username="acme_support_chat", participant_ids=(1, 3))
TELEGRAM = RawChat(id=-1003003, kind=KIND_CHANNEL, title="Telegram News", username="telegram")      # catalogued only
PUBLIC = RawChat(id=-1003004, kind=KIND_SUPERGROUP, title="Василёк", username="chat_c_public")       # catalogued only
POLICY = AnonPolicy(keep_terms=("Northwind",))


def test_pipeline_renders_exported_chat_usernames(tmp_path):
    store = make_store(tmp_path, [ROMASHKA, ACME, TELEGRAM, PUBLIC], [ME, IVAN, ANNA], {
        ROMASHKA.id: [
            msg(ROMASHKA.id, 1, IVAN.id, "наш чат romashka_support_chat, напишите в telegram"),
            msg(ROMASHKA.id, 2, IVAN.id, "ссылка @romashka_support_chat и t.me/romashka_support_chat"),
            msg(ROMASHKA.id, 3, IVAN.id, "коллеги в acme_support_chat, см. chat_c_public и @chat_c_public"),
        ],
        ACME.id: [msg(ACME.id, 1, ANNA.id, "ок")],
    })
    mapping = Mapping(tmp_path / "anon" / "mapping.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), POLICY)
    romashka, acme = mapping.chat(ROMASHKA.id), mapping.chat(ACME.id)
    assert [m.text for m in ds.messages_of(romashka)] == [
        f"наш чат @{romashka}, напишите в telegram",
        f"ссылка @{romashka} и <tg-link>",
        f"коллеги в @{acme}, см. chat_c_public и @user",
    ]
    assert mapping.chats() == {ROMASHKA.id: romashka, ACME.id: acme}  # nothing allocated for catalogued chats
    known = known_from_store(store, POLICY)
    assert {"romashka_support_chat", "acme_support_chat"} <= known.usernames
    assert not {"telegram", "chat_c_public"} & known.usernames
    assert "username" in {l.kind for l in LeakScanner(known).scan("чат romashka_support_chat")}

    out, report = written_and_verified(ds, store, POLICY, tmp_path)
    assert report.ok, report.leaks
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "наш чат romashka_support_chat"}, ensure_ascii=False) + "\n")
    assert "username" in verify(out, store, POLICY, tmp_path / "v.json").by_kind()


def test_migrated_group_maps_the_username_to_the_primary_chat(tmp_path):
    legacy = RawChat(id=-3001, kind=KIND_GROUP, title="Ромашка (old)", migrated_to=ROMASHKA.id)
    store = make_store(tmp_path, [legacy, ROMASHKA], [ME, IVAN], {
        legacy.id: [msg(legacy.id, 1, IVAN.id, "переезжаем в romashka_support_chat")],
        ROMASHKA.id: [msg(ROMASHKA.id, 2, IVAN.id, "fwd", forward=Forward(kind="chat", from_id=legacy.id))],
    })
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), POLICY)
    vid = mapping.chat(ROMASHKA.id)
    assert [m.text for m in ds.messages] == [f"переезжаем в @{vid}", "fwd"]
    assert ds.messages[1].forwarded == vid
    mapping.save()
    # Both peers keep the one virtual id of the conversation.
    assert json.loads((tmp_path / "m.json").read_text())["chats"] == {str(legacy.id): vid, str(ROMASHKA.id): vid}


def test_private_and_bot_dialog_usernames_stay_with_the_person(tmp_path):
    ivan = RawUser(id=2, first_name="Иван", username="ivan_petrov_99")
    bot = RawUser(id=4, first_name="Northwind Help", username="northwind_help_bot", is_bot=True)
    dialog = RawChat(id=2, kind=KIND_PRIVATE, title="Иван", username="ivan_petrov_99")
    bot_dialog = RawChat(id=4, kind=KIND_BOT, title="Northwind Help", username="northwind_help_bot")
    text = "пинг @ivan_petrov_99 и @northwind_help_bot"
    store = make_store(tmp_path, [ROMASHKA, dialog, bot_dialog], [ME, ivan, bot], {
        ROMASHKA.id: [msg(ROMASHKA.id, 1, ME.id, text,
                          entities=(Entity("Mention", 5, 15), Entity("Mention", 23, 19)))],
        dialog.id: [msg(dialog.id, 1, ivan.id, "привет")],
        bot_dialog.id: [msg(bot_dialog.id, 1, bot.id, "меню")],
    })
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), POLICY)
    assert ds.messages_of(mapping.chat(ROMASHKA.id))[0].text == f"пинг @{mapping.user(2)} и @{mapping.user(4)}"


def test_kept_links_and_kept_titles_hide_the_chat_username(tmp_path):
    titled = RawChat(id=ROMASHKA.id, kind=KIND_SUPERGROUP, title="Ромашка (romashka_support_chat)",
                     username="romashka_support_chat", participant_ids=(1, 2))
    store = make_store(tmp_path, [titled], [ME, IVAN], {titled.id: [
        msg(titled.id, 1, IVAN.id, "https://acme.com/c/romashka_support_chat?ref=1 и acme.com/romashka_support_chat"),
    ]})
    policy = AnonPolicy(url_mode="keep", allow_domains=("acme.com",), keep_chat_titles=True)
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), policy)
    vid = mapping.chat(titled.id)
    assert ds.messages[0].text == f"https://acme.com/c/@{vid}?ref=1 и acme.com/@{vid}"
    assert ds.chats[vid].title == f"Ромашка (@{vid})"
    assert written_and_verified(ds, store, policy, tmp_path)[1].ok


def test_keep_terms_protect_a_bare_chat_username(tmp_path):
    northwind = RawChat(id=-3005, kind=KIND_SUPERGROUP, title="Northwind community", username="northwind",
                        participant_ids=(1, 2))
    pay = RawChat(id=-3006, kind=KIND_SUPERGROUP, title="Northwind Pay", username="northwindpay", participant_ids=(1, 2))
    support = RawChat(id=-3007, kind=KIND_SUPERGROUP, title="Support #1", username="romashka_support_chat",
                      participant_ids=(1, 2))
    store = make_store(tmp_path, [northwind, pay, support], [ME, IVAN], {
        northwind.id: [msg(northwind.id, 1, IVAN.id, "Northwind API is down, northwind_v2, @northwind, northwindpay")],
        pay.id: [msg(pay.id, 1, IVAN.id, "ок")],
        support.id: [msg(support.id, 1, IVAN.id, "наш чат romashka_support_chat, пишите @romashka_support_chat")],
    })
    policy = AnonPolicy(keep_terms=("Northwind", "romashka_support_chat"))
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), policy)
    assert ds.messages_of(mapping.chat(northwind.id))[0].text == (
        f"Northwind API is down, northwind_v2, @{mapping.chat(northwind.id)}, @{mapping.chat(pay.id)}")
    # The '@' form always resolves, as for people; the bare keep term stays.
    assert ds.messages_of(mapping.chat(support.id))[0].text == (
        f"наш чат romashka_support_chat, пишите @{mapping.chat(support.id)}")
    assert written_and_verified(ds, store, policy, tmp_path)[1].ok


# --- display names that spell a username -------------------------------------------------

@pytest.mark.parametrize("user, mode", [
    (RawUser(id=0, first_name="Kotik", username="kotik"), "first"),
    (RawUser(id=0, first_name="kotik", username="kotik"), "first"),
    (RawUser(id=0, first_name="Kotik", username="KoTik"), "first"),
    (RawUser(id=0, first_name="Kotikov", username="kotikov"), "first"),
    (RawUser(id=0, first_name="Kotik", username="kotik"), "full"),
    (RawUser(id=0, first_name="Kotik", last_name="Smith", username="kotik"), "full"),
    (RawUser(id=0, first_name="Kotik Smith", username="kotik"), "first"),
    (RawUser(id=0, first_name="Kotik-Smith", username="kotik"), "first"),
    (RawUser(id=0, first_name="Anna Maria", username="maria"), "full"),
    (RawUser(id=0, first_name="Kotik", username="kot_2024", usernames=("KOTIK",)), "first"),
    (RawUser(id=0, first_name="Helper", username="helper", is_bot=True), "first"),
    (RawUser(id=0, first_name="Support", username="support", is_bot=True), "first"),
])
def test_display_name_equal_to_own_username_is_dropped(user, mode):
    assert display_name(user, mode) == ""
    assert display_name(user, mode, Scrubber(AnonPolicy(), Roster())) == ""


def test_display_name_equal_to_any_known_username_is_dropped():
    checker = Scrubber(AnonPolicy(), Roster(by_username={"elena": "U00001", "kotikkotik": "U00002"}))
    assert display_name(RawUser(id=0, first_name="Elena"), "first", checker) == ""
    assert display_name(RawUser(id=0, first_name="Kotikkotik", username="kotikkotik"), "first", checker) == ""
    # keep_terms are never a handle to hide: the scrubber keeps them bare too.
    keep = Scrubber(AnonPolicy(keep_terms=("Northwind",)),
                    Roster(by_username={"northwind": "C00001"}, keep_terms=("Northwind",)))
    assert display_name(RawUser(id=0, first_name="Northwind Bot", is_bot=True), "first", keep) == "Northwind Bot"


@pytest.mark.parametrize("user, mode, name", [
    (RawUser(id=0, first_name="Kotik", username="kotik_2024"), "first", "Kotik"),
    (RawUser(id=0, first_name="Anna", username="anna_support"), "full", "Anna"),
    (RawUser(id=0, first_name="Максим", username="maxim"), "first", "Максим"),  # transliteration: out of scope
    (RawUser(id=0, first_name="Иван", last_name="Петров"), "full", "Иван Петров"),
    (RawUser(id=0, first_name="Northwind Support", username="northwind_support_bot", is_bot=True), "first",
     "Northwind Support"),
    (RawUser(id=0, first_name="Kotik", username="kotik", is_deleted=True), "first", "Deleted"),
    (RawUser(id=0, first_name="Kotik", username="kotik"), "none", ""),
    (RawUser(id=0, first_name="Vasya_Pupkin"), "first", ""),
])
def test_display_name_rule_leaves_other_names_alone(user, mode, name):
    assert display_name(user, mode) == name


def test_pipeline_drops_a_username_shaped_name_and_verify_regains_it(tmp_path):
    kotik = RawUser(id=41, first_name="Kotik", username="kotik")
    anna = RawUser(id=42, first_name="Anna", username="anna_support")
    outsider = RawUser(id=43, first_name="Радмир", last_name="Загребин", username="radmir_z")
    chat = RawChat(id=-4001, kind=KIND_SUPERGROUP, title="Acme Ltd", participant_ids=(1, 41, 42))
    store = make_store(tmp_path, [chat], [ME, kotik, anna, outsider], {chat.id: [
        msg(chat.id, 1, 41, "мой ник kotik, пишите kotik или @kotik"),
        msg(chat.id, 2, 42, "Anna тут, Kotik тоже; имя: Kotik, ник kotik"),
        msg(chat.id, 3, 41, "KOTIK_PROMO код 42, t.me/kotik и tg@kotik"),
        msg(chat.id, 4, 41, "fwd", forward=Forward(kind=FWD_USER, from_id=43)),
    ]})
    policy = AnonPolicy()
    mapping = Mapping(tmp_path / "anon" / "mapping.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), policy)
    k, a = mapping.user(41), mapping.user(42)
    assert (ds.users[k].name, ds.users[a].name) == ("", "Anna")
    assert [m.text for m in ds.messages] == [
        f"мой ник @{k}, пишите kotik или @{k}",   # a bare short username stays (documented residual)
        f"Anna тут, Kotik тоже; имя: Kotik, ник @{k}",
        f"KOTIK_PROMO код 42, <tg-link> и tg@{k}",
        "fwd",
    ]
    # A forward origin outside the exported chats keeps the usual first-name row.
    fwd = ds.users[mapping.user(43)]
    assert (fwd.name, fwd.role) == ("Радмир", "client") and ds.messages[3].forwarded == fwd.vid

    known = known_from_store(store, policy)
    assert "Kotik" not in known.keep_terms and "Anna" not in known.keep_terms  # only the operator's keep_terms
    scanner = LeakScanner(known)
    assert {l.match for l in scanner.scan("мой ник kotik")} == {"ник kotik"}
    assert scanner.scan("Kotik тут, Anna тоже") == []
    out, report = written_and_verified(ds, store, policy, tmp_path)
    assert report.ok, report.leaks
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "planted: ник kotik ; логин kotik ; @kotik"}, ensure_ascii=False) + "\n")
    planted = {l.match for l in verify(out, store, policy, tmp_path / "v.json").leaks if l.kind == "username"}
    assert planted == {"ник kotik", "логин kotik", "@kotik"}


def test_full_mode_pipeline_with_a_username_shaped_first_name(tmp_path):
    kotik = RawUser(id=2, first_name="Kotik", last_name="Smith", username="kotik")
    anna = RawUser(id=3, first_name="Anna", last_name="Smith", username="anna_support")
    chat = RawChat(id=-4002, kind=KIND_SUPERGROUP, title="Acme Ltd", participant_ids=(1, 2, 3))
    store = make_store(tmp_path, [chat], [ME, kotik, anna], {chat.id: [
        msg(chat.id, 1, 2, "Smith тут, Kotik Smith пишет, Anna Smith тоже"),
    ]})
    policy = AnonPolicy(name_mode="full")
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), policy)
    assert ds.users[mapping.user(2)].name == "" and ds.users[mapping.user(3)].name == "Anna Smith"
    assert ds.messages[0].text == "<name> тут, <name> пишет, <name> тоже"
    assert "Kotik Smith" in known_from_store(store, policy).names
    assert written_and_verified(ds, store, policy, tmp_path)[1].ok


# --- participant order --------------------------------------------------------------------

CLIENT_O = RawUser(id=200002, first_name="Ольга")
OUTSIDER = RawUser(id=500001, first_name="Анна")          # posted, then left the group
BOT = RawUser(id=300001, first_name="Northwind Bot", username="northwind_bot", is_bot=True)
MEMBERS = (ME.id, 1002, IVAN.id, CLIENT_O.id, BOT.id)
SALES = RawUser(id=1002, first_name="Мария", username="masha_sales")


def _group_store(tmp_path, name, participant_ids):
    chat = RawChat(id=-5001, kind=KIND_SUPERGROUP, title="Ромашка support", participant_ids=participant_ids)
    return make_store(tmp_path / name, [chat], [ME, SALES, IVAN, CLIENT_O, BOT, OUTSIDER], {chat.id: [
        msg(chat.id, 1, CLIENT_O.id, "Добрый день"),
        msg(chat.id, 2, OUTSIDER.id, "Подключаюсь"),
        msg(chat.id, 3, ME.id, "Смотрю", reply_to_id=1),
        msg(chat.id, 4, IVAN.id, "Спасибо"),
        msg(chat.id, 5, chat.id, "Объявление", sender_kind=SENDER_CHANNEL),
    ]}), chat


def test_participants_do_not_mirror_the_member_list_order(tmp_path):
    mapping = Mapping(tmp_path / "m.json")
    roles = Roles.build(ME.id, sales=["@masha_sales"])
    policy = AnonPolicy(keep_bot_messages=False)
    forward_store, chat = _group_store(tmp_path, "fwd", MEMBERS)
    reversed_store, _ = _group_store(tmp_path, "rev", tuple(reversed(MEMBERS)))
    ds_fwd = anonymize(forward_store, mapping, roles, policy)
    ds_rev = anonymize(reversed_store, mapping, roles, policy)
    vid = mapping.chat(chat.id)
    got = ds_fwd.chats[vid].participants
    expected = {mapping.user(u) for u in (*MEMBERS, OUTSIDER.id)}
    assert got == ds_rev.chats[vid].participants == sorted(expected)
    assert mapping.user(chat.id) not in got                   # the anonymous channel sender is no participant
    assert [m.seq for m in ds_fwd.messages] == [1, 2, 3, 4, 5]
    assert [m.sender for m in ds_fwd.messages[:4]] == [mapping.user(u) for u in (CLIENT_O.id, OUTSIDER.id, ME.id, IVAN.id)]
    assert ds_fwd.messages[2].reply_to == 1

    out, report = written_and_verified(ds_fwd, forward_store, policy, tmp_path / "fwd")
    assert report.ok, report.leaks
    assert json.loads((out / "chats.json").read_text())[vid]["participants"] == got
    header = next(l for l in (out / "transcripts" / f"{vid}.md").read_text().splitlines() if l.startswith("Participants:"))
    assert re.findall(r"U\d+", header) == got
    assert f"{mapping.user(BOT.id)} BOT Northwind Bot (bot)" in header  # a silent bot member is still listed
    for row in (out / "episodes.jsonl").read_text().splitlines():
        assert json.loads(row)["participants"] == sorted(json.loads(row)["participants"])


def test_participants_are_sorted_without_a_member_list(tmp_path):
    mapping = Mapping(tmp_path / "m.json")
    store, chat = _group_store(tmp_path, "hidden", ())
    ds = anonymize(store, mapping, Roles.build(ME.id), AnonPolicy())
    vid = mapping.chat(chat.id)
    assert ds.chats[vid].participants == sorted(mapping.user(u) for u in (CLIENT_O.id, OUTSIDER.id, ME.id, IVAN.id))
    ds.chats[vid].participants = []
    assert "Participants: unknown" in render_transcript(ds, ds.chats[vid], Output(max_chars=0))[0]


def test_participants_sort_deterministically_in_a_legacy_mixed_width_mapping(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"users": {str(ME.id): "U0042", str(IVAN.id): "U00043"}, "chats": {}}))
    store, chat = _group_store(tmp_path, "legacy", MEMBERS)
    mapping = Mapping.load(path)
    runs = [anonymize(store, mapping, Roles.build(ME.id), AnonPolicy()).chats[mapping.chat(chat.id)] for _ in range(2)]
    assert runs[0].participants == runs[1].participants == sorted(runs[0].participants)
    assert {"U0042", "U00043"} <= set(runs[0].participants)


# --- virtual id width ---------------------------------------------------------------------

def _widths(ids):
    return {len(v) for v in ids}


def test_width_and_value_range_do_not_change_with_allocation_count(tmp_path):
    m = Mapping(tmp_path / "m.json")
    users = [m.user(i) for i in range(1, 1001)]
    chats = [m.chat(i) for i in range(1, 6001)]
    assert all(re.fullmatch(r"U\d{5}", v) for v in users) and all(re.fullmatch(r"C\d{5}", v) for v in chats)
    assert all(1 <= int(v[1:]) <= 99_999 for v in users + chats)
    assert len(set(users)) == 1000 and len(set(chats)) == 6000


def test_incremental_runs_keep_the_width_and_the_ids(tmp_path):
    path = tmp_path / "m.json"
    m = Mapping(path)
    first = [m.user(i) for i in range(1, 461)]
    m.save()
    assert json.loads(path.read_text())["digits"] == {"U": Mapping.DIGITS, "C": Mapping.DIGITS}
    m2 = Mapping.load(path)
    second = [m2.user(i) for i in range(461, 1061)]
    assert _widths(first) == _widths(second) == {Mapping.DIGITS + 1}
    assert [m2.user(i) for i in range(1, 461)] == first


def test_legacy_mapping_without_digits_is_pinned_per_prefix(tmp_path):
    # Written by the old growing allocator: users stayed at 4 digits, chats had widened.
    path = tmp_path / "m.json"
    path.write_text(json.dumps({
        "users": {str(i): f"U{i:04d}" for i in range(1, 600)},
        "chats": {**{str(i): f"C{i:04d}" for i in range(1, 451)}, **{str(i): f"C{i:05d}" for i in range(451, 500)}}}))
    m = Mapping.load(path)
    assert _widths(m.user(i) for i in range(10_000, 10_100)) == {5}   # never widened, never re-padded
    assert _widths(m.chat(i) for i in range(10_000, 10_100)) == {6}   # follows the widest chat id
    assert m.user(1) == "U0001" and m.chat(1) == "C0001"
    m.save()
    assert json.loads(path.read_text())["digits"] == {"U": 4, "C": 5}


def test_exhausted_space_fails_loudly_instead_of_looping(tmp_path):
    m = Mapping(tmp_path / "m.json", digits={"U": 1, "C": 1})
    assert sorted(m.user(i) for i in range(1, 10)) == [f"U{d}" for d in range(1, 10)]
    with pytest.raises(AnonymizationError, match="virtual ids U#"):
        m.user(10)


@pytest.mark.parametrize("payload", [
    {"digits": "five", "users": {}, "chats": {}},
    {"digits": {"U": 0, "C": 5}, "users": {}, "chats": {}},
    {"digits": {"U": 5}, "users": {}, "chats": {}},
    {"digits": {"U": 4, "C": 4}, "users": {"1": "U00042"}, "chats": {}},  # narrower than a stored id
    {"users": {"1": "C0042"}, "chats": {}},                                 # wrong prefix
    {"users": {"1": "U00x2"}, "chats": {}},                                 # not an id
])
def test_corrupted_width_or_ids_are_reported(tmp_path, payload):
    path = tmp_path / "m.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(AnonymizationError, match="corrupted"):
        Mapping.load(path)


def test_virtual_ids_stay_below_the_raw_id_sweep():
    # The raw-id sweeps do not stop at a letter, so a virtual id as wide as a
    # hunted raw id would abort the self-check.
    assert Mapping.DIGITS < LeakScanner.MIN_ID_DIGITS
    assert LeakScanner(Known(user_ids=frozenset({12345})), regex_rules=False).scan("U12345 (client, Ivan): hi @U12345") == []


@pytest.mark.parametrize("text", [
    '[2024-01-10 12:05] #4 STAFF U48941 Anna (support) ↳#3 U12210 "Excel export fails with E1042, @U48941 '
    'please look": Ivan, looking into it',
    "(forwarded from U12345) (forwarded from C54321)",
    "U12345 U23456 U34567 U45678",
    "U04837 (client, Ivan): @U04837 please look at C12345, see scan_@U00042.pdf",
    "U0042 (client, Иван): @U04837 гляньте C12345 и C123456, cvv: U04837",
])
def test_scanner_accepts_virtual_ids_of_any_width(text):
    assert LeakScanner(Known()).scan(text) == []


@pytest.mark.parametrize("raw", [
    "RRN @ivan_petrov", "auth code @ivan_petrov, ок", "ИНН @ivan_petrov 500", "cvv @ivan_petrov",
    "индекс @ivan_petrov", "RRN: @romashka_support_chat",
])
def test_scanner_is_silent_on_a_mention_in_a_value_slot(raw):
    # "U04217" has the shape of a six-character auth code; it is still our id.
    roster = Roster(by_username={"ivan_petrov": "U04217", "romashka_support_chat": CHAT_VID})
    scanner = LeakScanner(Known(usernames=frozenset(roster.by_username)))
    out = Scrubber(AnonPolicy(), roster).scrub(raw)
    assert re.search(r"@(U04217|C01735)", out) and scanner.scan(out) == []
    assert [l.kind for l in scanner.scan(raw)] == ["username"]


@pytest.mark.parametrize("raw, scrubbed, kinds", [
    ("RRN A1B2C3", "RRN <txn-ref>", {"txn_ref"}),
    ("RRN @A1B2C3", "RRN @<txn-ref>", {"txn_ref", "handle"}),   # not a virtual id: still a value
])
def test_value_slot_guard_only_covers_virtual_ids(raw, scrubbed, kinds):
    assert Scrubber(AnonPolicy(), Roster()).scrub(raw) == scrubbed
    assert {l.kind for l in LeakScanner(Known()).scan(raw)} == kinds


def test_five_digit_roster_values_scrub_as_before():
    scrubber = Scrubber(AnonPolicy(), Roster(by_username={"alice": "U04837"}, by_user_id={777000123: "U04837"},
                                             known_ids=(777000123,)))
    assert scrubber.scrub("@alice wrote to 777000123, code: 123456, uid 777000123") == (
        "@U04837 wrote to <id>, code: <otp>, uid <id>")
    assert scrubber.scrub("id: @alice see scan_@alice.pdf") == "id: @U04837 see <email>"
    assert Scrubber(AnonPolicy(), Roster()).scrub("cvv: 1234") == "cvv: <cvv>"
    assert [l.kind for l in LeakScanner(Known()).scan("cvv: 1234")] == ["cvv"]
