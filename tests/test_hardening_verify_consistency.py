"""verify is silent on every clean dataset and loud on every planted leak.

A display name never shows somebody else's name, a forward author's surname
is removed by the same rule that hunts it, the transcript writer never cuts
through a rendering nor glues a keyword to the next part's value, and the
audit reads every file the directory holds.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from tg_collector.anonymize import Mapping, anonymize, display_name, vocabulary
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import (
    DATASET_README, FORMAT_VERSION, QUOTE_LINE_BREAK, _quote, _shorten, split_transcript_line, write_dataset,
)
from tg_collector.model import (
    FWD_HIDDEN, KIND_SUPERGROUP, SENDER_USER, Forward, Media, RawChat, RawMessage, RawUser, Roles,
)
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber
from tg_collector.verify import verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
CLIENT = RawUser(id=11, first_name="Иван", last_name="Петров")


def build(tmp_path, users, messages, policy=AnonPolicy(), output=None, title="Ромашка"):
    """Anonymize, write and verify one chat. ``messages`` are RawMessage
    keyword dicts without chat_id/date; they are numbered and spaced a
    minute apart."""
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title=title,
                   participant_ids=tuple(u.id for u in (ME, *users)))
    store.put_chats([chat])
    store.put_users([ME, *users])
    store.set_me_id(ME.id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, date=T0 + timedelta(minutes=i), sender_kind=SENDER_USER, **m)
        for i, m in enumerate(messages, 1)
    ])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    out = tmp_path / "dataset"
    write_dataset(ds, out, output or Output(), {})
    return ds, out, store, verify(out, store, policy, tmp_path / "verify_report.json")


def kept_name(tmp_path, user, policy=AnonPolicy(), others=()) -> str:
    vocab = vocabulary(_store_of(tmp_path, [user, *others]), policy)
    return vocab.kept_names[user.id]


def _store_of(tmp_path, users) -> RawStore:
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка",
                   participant_ids=tuple(u.id for u in (ME, *users)))
    store.put_chats([chat])
    store.put_users([ME, *users])
    store.set_me_id(ME.id)
    store.append_messages(chat.id, [RawMessage(chat_id=chat.id, id=1, date=T0, sender_id=users[0].id,
                                               sender_kind=SENDER_USER, text="привет")])
    return store


# --- a display name never shows somebody else's name -----------------------------------------

@pytest.mark.parametrize("first_name, expected", [
    ("Кузнецов", ""), ("Смирнова", ""), ("Кузнецов А.", ""), ("Кузнецов (Ромашка)", ""),
    ("Иван", "Иван"), ("Мирослава", "Мирослава"), ("Яков", "Яков"), ("Ярослав", "Ярослав"),
    ("Владислава", "Владислава"), ("Лев", "Лев"), ("Саныч", "Саныч"), ("Марина", "Марина"),
    ("Иванов Сергей", "Сергей"), ("Кузнецова Анна", "Анна"),
    ("Petrov", "Petrov"),  # Latin is judged by the vocabulary, not by the ending
])
def test_a_first_name_field_holding_only_a_surname_is_dropped(first_name, expected):
    assert display_name(RawUser(id=2, first_name=first_name), "first") == expected


def test_a_bot_keeps_a_surname_shaped_name_and_full_mode_keeps_both_fields():
    assert display_name(RawUser(id=2, first_name="Мониторов", is_bot=True), "first") == "Мониторов"
    assert display_name(RawUser(id=2, first_name="Иван", last_name="Кузнецов"), "full") == "Иван Кузнецов"


def test_a_lone_surname_is_dropped_from_users_json_and_from_the_text(tmp_path):
    users = [RawUser(id=12, first_name="Кузнецов"), RawUser(id=13, first_name="Смирнова")]
    ds, out, store, report = build(tmp_path, users, [
        dict(id=1, sender_id=12, text="Кузнецов, пришлите акт"),
        dict(id=2, sender_id=13, text="Смирновой отправили"),
    ], policy=AnonPolicy(name_mode="first"))
    assert {u.name for u in ds.users.values() if u.role == "client"} == {""}
    assert [m.text for m in ds.messages] == ["<name>, пришлите акт", "<name> отправили"]
    assert report.ok, report.leaks
    assert "Кузнецов" not in (out / "users.json").read_text(encoding="utf-8")


def test_a_lone_surname_stays_in_the_text_when_the_policy_keeps_last_names(tmp_path):
    policy = AnonPolicy(name_mode="first", scrub_last_names=False)
    ds, out, store, report = build(tmp_path, [RawUser(id=12, first_name="Кузнецов")], [
        dict(id=1, sender_id=12, text="Кузнецов, пришлите акт"),
    ], policy=policy)
    assert [m.text for m in ds.messages] == ["Кузнецов, пришлите акт"]
    assert all(u.name != "Кузнецов" for u in ds.users.values())
    assert report.ok, report.leaks


@pytest.mark.parametrize("user, expected", [
    (RawUser(id=12, first_name="Петрова"), ""),
    (RawUser(id=12, first_name="Petrov"), ""),
    (RawUser(id=12, first_name="Марина"), "Марина"),
    (RawUser(id=12, first_name="Иван"), "Иван"),
])
def test_a_first_name_that_spells_a_participants_surname_is_dropped(tmp_path, user, expected):
    others = [CLIENT, RawUser(id=13, first_name="Марин", last_name="Марин")]
    assert kept_name(tmp_path, user, AnonPolicy(name_mode="first"), others) == expected


@pytest.mark.parametrize("bot, expected", [
    (RawUser(id=51, first_name="Northwind Bot", is_bot=True), "Northwind Bot"),
    (RawUser(id=51, first_name="Олег Северов", is_bot=True), ""),
    (RawUser(id=51, first_name="Petrov Assistant", is_bot=True), ""),
])
def test_a_bot_named_after_a_person_loses_its_name(tmp_path, bot, expected):
    assert kept_name(tmp_path, bot, AnonPolicy(keep_terms=("Northwind",)), [CLIENT]) == expected


def test_full_mode_keeps_a_users_own_name(tmp_path):
    user = RawUser(id=12, first_name="Игорь", last_name="Коваль")
    assert kept_name(tmp_path, user, AnonPolicy(name_mode="full"), [CLIENT]) == "Игорь Коваль"


def test_a_dropped_display_name_leaves_a_clean_dataset(tmp_path):
    users = [CLIENT, RawUser(id=12, first_name="Петрова"), RawUser(id=51, first_name="Олег Северов", is_bot=True)]
    ds, out, store, report = build(tmp_path, users, [dict(id=1, sender_id=11, text="привет")],
                                   policy=AnonPolicy(keep_bot_messages=True))
    assert report.ok, report.leaks
    users_json = (out / "users.json").read_text(encoding="utf-8")
    for fragment in ("Петрова", "Северов"):
        assert fragment not in users_json, fragment


# --- a forward author's surname is removed by the rule that hunts it -------------------------

def test_a_forward_authors_surname_alone_is_removed_and_verifies(tmp_path):
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text="пересылаю", forward=Forward(kind=FWD_HIDDEN, from_name="Геннадий Громов")),
        dict(id=2, sender_id=11, text="Громов сказал, что всё ок"),
        dict(id=3, sender_id=11, text="Геннадий Громов в отпуске"),
    ])
    assert [m.text for m in ds.messages[1:]] == ["<name> сказал, что всё ок", "<name> в отпуске"]
    assert report.ok, report.leaks


def test_the_same_forward_leaves_the_text_alone_when_last_names_are_kept(tmp_path):
    policy = AnonPolicy(scrub_last_names=False)
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text="пересылаю", forward=Forward(kind=FWD_HIDDEN, from_name="Геннадий Громов")),
        dict(id=2, sender_id=11, text="Громов сказал, что всё ок"),
    ], policy=policy)
    assert ds.messages[1].text == "Громов сказал, что всё ок"
    assert report.ok, report.leaks


def test_a_post_author_surname_is_not_reported_when_last_names_are_kept(tmp_path):
    policy = AnonPolicy(scrub_last_names=False)
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text="привет", post_author="Ольга Сидорова"),
        dict(id=2, sender_id=11, text="Сидорова на связи"),
    ], policy=policy)
    assert report.ok, report.leaks


@pytest.mark.parametrize("from_name, text", [
    ("Магазин Цветов", "Цветов нет на складе"),          # a shop, not a person
    ("Отдел Продаж", "продажи выросли"),
    ("Служба Доставки", "Доставки нет на этой неделе"),
])
def test_a_forward_header_naming_a_team_or_a_shop_keeps_its_word(tmp_path, from_name, text):
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text="пересылаю", forward=Forward(kind=FWD_HIDDEN, from_name=from_name)),
        dict(id=2, sender_id=11, text=text),
    ])
    assert ds.messages[1].text == text


def test_a_forward_surname_that_is_not_spelled_like_one_stays_reported(tmp_path):
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text="пересылаю", forward=Forward(kind=FWD_HIDDEN, from_name="Иван Коваль")),
        dict(id=2, sender_id=11, text="Коваль сказал, что всё ок"),
    ])
    assert ds.messages[1].text == "Коваль сказал, что всё ок"
    assert {(l.kind, l.match) for l in report.leaks} == {("name", "Коваль")}


# --- the writer never cuts through a rendering ------------------------------------------------

def test_shorten_cuts_at_word_boundaries_and_counts_what_it_omits():
    text = "слово " * 60
    out = _shorten(text, 100)
    head, rest = out.split("\n[... ", 1)
    omitted, tail = rest.split(" chars omitted ...]\n", 1)
    assert head and text.startswith(head) and text.endswith(tail)
    assert set(head.split()) == set(tail.split()) == {"слово"}
    assert len(head) + int(omitted) + len(tail) == len(text)
    assert _shorten("короткий текст", 100) == "короткий текст"


def test_shorten_falls_back_to_a_hard_cut_for_one_long_word():
    out = _shorten("a" * 300, 100)
    assert "[... 200 chars omitted ...]" in out
    assert out.startswith("a" * 75) and out.endswith("a" * 25)


def test_a_quote_keeps_line_breaks_visible_and_cuts_at_a_word():
    def message(text):
        return {1: _msg(text)}
    assert _quote(message("строка1\nстрока2"), 1) == f'↳#1 U1 "строка1{QUOTE_LINE_BREAK}строка2"'
    assert _quote(message("короткий текст"), 1) == '↳#1 U1 "короткий текст"'
    assert _quote(message("z" * 80), 1) == '↳#1 U1 "' + "z" * 57 + '..."'


def _msg(text):
    from tg_collector.dataset import AnonMessage
    return AnonMessage(chat="C1", seq=1, date=T0, sender="U1", role="client", side="CLIENT", text=text)


@pytest.mark.parametrize("prefix", [32, 33, 34, 40])
def test_a_quoted_link_is_never_cut_in_half(tmp_path, prefix):
    text = "x" * prefix + " см https://shop.example.com/login ok"
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text=text),
        dict(id=2, sender_id=1, text="сейчас проверю", reply_to_id=1),
    ], policy=AnonPolicy(url_mode="domain"))
    assert report.ok, report.leaks
    transcript = next((out / "transcripts").glob("*.md")).read_text(encoding="utf-8")
    line = next(l for l in transcript.splitlines() if "↳#1" in l and l.startswith("["))
    assert "shop.example.co" not in line or "<url:shop.example.com>" in line


@pytest.mark.parametrize("tail", [3, 5, 8, 12, 20, 30])
def test_a_shortened_link_is_never_cut_in_half(tmp_path, tail):
    text = "слово " * 40 + " see https://shop.example.com/pay/1 " + "z" * tail
    ds, out, store, report = build(tmp_path, [CLIENT], [dict(id=1, sender_id=11, text=text)],
                                   policy=AnonPolicy(url_mode="domain"),
                                   output=Output(max_message_chars=100))
    assert report.ok, report.leaks


@pytest.mark.parametrize("tail", [2, 4, 6, 9, 14, 22])
def test_a_kept_hosts_subdomain_is_never_cut_in_half(tmp_path, tail):
    policy = AnonPolicy(url_mode="keep", allow_domains=("example.com",))
    text = "слово " * 40 + " https://secret.example.com/pay " + "z" * tail
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text=text),
        dict(id=2, sender_id=1, text="ок", reply_to_id=1),
    ], policy=policy, output=Output(max_message_chars=100))
    assert report.ok, report.leaks


# --- a transcript line is audited in the parts the writer composed ---------------------------

@pytest.mark.parametrize("first, second", [
    ("Не могу войти, подскажите пароль", "Добрый день, сейчас проверю"),
    ("забыл пароль", "Добрый день"),
    ("как сменить пароль", "сейчас пришлю инструкцию"),
    ("какой логин", "Olga, hello"),
])
def test_a_keyword_at_the_end_of_a_quote_claims_nothing_from_the_reply(tmp_path, first, second):
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text=first),
        dict(id=2, sender_id=1, text=second, reply_to_id=1),
    ])
    assert report.ok, report.leaks


def test_an_address_keyword_before_a_media_reply_claims_nothing(tmp_path):
    ds, out, store, report = build(tmp_path, [CLIENT], [
        dict(id=1, sender_id=11, text="адрес доставки"),
        dict(id=2, sender_id=1, text="", reply_to_id=1, media=Media(kind="photo", size=45_000)),
    ])
    assert report.ok, report.leaks


def test_a_display_name_that_is_a_handle_keyword_claims_nothing_from_the_body(tmp_path):
    ds, out, store, report = build(tmp_path, [RawUser(id=11, first_name="Nick", last_name="Brown")], [
        dict(id=1, sender_id=11, text="Hello, I have a problem"),
    ])
    assert report.ok, report.leaks
    assert any(u.name == "Nick" for u in ds.users.values())


@pytest.mark.parametrize("line, parts", [
    ('[2024-01-10 09:02] #2 STAFF U1 Олег (support): текст',
     ('[2024-01-10 09:02] #2 STAFF U1 Олег (support)', 'текст')),
    ('[2024-01-10 09:02] #2 STAFF U1 Олег (support) ↳#1 U2 "вопрос": ответ',
     ('[2024-01-10 09:02] #2 STAFF U1 Олег (support) ↳#1 U2', 'вопрос', 'ответ')),
    ('    #3: продолжение', ('    #3', 'продолжение')),
    ('[2024-01-10 09:02] #2 STAFF U1 X (forwarded from U9): текст',
     ('[2024-01-10 09:02] #2 STAFF U1 X', ' (forwarded from U9)', 'текст')),
    ('## Episode 1 - 2024-01-10 09:01 .. 09:02 (2 messages)',
     ('## Episode 1 - 2024-01-10 09:01 .. 09:02 (2 messages)',)),
    ('Participants: U1 STAFF Олег (support)', ('Participants: U1 STAFF Олег (support)',)),
])
def test_a_transcript_line_splits_into_the_parts_the_writer_composed(line, parts):
    assert split_transcript_line(line) == parts


def test_a_leak_planted_in_a_transcript_body_is_still_reported(tmp_path):
    ds, out, store, report = build(tmp_path, [CLIENT], [dict(id=1, sender_id=11, text="привет")])
    assert report.ok, report.leaks
    path = next((out / "transcripts").glob("*.md"))
    lines = path.read_text(encoding="utf-8").splitlines()
    body = next(i for i, l in enumerate(lines) if l.endswith(": привет"))
    lines[body] = lines[body].replace("привет", "пишите на ivan@example.com")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    leaks = verify(out, store, AnonPolicy(), tmp_path / "again.json").leaks
    assert ("email", "ivan@example.com") in {(l.kind, l.match) for l in leaks}


def test_a_pasted_chat_header_in_a_transcript_body_is_still_reported(tmp_path):
    ds, out, store, report = build(tmp_path, [CLIENT], [dict(id=1, sender_id=11, text="привет")])
    path = next((out / "transcripts").glob("*.md"))
    text = path.read_text(encoding="utf-8").replace(": привет", ": Пётр Сидоров, [12.03.2024 10:15]")
    path.write_text(text, encoding="utf-8")
    leaks = verify(out, store, AnonPolicy(), tmp_path / "again.json").leaks
    assert "td_header" in {l.kind for l in leaks}


def test_a_secret_hand_edited_into_messages_jsonl_is_still_reported(tmp_path):
    ds, out, store, report = build(tmp_path, [CLIENT], [dict(id=1, sender_id=11, text="привет")])
    path = out / "messages.jsonl"
    path.write_text(path.read_text(encoding="utf-8").replace("привет", "пароль: Qwerty123"), encoding="utf-8")
    leaks = verify(out, store, AnonPolicy(), tmp_path / "again.json").leaks
    assert "password" in {l.kind for l in leaks}


# --- a value wrapped over a line break --------------------------------------------------------

@pytest.mark.parametrize("raw, scrubbed", [
    ("e-mail: ivan.sidorov\n@example.com", "e-mail: <email>"),
    ("почта ivan\n@example.com", "почта <email>"),
    ("ivan.sidorov@\nexample.com", "<email>"),
    ("СНИЛС 112-233\n445 95", "СНИЛС <snils>"),
    ("СНИЛС 112-233-445 95\n8 999 123-45-67", "СНИЛС <snils>\n<phone>"),
])
def test_a_value_wrapped_over_one_line_break_is_still_removed(raw, scrubbed):
    scrubber = Scrubber(AnonPolicy(), Roster())
    scanner = LeakScanner(Known())
    assert scrubber.scrub(raw) == scrubbed
    assert scanner.scan(raw), "the scanner must see what the scrubber removes"
    assert scanner.scan(scrubbed) == []


@pytest.mark.parametrize("text", ["спасибо\n@mail.ru", "ошибка\n@example.com", "см. док\n@docs.example.com/page"])
def test_a_russian_word_above_an_at_line_is_not_read_as_an_address(text):
    """An e-mail local part is ASCII, so the word above such a line stays."""
    assert Scrubber(AnonPolicy(), Roster()).scrub(text).startswith(text.split("\n")[0])


@pytest.mark.parametrize("text", [
    "Ошибки 4001\n4002\n4003",
    "суммы\n1500\n2300\n4500",
    "Итого:\n1500 2300\n4500 1200",
])
def test_product_knowledge_under_each_other_survives_and_stays_silent(text):
    scrubber = Scrubber(AnonPolicy(), Roster())
    assert scrubber.scrub(text) == text


@pytest.mark.parametrize("text", [
    "Ошибки 4001\n4002\n4003",
    "суммы\n1500\n2300\n4500",
    "ошибки\n4242\n4242\n4242\n4242",
    "карта 4000 0000\n0000 0002",
])
def test_a_reply_quote_never_changes_the_verdict(tmp_path, text):
    alone = build(tmp_path / "a", [CLIENT], [dict(id=1, sender_id=11, text=text)])[3]
    quoted = build(tmp_path / "b", [CLIENT], [
        dict(id=1, sender_id=11, text=text),
        dict(id=2, sender_id=1, text="ок", reply_to_id=1),
    ])[3]
    assert {(l.kind, l.match) for l in alone.leaks} == {(l.kind, l.match) for l in quoted.leaks}
    assert alone.ok and quoted.ok, (alone.leaks, quoted.leaks)


# --- every file of the dataset is read ---------------------------------------------------------

PAYLOAD = "Иван Петров @ivan_petrov +7 999 123-45-67 ivan@example.com"


def _planted(tmp_path):
    client = RawUser(id=11, first_name="Иван", last_name="Петров", username="ivan_petrov", phone="+79991234567")
    return build(tmp_path, [client], [dict(id=1, sender_id=11, text="привет")],
                 output=Output(max_chars=10_000))


def test_a_clean_dataset_is_silent_although_every_file_is_read(tmp_path):
    ds, out, store, report = _planted(tmp_path)
    assert report.ok, report.leaks
    assert report.files_scanned >= 8  # README and chunks/index.json are counted in


@pytest.mark.parametrize("name", ["notes.txt", "export.csv", "extra.JSONL", "transcripts/README.md"])
def test_a_leak_in_a_foreign_file_is_reported(tmp_path, name):
    ds, out, store, report = _planted(tmp_path)
    (out / name).write_text(PAYLOAD + "\n", encoding="utf-8")
    leaks = verify(out, store, AnonPolicy(), tmp_path / "again.json").leaks
    assert {"username", "phone", "email"} <= {l.kind for l in leaks}, leaks


def test_a_leak_planted_as_a_json_key_is_reported(tmp_path):
    ds, out, store, report = _planted(tmp_path)
    rows = json.loads((out / "users.json").read_text(encoding="utf-8"))
    rows[PAYLOAD] = {"name": "", "role": "client", "side": "CLIENT"}
    (out / "users.json").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    index = json.loads((out / "chunks" / "index.json").read_text(encoding="utf-8"))
    index[PAYLOAD] = []
    (out / "chunks" / "index.json").write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")
    leaks = verify(out, store, AnonPolicy(), tmp_path / "again.json").leaks
    for location in ("users.json", "chunks/index.json"):
        kinds = {l.kind for l in leaks if l.location.startswith(location)}
        assert {"username", "phone", "email"} <= kinds, (location, leaks)


def test_the_datasets_own_readme_is_skipped_only_while_it_is_untouched(tmp_path):
    ds, out, store, report = _planted(tmp_path)
    assert (out / "README.md").read_text(encoding="utf-8") == DATASET_README.format(version=FORMAT_VERSION)
    assert not [l for l in report.leaks if l.location.startswith("README.md")]
    with open(out / "README.md", "a", encoding="utf-8") as fh:
        fh.write("\n" + PAYLOAD + "\n")
    leaks = verify(out, store, AnonPolicy(), tmp_path / "again.json").leaks
    assert {"username", "phone", "email"} <= {l.kind for l in leaks if l.location.startswith("README.md")}


def test_a_raw_id_planted_as_a_key_is_reported(tmp_path):
    client = RawUser(id=200001, first_name="Иван", last_name="Петров")
    ds, out, store, report = build(tmp_path, [client], [dict(id=1, sender_id=200001, text="привет")])
    rows = json.loads((out / "users.json").read_text(encoding="utf-8"))
    rows["200001"] = {"name": "", "role": "client", "side": "CLIENT"}
    (out / "users.json").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    leaks = verify(out, store, AnonPolicy(), tmp_path / "again.json").leaks
    assert "user_id" in {l.kind for l in leaks}, leaks


# --- a placeholder glued to a word is nobody's value ------------------------------------------

@pytest.mark.parametrize("raw, scrubbed", [
    ("@some_buyerу2 ок", "@userу2 ок"),
    ("ivan_petrovу_x", "@U04217у_x"),
    ("ivan_petrovу2", "@U04217у2"),
    ("@ivan_petrovу ок", "@U04217 ок"),
    ("@some_buyerом тоже", "@user тоже"),
    ("pip install romashka-pay==4.1.0", "pip install <org>-pay==4.1.0"),
    ("docker pull romashka-php:8.2-fpm", "docker pull <org>-php:8.2-fpm"),
])
def test_a_case_ending_glued_to_a_handle_never_makes_a_new_one(raw, scrubbed):
    roster = Roster(by_username={"ivan_petrov": "U04217"}, org_terms=("Romashka", "Ромашка"))
    assert Scrubber(AnonPolicy(), roster).scrub(raw) == scrubbed
    assert LeakScanner(Known()).scan(scrubbed) == []


@pytest.mark.parametrize("raw, scrubbed", [
    ("mysql -u root -pS3cretPass", "mysql -u root -p<password>"),
    ("mysql -u root -p secret99", "mysql -u root -p <password>"),
])
def test_a_command_line_password_flag_still_fires(raw, scrubbed):
    assert Scrubber(AnonPolicy(), Roster()).scrub(raw) == scrubbed
    assert "password" in {l.kind for l in LeakScanner(Known()).scan(raw)}
