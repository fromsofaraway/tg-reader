"""Anonymize -> write -> verify hardening on a synthetic raw store: names in
the first-name field, nickname-shaped names, forward-header names, kept
names shared with verify, decoded-JSON scanning."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import PEM_BODY, PEM_TAIL, SENDGRID, pem_begin, pem_block
from tg_collector.anonymize import Mapping, anonymize, display_name, split_free_text_name, vocabulary
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import FWD_HIDDEN, KIND_SUPERGROUP, SENDER_USER, Forward, Media, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support", phone="79990000001")
USERS = [
    ME,
    RawUser(id=11, first_name="Иван Петров"), RawUser(id=12, first_name="Иванов Сергей"), RawUser(id=13, first_name="Anna Smirnova"),
    RawUser(id=14, first_name="Ирина Петрова"), RawUser(id=15, first_name="Лев Толстов"), RawUser(id=16, first_name="Sergey CEO"),
    RawUser(id=17, first_name="Vasya_Pupkin"), RawUser(id=18, first_name="vasya.pupkin"), RawUser(id=19, first_name="VasyaPupkin"),
    RawUser(id=20, first_name="Ivan|Sidorov"), RawUser(id=21, first_name="Ромашка_support"),
    RawUser(id=23, first_name="Анна-Мария", last_name="Кузнецова"), RawUser(id=24, first_name="O'Brien"),
    RawUser(id=25, first_name="Ромашка"), RawUser(id=26, first_name="Петров"), RawUser(id=27, first_name="Northwind Bot", is_bot=True),
]
POLICY = AnonPolicy(keep_terms=("Northwind",), keep_file_names=True)


def msg(chat, mid, sender, text, **kw):
    return RawMessage(chat_id=chat.id, id=mid, date=T0 + timedelta(minutes=mid), sender_id=sender, sender_kind=SENDER_USER, text=text, **kw)


@pytest.fixture
def store(tmp_path):
    s = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="ООО Ромашка × Northwind support", participant_ids=tuple(u.id for u in USERS))
    others = [RawChat(id=-1002, kind=KIND_SUPERGROUP, title="Василёк / Northwind", participant_ids=(1, 11)),
              RawChat(id=-1003, kind=KIND_SUPERGROUP, title="Лютик / Northwind", participant_ids=(1, 11))]
    s.put_chats([chat, *others])
    s.put_users(USERS)
    s.set_me_id(1)
    s.append_messages(chat.id, [
        msg(chat, 1, 11, "Добрый день, Иван Петров! Петров, пришлите лог"),
        msg(chat, 2, 12, "это Сергей Иванов, Иванов Сергей передайте привет; Smirnova спасибо"),
        msg(chat, 3, 11, "Иван, смотрю. Иванов тоже. Ивана видел", post_author="Иван"),
        msg(chat, 4, 11, "спросите Ивана Петрова; Petrov ok", forward=Forward(kind=FWD_HIDDEN, from_name="Иван Петров")),
        msg(chat, 5, 11, "привет от Анны", forward=Forward(kind=FWD_HIDDEN, from_name="Анна")),
        msg(chat, 6, 11, "паспорт: 4509 123456, password: hunter2, тел.89991234567 и 8\u2011999\u2011000\u201100\u201101"),
        msg(chat, 7, 11, "", media=Media(kind="document", ext="log", file_name="romashka_export.log")),
    ])
    for c in others:
        s.append_messages(c.id, [msg(c, 1, 11, "ok")])
    return s


def test_free_text_names_and_nicknames(store, tmp_path):
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(1), POLICY)
    names = {u.id: ds.users[mapping.user(u.id)].name for u in USERS}
    assert names[11] == "Иван" and names[12] == "Сергей" and names[13] == "Anna" and names[14] == "Ирина" and names[15] == "Лев"
    assert names[16] == "Sergey" and names[23] == "Анна-Мария" and names[24] == "O'Brien" and names[27] == "Northwind Bot"
    assert all(names[i] == "" for i in (17, 18, 19, 20, 21, 25, 26))
    joined = "\n".join(m.text for m in ds.messages)
    for leak in ("Петров", "Иванов", "Smirnova", "Vasya_Pupkin", "romashka"):
        assert leak not in joined
    assert "Сергей" in joined and "Иван, смотрю" in joined and "привет от Анны" in joined
    assert "спросите <name>; <name> ok" in joined
    assert "паспорт: <passport>, password: <password>, тел.<phone> и <phone>" in joined
    assert [m.media["name"] for m in ds.messages if m.media] == ["<org>_export.log"]
    vocab = vocabulary(store, POLICY)
    assert all(vocab.kept_names[u.id] == names[u.id] for u in USERS)


def test_verify_makes_exactly_the_scrubbers_exceptions(store, tmp_path):
    # Only the operator's keep_terms are exceptions, as in the scrubber: a
    # kept display name is not, so "менеджер Анна Смирнова" in text is still
    # audited; verify skips people's names only in the fields that show
    # kept names on purpose.
    known = known_from_store(store, POLICY)
    assert known.keep_terms == frozenset(POLICY.keep_terms)
    assert "Иван" not in known.keep_terms and "Anna" not in known.keep_terms
    assert "Петров" in known.names and "Ромашка" in known.titles
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), POLICY)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(), {})
    assert verify(out, store, POLICY, tmp_path / "v.json").ok
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "менеджер Иван Смирнов на связи, Петрову передал"}, ensure_ascii=False) + "\n")
    leaks = {(l.kind, l.match) for l in verify(out, store, POLICY, tmp_path / "v.json").leaks}
    assert ("name", "Петрову") in leaks and ("person", "менеджер Иван Смирнов") in leaks


def test_verify_scans_decoded_json(store, tmp_path):
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(1), POLICY)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(), {})
    report = tmp_path / "verify_report.json"
    assert verify(out, store, POLICY, report).ok
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "planted: Ромашка, Петров, Петрову", "media": {"name": "Петров.pdf"}}, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"text": "карта\n5105 1051 0510 5100\nИНН:\n7700000425\nС уважением,\nПетров"}, ensure_ascii=False) + "\n")
        fh.write(json.dumps({"text": "5105\t1051\t0510\t5100"}) + "\n")
        fh.write(json.dumps({"text": "8 999 123-45-67\n8 999 765-43-21"}) + "\n")
    vr = verify(out, store, POLICY, report)
    kinds = vr.by_kind()
    assert {"name", "title", "card", "inn", "phone"} <= set(kinds) and kinds["card"] == 2 and kinds["phone"] == 2
    locations = {l.location for l in vr.leaks}
    assert any(loc.endswith(":media.name") for loc in locations)
    assert any(l.kind == "card" and l.match == "5105 1051 0510 5100" for l in vr.leaks)


def test_name_mode_none_keeps_word_like_first_names(tmp_path):
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-2001, kind=KIND_SUPERGROUP, title="X", participant_ids=(1, 31, 32))
    store.put_chats([chat])
    store.put_users([ME, RawUser(id=31, first_name="Тема"), RawUser(id=32, first_name="Максим")])
    store.set_me_id(1)
    store.append_messages(chat.id, [msg(chat, 1, 31, "тема закрыта, максимум 5 карт"), msg(chat, 2, 32, "Максим, привет"),
                                    msg(chat, 3, 31, "Иван, смотрю", post_author="Иван")])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), AnonPolicy(name_mode="none"))
    assert [m.text for m in ds.messages] == ["тема закрыта, максимум 5 карт", "<name>, привет", "<name>, смотрю"]
    # A real first name: the operator is told, the shareable manifest is not.
    assert ds.private["first_names_kept_as_words"] == ["Тема"]
    assert "first_names_kept_as_words" not in ds.notes


def test_split_free_text_name_and_display_name():
    assert split_free_text_name(RawUser(id=0, first_name="Иванов Сергей")) == ("Сергей", ("Иванов",))
    assert split_free_text_name(RawUser(id=0, first_name="Sergey CEO")) == ("Sergey", ())
    assert split_free_text_name(RawUser(id=0, first_name="+7 999 000-00-00")) == ("+7", ())
    assert split_free_text_name(RawUser(id=0, first_name="Northwind Support Team")) == ("Northwind", ())
    assert split_free_text_name(RawUser(id=0, first_name="Иван Петров", last_name="Сидоров")) == ("Иван", ())
    assert display_name(RawUser(id=0, first_name="Иван", last_name="Петров"), "full") == "Иван Петров"
    assert display_name(RawUser(id=0, first_name="Zoë"), "first") == "Zoë"
    for nick in ("Vasya_Pupkin", "vasya.pupkin", "VasyaPupkin", "Ivan|Sidorov", "Иван."):
        assert display_name(RawUser(id=0, first_name=nick), "first") == ""
    swapped = RawUser(id=0, first_name="Сидоров", last_name="Иван")
    assert display_name(swapped, "first", given_names={"иван": 1, "сидоров": 1}) == ""
    assert display_name(RawUser(id=0, first_name="Иван", last_name="Петров"), "first", given_names={"иван": 2}) == "Иван"


def test_bracketed_link_survives_anonymize_and_verify(tmp_path):
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-2002, kind=KIND_SUPERGROUP, title="Ромашка / Northwind", participant_ids=(1, 11))
    store.put_chats([chat])
    store.put_users([ME, RawUser(id=11, first_name="Иван")])
    store.set_me_id(1)
    store.append_messages(chat.id, [msg(chat, 1, 11, "см http://[::1]:8000/x"),
                                    msg(chat, 2, 11, "перейдите по http://[ваш-домен]/admin")])
    for mode in ("drop", "keep", "domain"):
        policy = AnonPolicy(keep_terms=("Northwind",), url_mode=mode)
        ds = anonymize(store, Mapping(tmp_path / f"m-{mode}.json"), Roles.build(1), policy)
        expected = {"drop": "см <url>", "keep": "см http://[::1]:8000/x", "domain": "см <url:[::1]>"}[mode]
        assert [m.text for m in ds.messages] == [expected, "перейдите по <url>"]
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), POLICY)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(), {})
    report = tmp_path / "verify_report.json"
    assert verify(out, store, POLICY, report).ok
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "перейдите по http://[ваш-домен]/admin"}, ensure_ascii=False) + "\n")
    vr = verify(out, store, POLICY, report)
    assert [(l.kind, l.match) for l in vr.leaks] == [("url", "http://[ваш-домен]/admin")]


def test_pasted_secrets_leave_no_fragment_in_the_dataset(tmp_path):
    pem = pem_block()
    texts = [
        f"вот ключ:\n{pem}\nподпись не проходит",
        '{"private_key": "' + pem.replace("\n", "\\n") + '\\n", "client_email": "svc@acme.example.com"}',
        f'PRIVATE_KEY="{pem}"',
        f"пароль: {pem}",
        f"SENDGRID_API_KEY={SENDGRID} и просто {SENDGRID}",
        'curl -u admin:S3cretPass -H "Authorization: Basic YWRtaW46UzNjcmV0UGFzcw==" https://api.acme.com/v1',
        'mysql -u root -pS3cretPass; {"password": "Summer#2024"}; DB_PASSWORD=Summer#2024; токен доступа: AbCdEfGh1234567890',
    ]
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-2003, kind=KIND_SUPERGROUP, title="Ромашка / Northwind", participant_ids=(1, 11))
    store.put_chats([chat])
    store.put_users([ME, RawUser(id=11, first_name="Иван")])
    store.set_me_id(1)
    store.append_messages(chat.id, [msg(chat, i + 1, 11, t) for i, t in enumerate(texts)])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), POLICY)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(), {})
    assert verify(out, store, POLICY, tmp_path / "verify_report.json").ok
    written = "\n".join(p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file())
    for fragment in (PEM_BODY, PEM_TAIL, SENDGRID.split(".")[1], "S3cretPass", "YWRtaW46", "Summer", "#2024", "AbCdEfGh"):
        assert fragment not in written, fragment
    assert written.count("<private-key>") >= 4 and pem_begin() in written
