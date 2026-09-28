"""Vocabulary built from titles, handles and ids: a chat title that names a
feature keeps that feature word in the corpus, a public chat handle that is an
ordinary product word is replaced only where it is written as a handle, the
"-100" ids of chats the export never saw are removed, contact names from the
dialog catalogue are removed as whole phrases, and a conversation keeps its
virtual id when its migration to a supergroup shows up in a later export.

Every rule is checked in both directions: the identifying form is scrubbed and
flagged by the scanner, product knowledge stays byte-identical with the scanner
silent, and no placeholder is ever flagged.
"""

import argparse
import json
from datetime import datetime, timedelta, timezone

import pytest

from tg_collector import cli
from tg_collector.anonymize import Mapping, anonymize, vocabulary
from tg_collector.config import AnonPolicy, Output, Settings
from tg_collector.dataset import write_dataset
from tg_collector.model import (
    FWD_CHAT, FWD_CHANNEL, FWD_USER, KIND_BOT, KIND_GROUP, KIND_PRIVATE, KIND_SUPERGROUP, SENDER_CHANNEL,
    SENDER_USER, Forward, RawChat, RawMessage, RawUser, Roles,
)
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber, org_terms_from_titles
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 3, 4, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
IVAN = RawUser(id=2, first_name="Ivan", username="ivan_client")
OUTPUT = Output(timezone="Europe/Berlin")
MAIN = -1001000000001

# Every placeholder the scrubber writes: the scanner must never flag one.
PLACEHOLDERS = ("<email> <phone> <url> <tg-link> <ip> <iban> <token> <name> <org> @user <id> <redacted> <inn> "
                "<ogrn> <snils> <account> <passport> 424242********** <card> <otp> <password>")


def msg(chat_id, mid, text, sender=IVAN.id, **kw):
    kind = kw.pop("sender_kind", SENDER_USER)
    return RawMessage(chat_id=chat_id, id=mid, date=T0 + timedelta(minutes=mid), sender_id=sender,
                      sender_kind=kind, text=text, **kw)


def make_store(tmp_path, chats, messages, users=(ME, IVAN)):
    store = RawStore(tmp_path / "raw")
    store.set_me_id(ME.id)
    store.put_users(list(users))
    store.put_chats(list(chats))
    for chat_id, rows in messages.items():
        store.append_messages(chat_id, rows)
    return store


def text_of(ds, mapping, raw_chat_id):
    """The text of the single message of one chat, addressed by its raw id."""
    return next(m.text for m in ds.messages if m.chat == mapping.chat(raw_chat_id))


def verified(ds, store, policy, tmp_path):
    out = tmp_path / "anon" / "dataset"
    write_dataset(ds, out, OUTPUT, {})
    return verify(out, store, policy, tmp_path / "anon" / "verify_report.json")


# --- chat titles that name a feature ---------------------------------------------------------

FEATURE_TITLES = [
    "Acme Ltd / Northwind: подключение", "Василёк — Northwind Касса", "Ромашка — вебхуки", "Роза — СБП",
    "Пион — 3DS", "Лотос / ККТ / ОФД", "Ромашка [прод]", "Астра — личный кабинет", "Незабудка — SberPay",
    "Ирис — песочница и миграция", "Мимоза — сверка и отчёты", "Клевер — возвраты и чеки",
    "Гортензия — подписки", "Тюльпан — оплата и фискализация", "Пальма — checkout и webhooks",
]
FEATURE_ORG_TERMS = ("Acme", "Northwind", "SberPay", "Астра", "Василёк", "Гортензия", "Ирис", "Клевер", "Лотос",
                     "Мимоза", "Незабудка", "Пальма", "Пион", "Роза", "Ромашка", "Тюльпан")

PRODUCT_KNOWLEDGE = [
    "Подключение займёт 2 дня, касса нужна",
    "Настройте вебхуки и проверьте возвраты",
    "по СБП лимит 1 000 000",
    "3DS обязателен для подписки",
    "в личном кабинете включите прод, песочница отдельно",
    "сверка и отчёты приходят в ОФД, чеки бьёт ККТ",
    "оплата через checkout, webhooks приходят на sandbox",
    "миграция на новый эквайринг, фискализация без сплита",
]


def test_feature_words_of_titles_are_not_organisation_terms():
    org, candidates = org_terms_from_titles(FEATURE_TITLES, 0.3)
    assert tuple(org) == FEATURE_ORG_TERMS
    assert candidates == []


@pytest.mark.parametrize("title, org", [
    ("Acme Ltd / Northwind: подключение", ["Acme", "Northwind"]),
    ("Лотос / ККТ / ОФД", ["Лотос"]),
    ("Ромашка — вебхуки", ["Ромашка"]),
    ("Астра — SberPay", ["Astra".replace("Astra", "SberPay"), "Астра"]),
])
def test_one_title_keeps_only_its_client_name(title, org):
    assert org_terms_from_titles([title], 0.3)[0] == sorted(org)


@pytest.mark.parametrize("text", PRODUCT_KNOWLEDGE)
def test_feature_words_survive_the_scrubber_and_the_scanner(text):
    scrubber = Scrubber(AnonPolicy(), Roster(org_terms=FEATURE_ORG_TERMS))
    assert scrubber.scrub(text) == text
    assert LeakScanner(Known(titles=frozenset(FEATURE_ORG_TERMS))).scan(text) == []


@pytest.mark.parametrize("raw, scrubbed", [
    ("Ромашка подключила кассу", "<org> подключила кассу"),
    ("переходите на SberPay", "переходите на <org>"),
    ("Незабудка и Василёк ждут вебхуки", "<org> и <org> ждут вебхуки"),
])
def test_client_names_of_the_same_titles_are_still_scrubbed(raw, scrubbed):
    assert Scrubber(AnonPolicy(), Roster(org_terms=FEATURE_ORG_TERMS)).scrub(raw) == scrubbed
    scanner = LeakScanner(Known(titles=frozenset(FEATURE_ORG_TERMS)))
    assert [l.kind for l in scanner.scan(raw)] == ["title"] * scrubbed.count("<org>")
    assert scanner.scan(scrubbed) == []
    assert scanner.scan(PLACEHOLDERS) == []


def test_a_feature_title_leaves_the_corpus_intact_end_to_end(tmp_path):
    text = "Настройте вебхуки, проверьте возвраты в личном кабинете, по СБП лимит 1 000 000"
    chats = [RawChat(id=MAIN, kind=KIND_SUPERGROUP, title="Ромашка — вебхуки, возвраты, СБП"),
             RawChat(id=MAIN - 1, kind=KIND_SUPERGROUP, title="Василёк — личный кабинет")]
    store = make_store(tmp_path, chats, {MAIN: [msg(MAIN, 1, text)],
                                         MAIN - 1: [msg(MAIN - 1, 2, "Ромашка ждёт возвраты")]})
    policy = AnonPolicy()
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    assert sorted(m.text for m in ds.messages) == sorted([text, "<org> ждёт возвраты"])
    assert verified(ds, store, policy, tmp_path).leaks == []


# --- public chat handles that are ordinary product words -------------------------------------

PRODUCT_CHATS = [
    RawChat(id=MAIN, kind=KIND_SUPERGROUP, title="Ромашка", username="payments"),
    RawChat(id=MAIN - 1, kind=KIND_SUPERGROUP, title="Василёк", username="sandbox_api"),
    RawChat(id=MAIN - 2, kind=KIND_SUPERGROUP, title="Лотос", username="romashka_support"),
]


def product_chat_store(tmp_path, text):
    """Every public chat carries a message, so every username is exported."""
    return make_store(tmp_path, PRODUCT_CHATS,
                      {c.id: [msg(c.id, 1 + i, text if c.id == MAIN else "ok")]
                       for i, c in enumerate(PRODUCT_CHATS)})


def test_a_product_word_handle_is_replaced_only_where_it_is_a_handle(tmp_path):
    text = ("Метод payments/create возвращает 500, sandbox_api недоступен, "
            "пишите в @payments, ник: payments, t.me/payments")
    store = product_chat_store(tmp_path, text)
    policy = AnonPolicy()
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), policy)
    payments, sandbox = mapping.chat(MAIN), mapping.chat(MAIN - 1)
    assert text_of(ds, mapping, MAIN) == (f"Метод payments/create возвращает 500, sandbox_api недоступен, "
                                          f"пишите в @{payments}, ник: @{payments}, <tg-link>")
    assert sandbox not in text_of(ds, mapping, MAIN)
    # Nothing was removed as a bare word, so the operator is told nothing.
    assert ds.private["chat_usernames_scrubbed_bare"] == []
    assert verified(ds, store, policy, tmp_path).leaks == []


def test_a_distinctive_chat_handle_is_still_removed_bare(tmp_path):
    store = product_chat_store(tmp_path, "romashka_support молчит, Romashka_Support тоже")
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), AnonPolicy())
    vid = mapping.chat(MAIN - 2)
    assert text_of(ds, mapping, MAIN) == f"@{vid} молчит, @{vid} тоже"
    assert ds.private["chat_usernames_scrubbed_bare"] == ["romashka_support"]
    assert ds.private["scrub"]["top_surfaces"]["bare_username"] == {"romashka_support": 2}


def test_the_scanner_keeps_the_product_word_and_hunts_the_handle_forms(tmp_path):
    store = product_chat_store(tmp_path, "payments")
    scanner = LeakScanner(known_from_store(store, AnonPolicy()))
    assert scanner.scan("Метод payments/create возвращает 500, sandbox_api недоступен") == []
    assert scanner.scan(PLACEHOLDERS) == []
    assert {"@payments", "romashka_support"} <= {
        l.match for l in scanner.scan("пишите в @payments и romashka_support")}


def test_keep_terms_free_a_handle_of_a_client_chat(tmp_path):
    store = product_chat_store(tmp_path, "romashka_support/create, @romashka_support, t.me/romashka_support")
    mapping = Mapping(tmp_path / "m.json")
    policy = AnonPolicy(keep_terms=("romashka_support",))
    ds = anonymize(store, mapping, Roles.build(ME.id), policy)
    assert text_of(ds, mapping, MAIN) == f"romashka_support/create, @{mapping.chat(MAIN - 2)}, <tg-link>"
    assert ds.private["chat_usernames_scrubbed_bare"] == []


def test_a_persons_handle_is_removed_bare_whatever_it_spells():
    """Only a chat's handle may spell a product word: a person's handle links
    a virtual id straight to t.me/<username>."""
    roster = Roster(by_username={"payments": "U04217"})
    assert Scrubber(AnonPolicy(), roster).scrub("пишите payments") == "пишите @U04217"
    assert [l.kind for l in LeakScanner(Known(usernames=frozenset({"payments"}))).scan("пишите payments")] \
        == ["username"]


def test_the_cli_names_the_handles_it_removed_bare(tmp_path, capsys):
    product_chat_store(tmp_path / "data", "payments и romashka_support")
    settings = Settings(project_dir=tmp_path, data_dir=tmp_path / "data", anon=AnonPolicy())
    assert cli.cmd_anonymize(settings, argparse.Namespace()) == 0
    printed = capsys.readouterr().err
    assert "romashka_support" in printed and "add it to keep_terms" in printed
    assert "payments" not in printed.replace("t.me", "")
    report = json.loads((settings.anon_dir / "anonymize_report.json").read_text(encoding="utf-8"))
    assert report["chat_usernames_scrubbed_bare"] == ["romashka_support"]


# --- marked ids of chats the export never saw ------------------------------------------------

@pytest.mark.parametrize("raw, scrubbed", [
    ("бот не шлёт в чат -1001234567890", "бот не шлёт в чат <id>"),
    ("peer -1001234567890 недоступен", "peer <id> недоступен"),
    ("-1001000000001", "<id>"),                       # the mark goes with the id
    ("баланс -1001234567890.50", "баланс -1001234567890.50"),
    ("остаток -1001234567890,50 руб", "остаток -1001234567890,50 руб"),
    ("заказ 1001234567", "заказ 1001234567"),
    ("заказ 1001234567890", "заказ 1001234567890"),   # no mark, no minus
    ("сумма -1001.50", "сумма -1001.50"),
    ("ошибка -1001", "ошибка -1001"),
])
def test_marked_chat_ids_are_removed_and_amounts_are_not(raw, scrubbed):
    assert Scrubber(AnonPolicy(), Roster()).scrub(raw) == scrubbed
    scanner = LeakScanner(Known())
    assert [l.kind for l in scanner.scan(raw)] == (["chat_id"] if raw != scrubbed else [])
    assert scanner.scan(scrubbed) == []


def test_third_party_ids_of_senders_and_forwards_are_known(tmp_path):
    chat = RawChat(id=MAIN, kind=KIND_SUPERGROUP, title="Ромашка")
    store = make_store(tmp_path, [chat], {MAIN: [
        msg(MAIN, 1, "id канала -1001000000777, он же 1000000777",
            sender=-1001000000777, sender_kind=SENDER_CHANNEL),
        msg(MAIN, 2, "источник пересылки -1001000000888", forward=Forward(kind=FWD_CHANNEL, from_id=-1001000000888)),
        msg(MAIN, 3, "юзер 5555555555", forward=Forward(kind=FWD_USER, from_id=5555555555)),
    ]})
    policy = AnonPolicy()
    vocab = vocabulary(store, policy)
    assert vocab.third_party_ids == frozenset({-1001000000777, -1001000000888, 5555555555})
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    assert [m.text for m in ds.messages] == [
        "id канала <id>, он же <id>", "источник пересылки <id>", "юзер <id>"]
    assert verified(ds, store, policy, tmp_path).leaks == []
    # The same ids are what verify hunts for.
    assert {-1001000000888, 5555555555} <= known_from_store(store, policy).chat_ids


# --- contact names from the dialog catalogue -------------------------------------------------

CATALOGUE = [
    RawChat(id=MAIN, kind=KIND_SUPERGROUP, title="Ромашка"),
    RawChat(id=-1001000000555, kind=KIND_SUPERGROUP, title="ООО Лютик support", is_archived=True),
    RawChat(id=777, kind=KIND_PRIVATE, title="Мария Кузнецова"),
    RawChat(id=778, kind=KIND_PRIVATE, title="Мама"),
    RawChat(id=779, kind=KIND_PRIVATE, title="Отдел продаж"),
    RawChat(id=780, kind=KIND_BOT, title="Northwind Bot"),
    RawChat(id=781, kind=KIND_SUPERGROUP, title="Northwind Android релизы"),
]


def catalogue_store(tmp_path, text):
    return make_store(tmp_path, CATALOGUE, {MAIN: [msg(MAIN, 1, text)]})


def test_a_contact_name_is_removed_as_a_whole_phrase(tmp_path):
    text = "Мария Кузнецова пришлёт акт, Марии Кузнецовой передайте"
    store = catalogue_store(tmp_path, text)
    policy = AnonPolicy()
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    assert ds.messages[0].text == "<name> пришлёт акт, <name> передайте"
    assert "Мария Кузнецова" in known_from_store(store, policy).names
    assert verified(ds, store, policy, tmp_path).leaks == []


@pytest.mark.parametrize("text", [
    "Кузнецова пришлёт акт",            # one word of the phrase is not the person
    "мама звонила, отдел продаж ждёт",  # a nickname and a label are no names
    "Northwind Bot не отвечает, на Android не работает, релиз 2.3",
])
def test_the_catalogue_takes_no_ordinary_word_with_it(tmp_path, text):
    store = catalogue_store(tmp_path, text)
    policy = AnonPolicy(keep_terms=("Northwind",))
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    assert ds.messages[0].text == text
    assert LeakScanner(known_from_store(store, policy)).scan(text) == []


def test_a_client_of_a_chat_that_was_not_exported_needs_custom_terms(tmp_path):
    """Documented residual: only the titles of exported chats become
    organisation terms."""
    text = "Лютик тоже подключается"
    store = catalogue_store(tmp_path, text)
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), AnonPolicy())
    assert ds.messages[0].text == text
    ds = anonymize(store, Mapping(tmp_path / "m2.json"), Roles.build(ME.id),
                   AnonPolicy(custom_terms=("Лютик",)))
    assert ds.messages[0].text == "<org> тоже подключается"


# --- one virtual id per conversation, across incremental runs --------------------------------

LEGACY = RawChat(id=-2000000001, kind=KIND_GROUP, title="Ромашка")
SUPER = RawChat(id=-1001000000001, kind=KIND_SUPERGROUP, title="Ромашка")


def migrated_store(tmp_path):
    store = make_store(tmp_path, [LEGACY], {LEGACY.id: [msg(LEGACY.id, 1, "привет")]})
    return store


def announce_migration(store):
    store.put_chats([RawChat(id=LEGACY.id, kind=KIND_GROUP, title="Ромашка", migrated_to=SUPER.id), SUPER])
    store.append_messages(SUPER.id, [
        msg(SUPER.id, 2, "после миграции"),
        msg(SUPER.id, 3, "fwd", forward=Forward(kind=FWD_CHAT, from_id=LEGACY.id))])


def test_a_migration_seen_later_keeps_the_virtual_id(tmp_path):
    store = migrated_store(tmp_path)
    first = Mapping(tmp_path / "m.json")
    run1 = anonymize(store, first, Roles.build(ME.id), AnonPolicy())
    first.save()
    vid = run1.messages[0].chat

    announce_migration(store)
    second = Mapping.load(tmp_path / "m.json")
    run2 = anonymize(store, second, Roles.build(ME.id), AnonPolicy())
    second.save()
    assert [(m.chat, m.seq, m.text) for m in run2.messages] == [
        (vid, 1, "привет"), (vid, 2, "после миграции"), (vid, 3, "fwd")]
    assert run2.messages[2].forwarded == vid  # a forward from the legacy peer
    assert second.chats() == {LEGACY.id: vid, SUPER.id: vid}


def test_an_export_that_already_knows_the_migration_allocates_one_id(tmp_path):
    store = migrated_store(tmp_path)
    announce_migration(store)
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), AnonPolicy())
    assert len(set(mapping.chats().values())) == 1
    assert {m.chat for m in ds.messages} == set(mapping.chats().values())


def test_the_supergroups_own_id_survives_the_legacy_peer(tmp_path):
    store = make_store(tmp_path, [SUPER], {SUPER.id: [msg(SUPER.id, 2, "после миграции")]})
    mapping = Mapping(tmp_path / "m.json")
    vid = anonymize(store, mapping, Roles.build(ME.id), AnonPolicy()).messages[0].chat

    store.put_chats([RawChat(id=LEGACY.id, kind=KIND_GROUP, title="Ромашка", migrated_to=SUPER.id)])
    store.append_messages(LEGACY.id, [msg(LEGACY.id, 1, "привет")])
    ds = anonymize(store, mapping, Roles.build(ME.id), AnonPolicy())
    assert {m.chat for m in ds.messages} == {vid}


def test_unrelated_chats_keep_distinct_ids(tmp_path):
    other = RawChat(id=-1001000000002, kind=KIND_SUPERGROUP, title="Василёк")
    store = make_store(tmp_path, [LEGACY, other],
                       {LEGACY.id: [msg(LEGACY.id, 1, "привет")], other.id: [msg(other.id, 1, "тоже привет")]})
    mapping = Mapping(tmp_path / "m.json")
    ds = anonymize(store, mapping, Roles.build(ME.id), AnonPolicy())
    assert len({m.chat for m in ds.messages}) == 2
    assert len(set(mapping.chats().values())) == 2
