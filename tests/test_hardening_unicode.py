"""One text normaliser for the scrubber, the scanner and every term:
decomposed letters (macOS file names), soft hyphens, zero-width and bidi
characters, joiners between letters and Russian stress marks hide neither
a name nor an organisation nor a secret. Emoji sequences, keycaps and other
scripts stay intact, and the scanner stays silent on placeholders."""

import unicodedata
from datetime import datetime, timedelta, timezone

import pytest

from tg_collector.anonymize import Mapping, anonymize
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, Entity, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber, fold, plain_text
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
PERSONS = ("Петров", "Семёнов", "Ковальский", "Северов", "Андрей Северов", "Йолкин")
ORGS = ("Ромашка",)
SCRUB = Scrubber(AnonPolicy(), Roster(person_terms=PERSONS, org_terms=ORGS)).scrub
SCANNER = LeakScanner(Known(names=frozenset(PERSONS), titles=frozenset(ORGS)))


def nfd(text):
    return unicodedata.normalize("NFD", text)


@pytest.mark.parametrize("raw,expected,kind", [
    (nfd("Семёнов"), "<name>", "name"),
    (nfd("Семёнову пишет"), "<name> пишет", "name"),
    ("отчёт_" + nfd("Семёнов") + ".xlsx", "отчёт_<name>.xlsx", "name"),
    (nfd("отчёт_Семёнова.pdf"), "отчёт_<name>.pdf", "name"),
    (nfd("Йолкину"), "<name>", "name"),
    (nfd("Ковальский"), "<name>", "name"),
    (nfd("Андрей Северов"), "<name>", "name"),
    (nfd("Северов и Семёнов встретились"), "<name> и <name> встретились", "name"),
    ("СЕМЁНОВ", "<name>", "name"),
    ("Рома\u0301шка", "<org>", "title"),
    ("Ромашка\u0301", "<org>", "title"),
    ("отчёт_Рома\u0301шка.xlsx", "отчёт_<org>.xlsx", "title"),
    ("Пе\u0301тров", "<name>", "name"),
    ("Пе\u0300тров", "<name>", "name"),
    (nfd("Семё") + "\u0301нов", "<name>", "name"),
    ("Се\u00adве\u00adров", "<name>", "name"),
    ("Пет\u00adров", "<name>", "name"),
    ("Пет\u200bров", "<name>", "name"),
    ("Пет\u200cров", "<name>", "name"),
    ("Пет\u200dров", "<name>", "name"),
    ("Пет\u200eров", "<name>", "name"),
    ("Пет\u202eров", "<name>", "name"),
    ("Пет\u2066ров", "<name>", "name"),
    ("Пет\u2060ров", "<name>", "name"),
    ("Пет\ufeffров", "<name>", "name"),
    ("Пет\ufe0fров", "<name>", "name"),
    ("Пет\u034fров", "<name>", "name"),
    ("Ро\u200cмашка просит акт", "<org> просит акт", "title"),
])
def test_hidden_or_decomposed_names_are_scrubbed_and_flagged(raw, expected, kind):
    assert SCRUB(raw) == expected
    assert kind in {l.kind for l in SCANNER.scan(raw)}
    assert SCANNER.scan(expected) == []


@pytest.mark.parametrize("raw,expected", [
    (nfd("Зайцев Андрей Сергеевич"), "<name>"),
    (nfd("ФИО: Соловьёв Сергей"), "ФИО: <cardholder>"),
    ("пароль: Qw\u200derty123", "пароль: <password>"),
    ("пароль:\u200dQwerty123!", "пароль:\u200d<password>!"),  # a joiner stays unless it sits between letters
    ("ИНН 7707\u00ad083893", "ИНН <tax-id>"),
    ("iv\u00adan.example@mail.ru", "<email>"),
    ("ivan.example@mail\u200b.ru", "<email>"),
])
def test_generic_rules_see_the_normalised_text(raw, expected):
    assert SCRUB(raw) == expected
    assert SCANNER.scan(raw) and SCANNER.scan(expected) == []


@pytest.mark.parametrize("text", [
    "\U0001f468\u200d\U0001f469\u200d\U0001f467 семья",
    "\U0001f3f3\ufe0f\u200d\U0001f308 флаг",
    "\U0001f469\u200d\U0001f4bb разработчик, \U0001f937\u200d♂\ufe0f ок",
    "5\ufe0f\u20e3 пунктов",
    "1\ufe0f\u20e3 Оплата 2\ufe0f\u20e3 Возврат",
    "❤\ufe0f спасибо",
    "नमस\u094dत\u0947 द\u0941निया",
    "café résumé Ångström Ω",
    "ERR\u200d_DECLINED",
    "Ivan Petrenko v2.3.1 ERR_DECLINED 1 500 ₽ Northwind Acme Ltd",
    "заказ #4471, ошибка 05, версия 2.3.1, дедлайн 12.03.2026, сумма 10 000 ₸, ёжик",
])
def test_emoji_other_scripts_and_product_knowledge_stay(text):
    assert SCRUB(text) == text
    assert SCANNER.scan(text) == []


def test_composition_only_changes_the_encoding():
    assert SCRUB("cafe\u0301 " + nfd("отчёт, ёжик, йогурт")) == "café отчёт, ёжик, йогурт"
    assert SCRUB("Се\u0301рвер Ю\u0301лия") == "Сервер Юлия"  # stress marks go, the words stay


def test_plain_text_is_idempotent_and_ascii_is_untouched():
    for raw in ("Се\u00adве\u00adров", nfd("Рома\u0301шка Семёнов"), "Пет\u200d\u200dров", "\U0001f468\u200d\U0001f4bb",
                "Пе\u0301\u0301тров", "ERR\u200d_DECLINED", "a" * 50):
        once = plain_text(raw)
        assert plain_text(once) == once
    assert plain_text("ERR_DECLINED v2.3.1 \t x") == "ERR_DECLINED v2.3.1 \t x"


def test_terms_and_keep_terms_match_across_forms():
    assert Scrubber(AnonPolicy(), Roster(person_terms=(nfd("Семёнов"),))).scrub("Семёнов и " + nfd("Семёнов")) == \
        "<name> и <name>"
    assert Scrubber(AnonPolicy(), Roster(person_terms=("Сид\u00adорова",))).scrub("Сидорова в курсе") == "<name> в курсе"
    kept = Scrubber(AnonPolicy(keep_terms=(nfd("Ромашка"),)), Roster(org_terms=ORGS, keep_terms=(nfd("Ромашка"),)))
    assert kept.scrub("Ромашка и " + nfd("Ромашка")) == "Ромашка и Ромашка"
    hyphen = Scrubber(AnonPolicy(), Roster(org_terms=ORGS, keep_terms=("Рома\u00adшка",)))
    assert hyphen.scrub("Ромашка") == "Ромашка"
    assert fold("Ан\u200dна  Ку\u0301зина ") == fold("анна кузина")
    assert LeakScanner(Known(names=frozenset({nfd("Семёнов")}))).scan("Семёнов")


def test_entity_offsets_stay_valid_on_decomposed_text():
    head = nfd("Семёнов пишет ")
    text = head + "@ivan_petrov и https://acme.example.com/x"
    ents = [Entity(type="Mention", offset=len(head), length=12), Entity(type="Url", offset=len(head) + 15, length=26)]
    assert SCRUB(text, ents) == "<name> пишет @user и <url>"


def test_residuals_are_documented():
    # A combining mark with a non-Russian precomposed letter ("ӓ"), and
    # Zalgo-style overlays, are not undone.
    assert SCRUB("Ромӓшка") == "Ромӓшка"
    assert SCRUB("Севе\u0334ров") == "Севе\u0334ров"


def build_store(tmp_path, users, texts):
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка", participant_ids=tuple(u.id for u in users))
    store.put_chats([chat])
    store.put_users(users)
    store.set_me_id(users[0].id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=i, date=T0 + timedelta(minutes=i), sender_id=users[-1].id,
                   sender_kind=SENDER_USER, text=text) for i, text in enumerate(texts, 1)])
    return store


@pytest.mark.parametrize("first,last,kept", [
    ("Ан\u200dна", "Ку\u0301зина", "Анна Кузина"),
    ("Инна", "Сид\u00adорова", "Инна Сидорова"),
    (nfd("Семён"), nfd("Йолкин"), "Семён Йолкин"),
    ("Acme", " Северов ", "Acme Северов"),
])
def test_full_mode_keeps_the_normalised_name_and_verify_agrees(tmp_path, first, last, kept):
    policy = AnonPolicy(name_mode="full")
    surname = kept.split()[1]
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег", username="oleg_support"),
                                   RawUser(id=21, first_name=first, last_name=last),
                                   RawUser(id=200001, first_name="Иван")],
                        [f"{surname} в курсе, {kept} тоже", nfd(f"{surname} в курсе")])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), policy)
    assert [m.text for m in ds.messages] == ["<name> в курсе, <name> тоже", "<name> в курсе"]
    assert kept in {u.name for u in ds.users.values()}
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(timezone="Europe/Berlin"), {})
    assert verify(out, store, policy, tmp_path / "v.json").ok
    assert surname in {n for n in known_from_store(store, AnonPolicy()).names}


def test_first_mode_keeps_the_normalised_given_name(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег"), RawUser(id=21, first_name=nfd("Семён") + " Пет\u00adров"),
                                   RawUser(id=200001, first_name="Иван")], ["Петров на связи"])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), AnonPolicy())
    assert "Семён" in {u.name for u in ds.users.values()}
    assert [m.text for m in ds.messages] == ["<name> на связи"]
