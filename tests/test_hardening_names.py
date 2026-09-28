"""The people vocabulary: every case form of a Russian adjectival surname,
labels in the last-name field that are not surnames, and a longer known
name or organisation that wins over a keep term inside it. Every rule is checked in both directions: the raw form is scrubbed
and flagged by the scanner, ordinary words and product knowledge stay
byte-identical and the scanner stays silent on them and on placeholders."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import assert_fast
from tg_collector.anonymize import Mapping, anonymize, is_label, split_free_text_name, vocabulary
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import (
    FWD_HIDDEN, KIND_SUPERGROUP, SENDER_USER, Forward, RawChat, RawMessage, RawUser, Roles,
)
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber, _term_pattern
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
CLIENT = RawUser(id=200001, first_name="Иван")
PLACEHOLDERS = "<name> <org> <email> <phone> @U0042 @user <redacted> <cardholder> <password> <url>"


def scrub_with(policy=AnonPolicy(), **roster):
    return Scrubber(policy, Roster(**roster)).scrub


def names_scanner(*names, keep=()):
    return LeakScanner(Known(names=frozenset(names), keep_terms=frozenset(keep)), regex_rules=False)


def build_store(tmp_path, users, texts, title="Ромашка"):
    """One supergroup; ``users[0]`` is the support account; ``texts`` are (sender id, text)."""
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title=title, participant_ids=tuple(u.id for u in users))
    store.put_chats([chat])
    store.put_users(users)
    store.set_me_id(users[0].id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=i, date=T0 + timedelta(minutes=i), sender_id=sender, sender_kind=SENDER_USER,
                   text=text) for i, (sender, text) in enumerate(texts, 1)])
    return store


def pipeline(tmp_path, store, policy=AnonPolicy()):
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(store.me_id()), policy)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(timezone="Europe/Berlin"), {})
    return ds, out, verify(out, store, policy, tmp_path / "verify_report.json")


def plant(out, text):
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": text}, ensure_ascii=False) + "\n")


# --- every case form of an adjectival surname ---------------------------------------

DECLENSIONS = {
    "Ковальский": "Ковальский Ковальского Ковальскому Ковальским Ковальском Ковальская Ковальской Ковальскую "
                  "Ковальские Ковальских Ковальскими",
    "Ковальская": "Ковальская Ковальской Ковальскую Ковальский Ковальского",
    "Белый": "Белый Белого Белому Белым Белом Белая Белой Белую Белою Белые Белых Белыми",
    "Белая": "Белая Белой Белую Белою Белый Белого Белому Белым Белом",
    "Горький": "Горький Горького Горькому Горьким Горьком Горькая Горькой Горькую Горькие Горьких",
    "Чайковский": "Чайковский Чайковского Чайковскому Чайковским Чайковском Чайковская Чайковской Чайковскую",
    "Толстой": "Толстой Толстого Толстому Толстым Толстом Толстая Толстую Толстые Толстых",
    "Чёрный": "Чёрный Черный Чёрного Черного Черному Черным Черном Черная Чёрная Черной Черную",
    "Рыжий": "Рыжий Рыжего Рыжему Рыжим Рыжем Рыжая Рыжей Рыжую",
    "Седой": "Седой Седого Седому Седым Седом Седая Седую",
    "Андрей": "Андрей Андрея Андрею Андреем Андрее",
    "Николай": "Николай Николая Николаю Николаем Николае",
}


@pytest.mark.parametrize("surname,forms", DECLENSIONS.items())
def test_every_case_form_of_an_adjectival_surname_is_scrubbed_and_flagged(surname, forms):
    scrub = scrub_with(person_terms=(surname,))
    scanner = names_scanner(surname)
    for form in forms.split():
        text = f"звонил {form} вчера, тикет #4471"
        assert scrub(text) == "звонил <name> вчера, тикет #4471", form
        assert [l.match for l in scanner.scan(text)] == [form], form
        assert scanner.scan(scrub(text)) == []
    assert scrub(forms.upper()) == " ".join(["<name>"] * len(forms.split()))


def test_nominative_adjectival_surnames_in_latin_and_in_full_names():
    scrub = scrub_with(person_terms=("Ковальский", "Андрей Ковальский", "Ковальский Андрей"))
    assert scrub("Kovalskiy, Kovalsky, Андрей Ковальский, Ковальский Андрей, Андрея Ковальского") == \
        "<name>, <name>, <name>, <name>, <name>"
    assert scrub("Договор_Ковальский_Андрей.pdf") == "Договор_<name>_Андрей.pdf"  # a phrase needs whitespace
    assert scrub_with(person_terms=("Высоцкая",))("Высоцкий, Высоцкого, Высоцкая") == "<name>, <name>, <name>"
    assert scrub_with(person_terms=("Толстая",))("толстый файл, Толстой нет") == "толстый файл, <name> нет"


def test_short_adjectival_stems_take_only_adjective_endings():
    # The stem needs an ending ("Бел", "Мал" never match), hard stems take no
    # "-им"/"-ем"/"-ий" (verbs "чистим", "косим", "живем", the noun "серий"),
    # and other surnames built on the same letters stay.
    scrub = scrub_with(person_terms=("Белый", "Малый", "Живой", "Чистый", "Серый", "Косой"))
    text = ("бел и мал, мало места, малыш, белка, белье, белеет, живем, живет, чистим кэш, косим траву, "
            "серий карт, серия, белила, Белов, Белова, Малов, Беляев, Живов, Чистяков, код 05, версия 2.3.1")
    assert scrub(text) == text
    assert names_scanner("Белый", "Малый", "Живой", "Чистый", "Серый", "Косой").scan(text) == []
    # A too-short stem is never declined: "Злой" matches only itself and its old stem.
    assert scrub_with(person_terms=("Злой",))("злой, злая, злого") == "<name>, злая, злого"


def test_three_letter_surnames_are_unchanged_by_the_adjective_rule():
    scrub = scrub_with(person_terms=("Ким", "Цой", "Пак"))
    assert scrub("Ким, Кима, Цой, Цоя, Пак, Паку") == ", ".join(["<name>"] * 6)
    assert scrub("пакет, кимоно, цоколь, ханой") == "пакет, кимоно, цоколь, ханой"


def test_organisation_words_do_not_decline_as_adjectives():
    # A title word "Новая" is scrubbed as itself, never as "новый" / "новое".
    scrub = scrub_with(org_terms=("Новая", "Горный", "Лучший"))
    assert scrub("Новая просит акт, Горный и Лучший тоже") == "<org> просит акт, <org> и <org> тоже"
    text = "новый терминал, новое API, новые ключи, нового клиента, горного, лучшего"
    assert scrub(text) == text
    assert LeakScanner(Known(titles=frozenset({"Новая", "Горный"})), regex_rules=False).scan(text) == []


def test_documented_residual_common_word_surname_removes_the_adjective():
    scrub = scrub_with(person_terms=("Белый",))
    assert scrub("белый фон, на белом фоне") == "<name> фон, на <name> фоне"
    # The operator's keep term protects the common word; the other forms of the name still go.
    assert scrub_with(person_terms=("Белая",), keep_terms=("белый",))("белый фон, Белой нет") == "белый фон, <name> нет"


def test_scanner_never_flags_placeholders_with_adjectival_names():
    assert names_scanner("Белый", "Ковальский", "Андрей", "Толстой").scan(PLACEHOLDERS) == []


def test_adjectival_term_pattern_stays_linear_on_hostile_runs():
    rx = _term_pattern(["Белый", "Ковальский", "Андрей", "Чёрный", "Рыжий"] + [f"Фамилия{i}ский" for i in range(300)])
    for hostile in ("белого" * 700, "Ковальск" * 520, "ый" * 2048, "Бел " * 1024, "й" * 4096):
        assert_fast(lambda hostile=hostile: rx.findall(hostile[:4096]), label=hostile[:40])
    scrub = scrub_with(person_terms=("Белый", "Ковальский"))
    assert_fast(lambda: scrub(("Белого Ковальскому " * 250)[:4096]), label="adjectival scrub")


def test_adjectival_surname_end_to_end(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support"),
                                   RawUser(id=2, first_name="Анна", last_name="Белая"),
                                   RawUser(id=3, first_name="Андрей", last_name="Ковальский"), CLIENT],
                        [(200001, "Ковальский ответил? Белой нет, Анна Белая в отпуске; Андрей Ковальский в курсе"),
                         (1, "Северов на связи, заказ #4471, ошибка 05")])
    ds, out, report = pipeline(tmp_path, store)
    assert [m.text for m in ds.messages] == ["<name> ответил? <name> нет, <name> в отпуске; <name> в курсе",
                                             "<name> на связи, заказ #4471, ошибка 05"]
    assert report.ok
    plant(out, "Ковальский и Белая снова пишут")
    report = verify(out, store, AnonPolicy(), tmp_path / "v2.json")
    assert {(l.kind, l.match) for l in report.leaks} == {("name", "Ковальский"), ("name", "Белая")}


# --- a label in the last-name field is not a surname --------------------------------

ME = RawUser(id=1, first_name="Acme", last_name="Support", username="acme_support")
COLLEAGUE = RawUser(id=2, first_name="Anna", last_name="Staff")
CLIENT_LABEL = RawUser(id=11, first_name="Иван", last_name="Client")
CLIENT_REAL = RawUser(id=12, first_name="Олег", last_name="Северов")
FULL_IN_FIRST = RawUser(id=14, first_name="Иван Петров", last_name="Support")
KEEP = AnonPolicy(keep_terms=("Northwind",))


def test_label_words_in_the_last_name_field_are_not_surnames(tmp_path):
    store = build_store(tmp_path, [ME, COLLEAGUE, CLIENT_LABEL, CLIENT_REAL, FULL_IN_FIRST], [
        (11, "не проходит оплата, напишите в support или staff"),
        (1, "смотрим, Северов пришлите лог; Иван Client на связи"),
        (14, "это Петров, Иван Петров"),
    ], title="Ромашка / Northwind")
    known = known_from_store(store, KEEP)
    assert not {"Support", "Staff", "Client"} & set(known.names)
    assert {"Северов", "Петров"} <= set(known.names)
    assert vocabulary(store, KEEP).kept_names == {1: "Acme", 2: "Anna", 11: "Иван", 12: "Олег", 14: "Иван"}
    ds, out, report = pipeline(tmp_path, store, KEEP)
    assert [m.text for m in ds.messages] == [
        "не проходит оплата, напишите в support или staff",   # product vocabulary, not names
        "смотрим, <name> пришлите лог; Иван Client на связи",  # a real surname still goes
        "это <name>, <name>",                                   # the surname sits in the first-name field
    ]
    assert report.ok, report.leaks   # "(support)", "STAFF", "client" labels are not leaks
    plant(out, "planted: Северов, Петрову")
    report = verify(out, store, KEEP, tmp_path / "v2.json")
    assert report.by_kind() == {"name": 2} and {l.match for l in report.leaks} == {"Северов", "Петрову"}


@pytest.mark.parametrize("first,last,text", [
    ("Northwind", "Поддержка", "обратитесь в поддержку, поддержка отвечает 24/7, Поддержка Northwind"),
    ("Анна", "Тест", "в тесте всё работает, переключите на тест, после теста напишите"),
    ("Northwind", "Продажи", "вопрос в отдел продаж, продажи ответят"),
    ("Служба", "поддержки", "служба поддержки не отвечает, напишите в поддержку"),
    ("Анна", " Поддержка ", "поддержка на связи, заказ #4471"),
    ("Анна", "Саппорт", "саппорта нет, саппорт молчит"),
    ("Acme", "Support", "support не отвечает, пишу в Support"),
    ("Acme", "SUPPORT", "support не отвечает"),
    ("Anna", "(Support)", "Anna (support) на связи"),
    ("Anna", "Support Team", "support team ответит"),
])
def test_russian_and_english_support_account_labels_keep_the_words(tmp_path, first, last, text):
    store = build_store(tmp_path, [RawUser(id=1, first_name=first, last_name=last), CLIENT, CLIENT_REAL],
                        [(200001, text), (200001, "Северов, пришлите лог")])
    ds, _, report = pipeline(tmp_path, store, KEEP)
    assert [m.text for m in ds.messages] == [text, "<name>, пришлите лог"]
    assert report.ok, report.leaks
    assert last.strip() not in known_from_store(store, KEEP).names


def test_product_and_label_signature_stays_with_the_product_kept(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Northwind", last_name="Support"), CLIENT],
                        [(200001, "напишите в Northwind Support или support"), (1, "С уважением, Northwind Support")],
                        title="Ромашка / Northwind")
    ds, _, report = pipeline(tmp_path, store, KEEP)
    assert [m.text for m in ds.messages] == ["напишите в Northwind Support или support", "С уважением, Northwind Support"]
    assert report.ok


@pytest.mark.parametrize("users", [
    [RawUser(id=1, first_name="Anna", last_name="(Support)")],
    [RawUser(id=1, first_name="Олег"), RawUser(id=2, first_name="Anna", last_name="Staff")],
    [RawUser(id=1, first_name="Олег"), RawUser(id=2, first_name="Иван", last_name="Client")],
    [RawUser(id=1, first_name="Acme", last_name=" Support ")],
])
@pytest.mark.parametrize("mode", ["first", "full", "none"])
def test_verify_does_not_report_the_renderers_own_labels(tmp_path, users, mode):
    store = build_store(tmp_path, [*users, CLIENT], [(200001, "не проходит оплата"), (users[0].id, "смотрим")])
    assert pipeline(tmp_path, store, AnonPolicy(name_mode=mode))[2].ok


def test_label_first_name_under_none_mode_is_not_a_name(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Support"), CLIENT], [(200001, "support тут, Иван тоже")])
    ds, _, report = pipeline(tmp_path, store, AnonPolicy(name_mode="none"))
    assert [m.text for m in ds.messages] == ["support тут, <name> тоже"] and report.ok


def test_whole_name_in_the_first_name_field_next_to_a_label(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег"),
                                   RawUser(id=2, first_name="Семён Сидоров", last_name="Client"),
                                   RawUser(id=3, first_name="Петров Иван", last_name="Support"),
                                   RawUser(id=4, first_name="Ivan Petrov (Northwind)", last_name="Support"), CLIENT],
                        [(200001, "держатель карты Иван Сидоров; Сидоров в курсе"),
                         (3, "Петров Иван и Петров, Петрова нет"),
                         (4, "Ivan Petrov (Northwind) Support на связи, support")])
    ds, _, report = pipeline(tmp_path, store)
    # The name after "держатель карты" is a cardholder; the bare surname
    # later in the message comes from the first-name field.
    assert [m.text for m in ds.messages] == ["держатель карты <cardholder>; <name> в курсе",
                                             "<name> и <name>, <name> нет",
                                             "<name> на связи, support"]
    assert {u.name for u in ds.users.values()} >= {"Семён", "Иван", "Ivan"}  # "Петров Иван" keeps the given name
    assert report.ok


def test_real_surnames_and_common_word_surnames_are_still_scrubbed(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег", last_name="Северов"),
                                   RawUser(id=2, first_name="Anna", last_name="Мороз"),
                                   RawUser(id=3, first_name="Иван", last_name="Тестов"), CLIENT],
                        [(200001, "Северов на связи, Олег Северов, Северова нет"),
                         (200001, "мороз на улице, Мороз ответьте; support не отвечает"),
                         (200001, "Иван Тестов звонил, в тесте ок")])
    ds, _, report = pipeline(tmp_path, store)
    assert [m.text for m in ds.messages] == ["<name> на связи, <name>, <name> нет",
                                             "<name> на улице, <name> ответьте; support не отвечает",
                                             "<name> звонил, в тесте ок"]
    known = known_from_store(store, AnonPolicy())
    assert {"Мороз", "Тестов"} <= known.names and "Support" not in known.names
    assert report.ok


def test_documented_residual_real_surname_that_is_a_label_word(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Olga"), RawUser(id=2, first_name="Ravi", last_name="Dev"),
                                   CLIENT], [(200001, "спасибо, Ravi Dev")])
    ds, _, report = pipeline(tmp_path, store)
    assert [m.text for m in ds.messages] == ["спасибо, Ravi Dev"] and report.ok


def test_free_text_names_and_label_helper():
    assert split_free_text_name(RawUser(id=1, first_name="Acme Support")) == ("Acme", ())
    assert split_free_text_name(RawUser(id=1, first_name="Northwind Support Team")) == ("Northwind", ())
    assert split_free_text_name(RawUser(id=1, first_name="Anna Staff")) == ("Anna", ())
    assert split_free_text_name(FULL_IN_FIRST) == ("Иван", ("Петров",))
    assert split_free_text_name(RawUser(id=1, first_name="Olga Merchant")) == ("Olga", ("Merchant",))
    assert split_free_text_name(RawUser(id=1, first_name="Anna Card")) == ("Anna", ("Card",))
    assert split_free_text_name(RawUser(id=1, first_name="Иван Банков")) == ("Иван", ("Банков",))
    assert is_label("Support") and is_label("(Support)") and is_label("STAFF") and is_label("Служба поддержки")
    assert is_label("Northwind Support", ("Northwind",)) and not is_label("Northwind Support")
    assert not is_label("Северов") and not is_label("") and not is_label("Анна Мороз", ("мороз",))


def test_forward_name_made_of_labels_and_keep_words_is_not_a_name(tmp_path):
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег"), CLIENT], [])
    fwd = [RawMessage(chat_id=-1001, id=i, date=T0 + timedelta(minutes=i), sender_id=200001, sender_kind=SENDER_USER,
                      text=text, forward=Forward(kind=FWD_HIDDEN, from_name=name))
           for i, (name, text) in enumerate([("Support Team", "support team ответит"),
                                              ("Northwind Support", "С уважением, Northwind Support"),
                                              ("Анна Смирнова", "Анна Смирнова на связи")], 1)]
    store.append_messages(-1001, fwd)
    known = known_from_store(store, KEEP)
    assert not {"Support Team", "Northwind Support"} & known.names and "Анна Смирнова" in known.names
    ds, _, report = pipeline(tmp_path, store, KEEP)
    assert [m.text for m in ds.messages] == ["support team ответит", "С уважением, Northwind Support", "<name> на связи"]
    assert report.ok


# --- a longer known term wins over a keep term inside it -----------------------------

def keep_scrub(keep, org=(), person=(), **policy):
    return Scrubber(AnonPolicy(keep_terms=keep, **policy), Roster(org_terms=org, person_terms=person, keep_terms=keep)).scrub


def keep_scanner(keep, org=(), person=()):
    return LeakScanner(Known(titles=frozenset(org), names=frozenset(person), keep_terms=frozenset(keep)))


@pytest.mark.parametrize("keep,org,person,text,expected", [
    (("Acme",), ("Acme Corp",), (), "у Acme Corp проблема", "у <org> проблема"),
    (("Acme",), ("Acme Corp",), (), "в Acme Corpе не отвечают", "в <org> не отвечают"),
    (("Northwind",), ("Northwind Kazakhstan",), (), "филиал Northwind Kazakhstan не отвечает, а Northwind работает",
     "филиал <org> не отвечает, а Northwind работает"),
    (("Northwind",), ("Northwind Казахстан",), (),
     "филиал Northwind Казахстан не отвечает, в Northwind Казахстане тишина, а Northwind работает",
     "филиал <org> не отвечает, в <org> тишина, а Northwind работает"),
    (("Northwind",), ("Northwind Казахстан",), (), "у NORTHWIND КАЗАХСТАНА\nпроблема; Northwind-Казахстан тоже",
     "у <org>\nпроблема; Northwind-Казахстан тоже"),
    (("Northwind",), ("Ёлка Northwind",), (), "Ёлка Northwind и Елка Northwind", "<org> и <org>"),
    (("Ромашки",), ("Ромашка Групп",), (), "у Ромашки Групп проблема, у Ромашки тоже", "у <org> проблема, у Ромашки тоже"),
    (("Acme", "Corp"), ("Acme Corp",), (), "у Acme Corp проблема, Corp отдельно", "у <org> проблема, Corp отдельно"),
    (("Acme", "Pay"), ("Acme Pay Corp",), (), "Acme Pay Corp и Acme Pay", "<org> и Acme Pay"),
    (("Northwind",), ("Northwind Kazakhstan",), (), "Northwind Kazakhstan, код ошибки NW_500", "<org>, код ошибки NW_500"),
    (("Acme",), ("Acme-Corp",), (), "у Acme-Corp проблема", "у <org> проблема"),
    (("Олег",), (), ("Олег Северов",), "звонил Олег Северов", "звонил <name>"),
    (("Олег",), (), ("Олег Северов",), "звонил Oleg Severov", "звонил <name>"),
    (("мороз",), (), ("Мороз", "Анна Мороз", "Мороз Анна"),
     "мороз на улице, Анна Мороз не отвечает, передайте Анне Мороз", "мороз на улице, <name> не отвечает, передайте <name>"),
    (("мороз",), (), ("Мороз", "Анна Мороз", "Мороз Анна"), "мороз на улице, Мороз Анна не отвечает",
     "мороз на улице, <name> не отвечает"),
    (("лист",), (), ("Роман Лист", "Лист", "Лист Роман"), "Роман Лист прислал лист", "<name> прислал лист"),
    (("лист",), (), ("Роман Лист", "Лист", "Лист Роман"), "Роман\nЛист", "<name>"),
    (("лист",), (), ("Роман Лист", "Лист", "Лист Роман"), "Лист Роману отправил", "<name> отправил"),
])
def test_longer_term_beats_a_keep_term_inside_it(keep, org, person, text, expected):
    assert keep_scrub(keep, org, person)(text) == expected
    scanner = keep_scanner(keep, org, person)
    assert scanner.scan(text) and scanner.scan(expected) == []


@pytest.mark.parametrize("keep,org,person,text", [
    (("Acme",), ("Acme Corp",), (), "у Acme проблема"),
    (("Acme",), ("Acme Corp",), (), "Acme и Corp разные"),
    (("Acme",), ("Acme Corp",), (), "ACME_CORP_TIMEOUT в логах, ACME_CORP_TIMEOUT и Acme"),
    (("Acme",), ("Acme Corp",), (), "Acme_Corp и Corp Acme"),
    (("Acme",), ("Acme Corp",), (), "у Acme-Corp проблема"),
    (("Acme Corp", "Acme"), ("Acme Corp", "Acme"), (), "у Acme Corp и Acme проблема"),
    (("Acme", "Northwind"), ("Acme Corp",), (), "Northwind работает. Acme SDK 2.1, заказ #4471"),
    (("Ромашка",), ("ООО Ромашка",), (), "ООО «Ромашка» и Ромашка"),
    (("Northwind",), ("Northwind Kazakhstan",), (), "NORTHWIND_KAZAKHSTAN"),
    (("мороз",), (), ("Мороз", "Анна Мороз"), "Мороз ответьте, сегодня мороз"),
    (("лист",), (), ("Роман Лист", "Лист", "Лист Роман"), "звонил Роман, лист готов"),
    (("Олег",), (), ("Олег Северов",), "звонил Олег"),
])
def test_keep_terms_on_their_own_stay(keep, org, person, text):
    assert keep_scrub(keep, org, person)(text) == text
    assert keep_scanner(keep, org, person).scan(text) == []


def test_keep_term_rules_that_did_not_change():
    # The keyword person rule still treats a keep term as a non-person.
    assert keep_scrub(("Northwind",))("С уважением, Northwind Support") == "С уважением, Northwind Support"
    # A keep term that contains the org term is a separate residual: the text stays.
    assert keep_scrub(("Acme Corp Pay",), ("Acme Corp",))("Acme Corp Pay подключен") == "Acme Corp Pay подключен"
    # A contradictory config (the kept word is also a custom pattern) is still less revealing.
    policy = dict(custom_patterns=(r"Northwind",))
    assert keep_scrub(("Northwind",), ("Northwind Kazakhstan",), **policy)("Northwind Kazakhstan") == "<redacted> Kazakhstan"
    assert keep_scanner(("Acme",), ("Acme Corp",)).scan(PLACEHOLDERS) == []


def test_keep_term_inside_a_custom_term_end_to_end(tmp_path):
    policy = AnonPolicy(keep_terms=("Northwind",), custom_terms=("Northwind Kazakhstan",))
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег"), CLIENT],
                        [(200001, "филиал Northwind Kazakhstan не отвечает, а Northwind работает"),
                         (200001, "в Northwind Kazakhstanе тоже тихо")])
    ds, _, report = pipeline(tmp_path, store, policy)
    assert [m.text for m in ds.messages] == ["филиал <org> не отвечает, а Northwind работает", "в <org> тоже тихо"]
    assert report.ok


def test_full_name_with_a_kept_common_word_surname_end_to_end(tmp_path):
    policy = AnonPolicy(keep_terms=("мороз",))
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег"), RawUser(id=21, first_name="Анна", last_name="Мороз"),
                                   CLIENT], [(200001, "мороз на улице, Анна Мороз на связи")])
    ds, out, report = pipeline(tmp_path, store, policy)
    assert [m.text for m in ds.messages] == ["мороз на улице, <name> на связи"]
    assert report.ok
    plant(out, "Анна Мороз снова пишет")
    assert {l.match for l in verify(out, store, policy, tmp_path / "v2.json").leaks} == {"Анна Мороз"}


# --- a multi-word keep term is a phrase, not a licence for its words ----------------------

def test_is_label_counts_a_keep_term_only_as_a_whole_phrase():
    assert not is_label("Кузнецов", ("Кузнецов Pay",)) and not is_label("Белый", ("Белый список",))
    assert not is_label("Anna Smith", ("Smith Anna Foundation",))
    assert is_label("Кузнецов", ("Кузнецов",)) and is_label("Northwind Support", ("Northwind",))
    assert is_label("Northwind Pay Support", ("Northwind Pay",))
    assert is_label("Служба поддержки Northwind Pay", ("Northwind Pay",))
    assert not is_label("", ("Northwind",)) and not is_label("Анна Мороз", ("мороз",))


@pytest.mark.parametrize("keep,surname,text,expected", [
    (("Кузнецов Pay",), "Кузнецов", "Кузнецов, проверьте настройки Кузнецов Pay, Кузнецову отправили",
     "<name>, проверьте настройки Кузнецов Pay, <name> отправили"),
    (("Белый список",), "Белый", "Белый, проверьте белый список. Белому отправили счёт",
     "<name>, проверьте белый список. <name> отправили счёт"),
    (("Система быстрых платежей",), "Быстрых", "Быстрых подключила? Система быстрых платежей работает",
     "<name> подключила? Система быстрых платежей работает"),
])
def test_a_surname_inside_a_kept_phrase_is_still_scrubbed(tmp_path, keep, surname, text, expected):
    policy = AnonPolicy(keep_terms=keep)
    store = build_store(tmp_path, [RawUser(id=1, first_name="Олег", last_name="Северов"),
                                   RawUser(id=21, first_name="Андрей", last_name=surname), CLIENT],
                        [(200001, text)])
    assert surname in known_from_store(store, policy).names
    ds, out, report = pipeline(tmp_path, store, policy)
    assert [m.text for m in ds.messages] == [expected]
    assert report.ok, report.leaks   # the kept phrase is no leak, the surname in it is not hunted
    plant(out, f"{surname} снова пишет")
    assert {l.match for l in verify(out, store, policy, tmp_path / "v2.json").leaks} == {surname}


def test_a_kept_phrase_made_only_of_labels_is_still_a_label(tmp_path):
    policy = AnonPolicy(keep_terms=("Northwind Pay",))
    store = build_store(tmp_path, [RawUser(id=1, first_name="Иван", last_name="Northwind Pay Support"), CLIENT],
                        [(200001, "Northwind Pay не отвечает, Иван на связи")])
    assert not known_from_store(store, policy).names & {"Northwind Pay Support"}
    ds, _, report = pipeline(tmp_path, store, policy)
    assert [m.text for m in ds.messages] == ["Northwind Pay не отвечает, Иван на связи"]
    assert report.ok, report.leaks
