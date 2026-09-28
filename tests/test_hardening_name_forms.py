"""The harder name shapes the vocabulary and the patronymic rules read.

* The nominative of a surname that ends in a soft sign or in a Latin "-o"
  ("Коваль", "Бондарь", "Гоголь", "Shevchenko"), next to its case forms.
* Both halves of a hyphenated surname decline ("Смирновой-Кузнецовой").
* A term may run into a number ("petrov1990", "romashka2024"), while a term
  that ends in a digit may not ("S3" is not inside "S30").
* Identifiers: an ALL_CAPS product constant keeps an organisation term,
  while a file name and every person's name in one are scrubbed.
* A known username that contains a keep term ("northwind_ivan") is still a
  username.
* A name with a patronymic typed in capitals ("ПЕТРОВ ИВАН СЕРГЕЕВИЧ", as
  payment details print it) or, after a person keyword, in lower case
  ("фио: смирнов алексей викторович").

Every rule is checked in both directions: the raw form is scrubbed and
flagged by the scanner, product knowledge stays byte-identical and the
scanner stays silent on it and on placeholders.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest

from conftest import assert_fast
from tg_collector.anonymize import Mapping, anonymize, vocabulary
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber
from tg_collector.verify import verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
PLACEHOLDERS = ("<name> <org> <email> <phone> <url> <domain> <id> <token> <cardholder> <passport> @user @U0042 "
                "<redacted> ERR_ROMASHKA_TIMEOUT")


def scrub_with(policy=AnonPolicy(), **roster):
    return Scrubber(policy, Roster(**roster)).scrub


def scanner(names=(), titles=(), keep=(), usernames=(), regex_rules=False):
    return LeakScanner(Known(names=frozenset(names), titles=frozenset(titles), keep_terms=frozenset(keep),
                             usernames=frozenset(usernames)), regex_rules=regex_rules)


def both_ways(scrub, scan, raw, expected):
    """The raw text is scrubbed as expected and flagged; the output is clean."""
    assert scrub(raw) == expected
    assert scan.scan(raw), raw
    assert scan.scan(scrub(raw)) == []


# --- surnames whose nominative ends in "ь" or a Latin "o" ---------------------------------

DECLENSIONS = {
    "Коваль": "Коваль Коваля Ковалю Ковалем Ковалём Ковале",
    "Бондарь": "Бондарь Бондаря Бондарю Бондарем Бондаре",
    "Гоголь": "Гоголь Гоголя Гоголю Гоголем Гоголе",
    "Лось": "Лось Лося Лосю Лосем Лосе",
    "Кравець": "Кравець Кравця Кравцю Кравцем",
    "Shevchenko": "Shevchenko Shevchenka",
    "Petrenko": "Petrenko Petrenku",
    "Шевченко": "Шевченко Шевченку Shevchenko",
}


@pytest.mark.parametrize("surname,forms", DECLENSIONS.items())
def test_nominative_and_case_forms_of_soft_sign_and_o_surnames(surname, forms):
    scrub = scrub_with(person_terms=(surname,))
    scan = scanner(names=(surname,))
    for form in forms.split():
        both_ways(scrub, scan, f"звонил {form} вчера, заказ #4471", "звонил <name> вчера, заказ #4471")
    assert scrub(f"{surname.upper()}_ПАСПОРТ.pdf") == "<name>_ПАСПОРТ.pdf"


def test_full_name_with_a_soft_sign_surname():
    scrub = scrub_with(person_terms=("Мария Коваль", "Коваль"))
    both_ways(scrub, scanner(names=("Мария Коваль", "Коваль")),
              "Мария Коваль просит вернуть деньги, звоните Ковалю", "<name> просит вернуть деньги, звоните <name>")


def test_organisation_terms_ending_in_a_soft_sign_or_latin_o():
    scrub = scrub_with(org_terms=("Хрусталь", "Lutiko"))
    both_ways(scrub, scanner(titles=("Хрусталь", "Lutiko")),
              "Хрусталь не платит, Lutiko ok, Хрустали писали", "<org> не платит, <org> ok, <org> писали")


def test_soft_sign_surnames_do_not_reach_into_longer_words():
    terms = ("Коваль", "Король", "Лось", "Соболь", "Shevchenko", "Petrenko")
    scrub = scrub_with(person_terms=terms)
    text = ("Ковальчук пишет, Ковалевский тоже, ковальский завод, кроль не подошёл, лосьон, Shevchenkovsky, "
            "заказ #4471, ошибка 05")
    assert scrub(text) == text
    assert scanner(names=terms).scan(text) == []
    assert scanner(names=terms).scan(PLACEHOLDERS) == []


def test_documented_residual_a_surname_that_is_a_common_word():
    # "Лось" removes the animal too; a keep term is the operator's way out.
    assert scrub_with(person_terms=("Лось",))("лось в лесу") == "<name> в лесу"
    keep = AnonPolicy(keep_terms=("лось",))
    assert scrub_with(keep, person_terms=("Лось", "Анна Лось"), keep_terms=("лось",))(
        "лось в лесу, Анна Лось пишет") == "лось в лесу, <name> пишет"


# --- hyphenated surnames and terms that run into a number --------------------------------

def test_both_halves_of_a_hyphenated_surname_decline():
    scrub = scrub_with(person_terms=("Смирнова-Кузнецова",))
    scan = scanner(names=("Смирнова-Кузнецова",))
    both_ways(scrub, scan, "Смирновой-Кузнецовой Наталье передали", "<name> Наталье передали")
    both_ways(scrub, scan, "Смирнова-Кузнецова ответила", "<name> ответила")
    text = "Смирнова ответила, Кузнецова тоже"  # one half alone is not the term
    assert scrub(text) == text and scan.scan(text) == []


@pytest.mark.parametrize("raw,expected", [
    ("petrov1990 не заходит", "<name>1990 не заходит"),
    ("IMG_Petrov2.jpg приложил", "IMG_<name>2.jpg приложил"),
    ("экспорт petrov2026 готов", "экспорт <name>2026 готов"),
    ("romashka2024 в списке", "<org>2024 в списке"),
    ("Ромашка24 открылась", "<org>24 открылась"),
])
def test_a_term_may_run_into_a_number(raw, expected):
    scrub = scrub_with(person_terms=("Петров",), org_terms=("Ромашка",))
    both_ways(scrub, scanner(names=("Петров",), titles=("Ромашка",)), raw, expected)


def test_a_term_that_ends_in_a_digit_stays_a_whole_token():
    scrub = scrub_with(org_terms=("S3", "Z9"), person_terms=("Петров",))
    text = "S30 bucket, Z90 полок, Петрович, petrovich1990, версия 2.15.3, заказ 12345"
    assert scrub(text) == text
    assert scanner(names=("Петров",), titles=("S3", "Z9")).scan(text) == []
    assert scrub("S3 bucket и Z9 рядом") == "<org> bucket и <org> рядом"


# --- identifiers, constants and file names ------------------------------------------------

CONSTANTS = "ERR_BANK_TIMEOUT ROMASHKA_API_KEY ERR_ROMASHKA_TIMEOUT PAYMENT_STATUS.DECLINED PAY_DECLINED_05 3DS_TIMEOUT"


def test_all_caps_constants_keep_organisation_terms():
    scrub = scrub_with(org_terms=("Ромашка", "Bank", "Pay"))
    assert scrub(CONSTANTS) == CONSTANTS
    assert scanner(titles=("Ромашка", "Bank", "Pay")).scan(CONSTANTS) == []


@pytest.mark.parametrize("raw,expected", [
    ("прикрепляю PETROV_PASSPORT.pdf", "прикрепляю <name>_PASSPORT.pdf"),
    ("IMG_PETROV.JPG в чате", "IMG_<name>.JPG в чате"),
    ("WALKER_ПАСПОРТ.pdf пришёл", "<name>_ПАСПОРТ.pdf пришёл"),
    ("отчёт_ROMASHKA_март.xlsx", "отчёт_<org>_март.xlsx"),
    ("SEVEROV_PASSPORT_SCAN_FRONT_SIDE_2026_03_12_FINAL", "<name>_PASSPORT_SCAN_FRONT_SIDE_2026_03_12_FINAL"),
    ("WALKER_TIMEOUT в логе", "<name>_TIMEOUT в логе"),
])
def test_a_file_name_or_a_persons_name_in_an_identifier_is_scrubbed(raw, expected):
    scrub = scrub_with(person_terms=("Петров", "Walker", "Северов"), org_terms=("Ромашка",))
    both_ways(scrub, scanner(names=("Петров", "Walker", "Северов"), titles=("Ромашка",)), raw, expected)


def test_a_name_in_a_file_name_inside_a_kept_link_is_scrubbed():
    policy = AnonPolicy(url_mode="keep", allow_domains=("example.com",))
    scrub = scrub_with(policy, person_terms=("Петров",))
    assert scrub("https://example.com/files/PETROV_PASSPORT.pdf") == "https://example.com/files/<name>_PASSPORT.pdf"
    scan = LeakScanner(Known(names=frozenset({"Петров"})), url_allowed=lambda u: "example.com" in u)
    assert [l.kind for l in scan.scan("https://example.com/files/PETROV_PASSPORT.pdf")] == ["name"]
    assert scan.scan("https://example.com/files/<name>_PASSPORT.pdf") == []


# --- a known username that contains a keep term -------------------------------------------

def username_scrub(keep=("Northwind",)):
    roster = Roster(by_username={"northwind_ivan": "U00011", "northwind": "U00012"}, keep_terms=keep)
    return Scrubber(AnonPolicy(keep_terms=keep), roster).scrub


@pytest.mark.parametrize("raw,expected", [
    ("пишите northwind_ivan", "пишите @U00011"),
    ("tg@northwind_ivan", "tg@U00011"),
    ("scan_northwind_ivan.pdf", "scan_@U00011.pdf"),
    ("пишите northwind_ivanу", "пишите @U00011"),
    ("ник в тг northwind_ivan", "ник в тг @U00011"),
    ("@northwind ответил", "@U00012 ответил"),
])
def test_a_username_that_contains_a_keep_term_is_still_a_username(raw, expected):
    scan = scanner(usernames=("northwind_ivan", "northwind"), keep=("Northwind",))
    both_ways(username_scrub(), scan, raw, expected)


def test_the_keep_term_itself_stays_while_its_username_goes():
    scrub = username_scrub()
    text = "Northwind работает, northwind.ru открыт, northwind ivan рядом"
    assert scrub(text) == text
    assert scanner(usernames=("northwind_ivan", "northwind"), keep=("Northwind",)).scan(text) == []


# --- a name with a patronymic in capitals or in lower case --------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("СМИРНОВ АЛЕКСЕЙ ВИКТОРОВИЧ", "<name>"),
    ("ПЕТРОВ ИВАН СЕРГЕЕВИЧ, перевод 1500", "<name>, перевод 1500"),
    ("получатель: ИВАНОВА АННА ПЕТРОВНА", "получатель: <name>"),
    ("КОВАЛЬ ОЛЕГ ИЛЬИЧ", "<name>"),
    ("плательщик АННА СЕРГЕЕВНА КУЗНЕЦОВА", "плательщик <name>"),
])
def test_name_and_patronymic_in_capitals(raw, expected):
    both_ways(scrub_with(), LeakScanner(Known()), raw, expected)


CAPS_PRODUCT_TEXT = [
    "ОТДЕЛ ПРОДАЖ МОСКВИЧ",
    "ОШИБКА ПЛАТЕЖА ОТКЛОНЕНА",
    "ЭТИ ДАННЫЕ ЛОГИЧНЫ",
    "ВНИМАНИЕ: СРОЧНО ОПЛАТИТЕ",
    "СТАТУС ТРАНЗАКЦИИ DECLINED",
    "ООО ЛИЧНЫЙ КАБИНЕТ",
    "НЕ НАЙДЕН ОСНОВНОЙ СЧЁТ",
    "ОШИБКА НА УРОВНЕ БАНКА",
    "ПЛАТЕЖИ РАЗДЕЛЕНЫ ПОРОВНУ",
    "ВЫ НЕ ВИНОВНЫ",
    "ERR_BANK_TIMEOUT PAYMENT DECLINED 05",
]


@pytest.mark.parametrize("text", CAPS_PRODUCT_TEXT)
def test_shouted_product_text_is_no_patronymic(text):
    assert scrub_with()(text) == text
    assert LeakScanner(Known(), regex_rules=True).scan(text) == []


@pytest.mark.parametrize("raw,expected", [
    ("фио: смирнов алексей викторович", "фио: <name>"),
    ("меня зовут иван смирнов", "меня зовут <name>"),
    ("его зовут пётр ильич", "его зовут <name>"),
    ("контактное лицо: сидоров пётр ильич", "контактное лицо: <name>"),
    ("получатель: иванова анна петровна", "получатель: <name>"),
    ("меня зовут анна петрова, заказ #4471", "меня зовут <name>, заказ #4471"),
])
def test_a_lower_case_name_after_a_person_keyword(raw, expected):
    both_ways(scrub_with(), LeakScanner(Known()), raw, expected)


LOWER_CASE_PROSE = [
    "меня зовут иван, я из поддержки",
    "фио клиентов не отображается",
    "в поле фио пробелов нет",
    "фио: не заполнено",
    "получатель платежа не найден",
    "плательщик оплатил заказ #4471",
    "контактное лицо уточните завтра",
    "меня зовут для рассылки заказов",
    "получатель Тинькофф Банк",
]


@pytest.mark.parametrize("text", LOWER_CASE_PROSE)
def test_lower_case_prose_after_a_person_keyword_stays(text):
    assert scrub_with()(text) == text
    assert LeakScanner(Known(), regex_rules=True).scan(text) == []


def test_patronymic_rules_stay_fast_on_hostile_runs():
    scrub = scrub_with(person_terms=("Коваль", "Смирнова-Кузнецова"), org_terms=("Ромашка",))
    hostile = [("ПЕТРОВ ИВАН СЕРГЕЕВИЧ " * 200)[:4096], ("ЦЕНА УСЛОВНА НЕТ " * 250)[:4096], "А" * 4096,
               ("меня зовут иван смирнов, " * 170)[:4096], ("Коваль ковалю KOVAL_PASSPORT.pdf " * 130)[:4096],
               ("Смирновой-Кузнецовой " * 200)[:4096], "_" * 4096, ("ERR_ROMASHKA_TIMEOUT_" * 200)[:4096]]
    for text in hostile:
        assert_fast(lambda text=text: scrub(text), label=text[:40])


# --- end to end ---------------------------------------------------------------------------

def store_with(tmp_path, users, titles, texts):
    """One supergroup per title; ``users[0]`` is the support account and the
    client of each chat writes the matching text."""
    store = RawStore(tmp_path / "raw")
    store.set_me_id(users[0].id)
    clients = [RawUser(id=200000 + i, first_name="Ivan") for i in range(len(titles))]
    store.put_users([*users, *clients])
    member_ids = tuple(u.id for u in users)
    store.put_chats([RawChat(id=-1001000000100 - i, kind=KIND_SUPERGROUP, title=t,
                             participant_ids=(*member_ids, clients[i].id)) for i, t in enumerate(titles)])
    for i, text in enumerate(texts):
        store.append_messages(-1001000000100 - i, [RawMessage(
            chat_id=-1001000000100 - i, id=1, date=T0 + timedelta(minutes=i), sender_id=clients[i].id,
            sender_kind=SENDER_USER, text=text)])
    return store


def run(tmp_path, store, policy=AnonPolicy()):
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(store.me_id()), policy)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(timezone="Europe/Berlin"), {})
    return ds, out, verify(out, store, policy, tmp_path / "verify_report.json")


def test_usernames_around_a_keep_term_end_to_end(tmp_path):
    """A keep term inside a username shields neither the username nor, after
    a glued '@', the rest of the run."""
    policy = AnonPolicy(keep_terms=("Northwind",))
    staff = RawUser(id=1001, first_name="Олег", last_name="Северов", username="northwind_support")
    bot = RawUser(id=1003, first_name="NW", username="Northwind_Bot", is_bot=True)
    store = RawStore(tmp_path / "raw")
    store.set_me_id(staff.id)
    client = RawUser(id=200001, first_name="Ivan")
    store.put_users([staff, bot, client])
    store.put_chats([RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка support",
                             username="romashka_northwind", participant_ids=(staff.id, bot.id, client.id))])
    lines = ["пишите в tg@northwind_support", "бот Northwind_Bot не отвечает", "ссылка на чат: romashka_northwind",
             "Northwind работает, northwind.ru открыт"]
    store.append_messages(-1001, [RawMessage(chat_id=-1001, id=i, date=T0 + timedelta(minutes=i), sender_id=client.id,
                                             sender_kind=SENDER_USER, text=t) for i, t in enumerate(lines, 1)])
    ds, out, report = run(tmp_path, store, policy)
    texts = [m.text for m in ds.messages]
    assert re.fullmatch(r"пишите в tg@U\d+", texts[0]) and re.fullmatch(r"бот @U\d+ не отвечает", texts[1])
    assert re.fullmatch(r"ссылка на чат: @C\d+", texts[2])
    assert texts[3] == "Northwind работает, northwind.ru открыт"   # the keep term itself stays
    assert report.ok, report.leaks


def test_an_account_managers_soft_sign_surname_is_scrubbed_and_never_suggested(tmp_path):
    staff = RawUser(id=1001, first_name="Олег", last_name="Коваль", username="oleg_support")
    titles = [f"Client{i} × Коваль" for i in range(4)]
    store = store_with(tmp_path, [staff], titles, ["Коваль на связи, звоните Ковалю"] * 4)
    ds, out, report = run(tmp_path, store)
    # The surname is in every title, so it is an organisation term as well;
    # either way it is removed and never offered for keep_terms.
    assert {m.text for m in ds.messages} == {"<org> на связи, звоните <org>"}
    assert ds.private["keep_terms_suggested"] == []
    assert report.ok, report.leaks
    assert "Коваль" in vocabulary(store, AnonPolicy()).person_terms


@pytest.mark.parametrize("policy,text,expected", [
    (AnonPolicy(name_mode="none"), "Игорь на связи, Шамиль Бондарь тоже", "<name> на связи, <name> тоже"),
    (AnonPolicy(), "Бондарь ответил, Shevchenko ok", "<name> ответил, <name> ok"),
])
def test_participants_with_such_surnames_end_to_end(tmp_path, policy, text, expected):
    users = [RawUser(id=1001, first_name="Олег", last_name="Северов", username="oleg_support"),
             RawUser(id=1002, first_name="Игорь", last_name="Петров"),
             RawUser(id=1003, first_name="Шамиль", last_name="Бондарь"),
             RawUser(id=1004, first_name="Anna", last_name="Shevchenko")]
    store = store_with(tmp_path, users, ["Ромашка support"], [text])
    ds, out, report = run(tmp_path, store, policy)
    assert [m.text for m in ds.messages] == [expected]
    assert report.ok, report.leaks
