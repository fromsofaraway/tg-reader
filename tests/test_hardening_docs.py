"""The published documentation says what the code does.

Two kinds of test live here. The first pins behaviour the documentation
promises: a phone typed in keycap emoji is a phone, a shouted log level in
front of a bracketed stamp is not a pasted chat header, and every example the
README lists as removed really is removed while every example it lists as
kept survives byte-identical. The second reads README.md, docs/SETUP.md,
docs/RESIDUALS.md and the dataset README and holds their wording to the
strings the writer actually composes.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import check
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import (
    DATASET_README, AnonChat, AnonMessage, AnonUser, Dataset, render_transcript,
)
from tg_collector.model import KIND_SUPERGROUP
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

PROJECT_ROOT = Path(__file__).resolve().parent.parent
README = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
# The README wraps its lines, so an example is looked up with its blanks
# collapsed rather than as it happens to be broken across two source lines.
README_FLAT = " ".join(README.split())
SETUP = (PROJECT_ROOT / "docs" / "SETUP.md").read_text(encoding="utf-8")
RESIDUALS = (PROJECT_ROOT / "docs" / "RESIDUALS.md").read_text(encoding="utf-8")
CONFIG_EXAMPLE = (PROJECT_ROOT / "config.example.toml").read_text(encoding="utf-8")

BINS = ("424242", "400000", "510510")
T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
# A digit typed as a keycap emoji, with and without the variation selector.
KEYCAP = "\ufe0f\u20e3"
BARE_KEYCAP = "\u20e3"


def keycaps(digits: str, selector: str = KEYCAP, sep: str = "") -> str:
    return sep.join(d + selector for d in digits)


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS)))


# --- a phone typed in keycap emoji ----------------------------------------------------

def test_a_phone_written_in_keycap_emoji_is_a_phone(scrub, scanner):
    check(scrub, scanner, "тел " + keycaps("89991234567", BARE_KEYCAP), "тел <phone>", "phone")


def test_a_grouped_keycap_phone_is_a_phone(scrub, scanner):
    text = "+" + keycaps("7") + " " + keycaps("999") + " " + keycaps("123") + " " + keycaps("45") + " " + keycaps("67")
    check(scrub, scanner, text, "<phone>", "phone")


@pytest.mark.parametrize("text", [
    keycaps("1") + " Оплата\n" + keycaps("2") + " Доставка",  # an emoji-numbered list
    keycaps("2026") + " год",                                 # four keycaps are no run
    keycaps("12", sep=" ") + " шага",
])
def test_a_short_keycap_run_stays(scrub, scanner, text):
    check(scrub, scanner, text, text)


def test_a_keycap_run_of_five_never_reads_as_a_card(scrub, scanner):
    """Folding the keycaps hands the digits to the later layers, so the run
    is judged there like any other number: five digits are no card and no
    phone, and the scanner has nothing to report."""
    out = scrub("шаги " + keycaps("12345"))
    assert out == "шаги 12345", out
    assert not scanner.scan(out)


# --- a log level is not a pasted chat header ------------------------------------------

@pytest.mark.parametrize("level", ["ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE",
                                   "NOTICE", "ERR", "CRITICAL", "FATAL", "PANIC"])
def test_a_shouted_log_level_keeps_its_field(scrub, scanner, level):
    check(scrub, scanner, f"{level}, [2024-03-12 10:15:00]\nconnection refused",
          f"{level}, [2024-03-12 10:15:00]\nconnection refused")


def test_a_capitalised_level_is_a_name_like_any_other_word(scrub, scanner):
    """Only the shouted spelling is a level: "Error" reads as a name as
    readily, and a header carries a name."""
    check(scrub, scanner, "Error, [12.03.2024 10:15]", "<name>, [12.03.2024 10:15]", "td_header")


def test_a_real_pasted_header_is_still_removed(scrub, scanner):
    check(scrub, scanner, "Иван Петров, [12.03.2024 10:15]\nпривет",
          "<name>, [12.03.2024 10:15]\nпривет", "td_header")


def test_a_log_line_with_any_other_first_field_still_loses_it(scrub, scanner):
    """The residual RESIDUALS.md documents: only a log level is exempt."""
    check(scrub, scanner, "payment-service, [2024-03-12 10:15:00]",
          "<name>, [2024-03-12 10:15:00]", "td_header")


# --- what the README lists as removed, and as kept ------------------------------------

# What the README's "Removed" list claims, as (the fragment the list quotes,
# a message spelling it out, the expected output). A doc test: the claim and
# the behaviour move together.
README_REMOVED = [
    ("логин", "логин ivan_petrov", "логин @user"),
    ("ivan.example [at] mail [dot] ru", "пишите на ivan.example [at] mail [dot] ru", "пишите на <email>"),
    ("instagram.com/handle", "instagram.com/handle", "<url>"),
    ("northwind.client-shop.ru", "наш сайт northwind.client-shop.ru", "наш сайт <domain>"),
    ("file_4000000000000002.pdf", "file_4000000000000002.pdf", "file_400000**********.pdf"),
    ("4242424242424242|12|27|123", "4242424242424242|12|27|123", "424242**********|<exp>|<cvv>"),
    ("пароль из смс", "пароль из смс 482913", "пароль из смс <otp>"),
    ("держатель карты Visa Gold <cardholder>", "держатель карты Visa Gold Олег Северов",
     "держатель карты Visa Gold <cardholder>"),
    ("root:toor1234", "root:toor1234", "<credentials>"),
    ("пароль от личного кабинета:", "пароль от личного кабинета: Qwerty123",
     "пароль от личного кабинета: <password>"),
    ("<Password>", "<Password>Qwerty123</Password>", "<Password><password></Password>"),
    ("ключ активации VK7JG-NPHTM-C97JM-9MPGT-3V66T", "ключ активации VK7JG-NPHTM-C97JM-9MPGT-3V66T",
     "ключ активации <token>"),
    ("логин customer-acmeltd-cc-RU-city-moscow-sesstime-10",
     "логин customer-acmeltd-cc-RU-city-moscow-sesstime-10", "логин <token>"),
    ("customer-acmeltd-cc-RU-city-moscow-sesstime-10:Pa55w0rd",
     "customer-acmeltd-cc-RU-city-moscow-sesstime-10:Pa55w0rd", "<credentials>"),
    ("client_79161234567_northwind_payment_report_2026.xlsx",
     "client_79161234567_northwind_payment_report_2026.xlsx", "<token>.xlsx"),
    ("client_<phone>_report.xlsx", "client_79161234567_report.xlsx", "client_<phone>_report.xlsx"),
    ("скан_паспорт_<passport>.pdf", "скан_паспорт_4510123456.pdf", "скан_паспорт_<passport>.pdf"),
    ("уд.л.", "уд.л. 4510 123456", "уд.л. <passport>"),
    ("вод. уд.", "вод. уд. 7712345678", "вод. уд. <driver-licence>"),
    ("д/р", "д/р 12.03.1985", "д/р <dob>"),
    ("по адресу", "по адресу г. Алматы, ул. Абая 10", "по адресу <address>"),
    ("срок карты", "срок карты 12/27", "срок карты <exp>"),
    ("цвв", "цвв 123", "цвв <cvv>"),
    ("ПЕТРОВ ИВАН СЕРГЕЕВИЧ", "ПЕТРОВ ИВАН СЕРГЕЕВИЧ", "<name>"),
    ("меня зовут", "меня зовут Иван Смирнов", "меня зовут <name>"),
    ("[Forwarded from", "[Forwarded from Иван Петров]", "[Forwarded from <name>]"),
]

# Examples the README's "Kept" list gives: product knowledge that survives
# byte-identical, with the scanner silent on it.
README_KEPT = [
    "usdt: INV-20260312-000123",
    "код ответа 4001",
    "код товара 4001",
    "МСС код 5411",
    "код 4001 означает",
    "- код 4001: недостаточно средств",
    "| код 4001 | недостаточно средств |",
    "падает с кодом 5003",
    "срок до 12.03.2026",
    "срок 10-14 дней",
    "версия приложения 2.15.3.100",
    "обновитесь до 2.14.0.3",
    "APP_VERSION=1.2.3.4",
    "пункт 4.1.2.3",
    "127.0.0.1",
    "0.0.0.0:8080",
    "[::1]:8443",
    "1500.00 2300.50",
    "сумма 1500.00 12.03.2026",
    "ошибка PASSWORD_EXPIRED",
    "PASSWORD_MIN_LENGTH=8",
    "password_min_length: 8",
    "passwordMinLength",
    "password_reset_flow_v2",
    "tokens_rotation_plan_v2.docx",
    "PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001",
    "/api/v2/merchants/12345/transactions/2026-03-12",
    "report_2026_03_12_final_version_v2_export.xlsx",
    "offer-nutra-kz-2026-03-12-landing-v2",
    "ssh -p 2222",
    "mkdir -p /var/log",
    "docker run -u 1000:1000",
    "postgres:16-alpine",
    "docker compose -p Northwind2 up",
    "git log -p HEAD~3",
    "kubectl logs -p Pod1",
    "доступ: role:viewer",
    "права доступа: payments:write_all",
    "аккаунт: iOS:17.4",
    'пароль: "не задан"',
    '{"password": "не менее 8 символов"}',
    "пароль: неверный",
    "Пароль Устарел",
    "password: expired",
    '{"password": null}',
    "пароль 8-64 символа",
    "пароль: минимум 8 символов",
    "пароль: придёт отдельным письмом",
    "пароль: только латиница",
    'SECRET_KEY="см. README"',
    '{"secret_key": "выдаётся менеджером"}',
    'api_key: "храним в Vault"',
    "API_TOKEN=${API_TOKEN}",
    "<TokenType>Bearer</TokenType>",
    "<PinRequired>true</PinRequired>",
    "<ExpirePassword>true</ExpirePassword>",
    "пинг 1500 мс",
    "другая дата 12.03.2026",
    "индексация",
    "прописка не нужна",
    "адрес доставки можно изменить в течение 24 часов",
    "billing address must match the card",
    "адрес регистрации: 2 страница паспорта",
    "адрес доставки: 1-3 дня",
    "адрес: до 255 символов",
    "billing address: step 2 of 4",
    "для держателей Visa Gold",
    "держатель карты Visa Platinum",
    "Cardholder Name Mismatch",
    "держатели карт Райффайзен Премиум",
    "права на 1234567",
    "заявка id 1234567",
    "паспорт по 1234567",
    "пер. 1500 руб",
    "пер. на карту 1500",
    "2 cards by the way",
    "Yandex.Money",
    "App.Store",
    "Apple.Pay",
    "README.md",
    "CHANGELOG.md",
    "arr@2x.png",
    "lodash@4.17.21",
    "npm i @types/node",
]


def in_readme(fragment: str) -> bool:
    return " ".join(fragment.split()) in README_FLAT


@pytest.mark.parametrize("fragment,text,expected", README_REMOVED)
def test_every_removed_example_of_the_readme_is_removed(scrub, scanner, fragment, text, expected):
    assert in_readme(fragment), fragment
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", README_KEPT)
def test_every_kept_example_of_the_readme_survives(scrub, scanner, text):
    assert in_readme(text), text
    check(scrub, scanner, text, text)


def test_a_licence_key_after_a_licence_word_goes_and_a_reference_stays(scrub, scanner):
    """The README's "grouped licence keys after a licence word" claim, in
    both directions: a key goes, a reference run of the same shape stays."""
    check(scrub, scanner, "ключ активации XK7P2-9QWER-TY3UI-OP4AS-DF5GH", "ключ активации <token>")
    check(scrub, scanner, "license key: W269N-WFGWX-YVC9B-4J6C9-T83GX", "license key: <token>")
    check(scrub, scanner, "XK7P2-9QWER-TY3UI-OP4AS-DF5GH-QW3ER-TY7UI", "<token>")
    for kept in ("заказ INV-2026-0312-0001", "ORD-AB12-CD34-EF56-GH78",
                 "лицензия ABCD-EFGH-IJKL-MNOP на 12 месяцев", "ключ payment_status_code_01"):
        check(scrub, scanner, kept, kept)


def test_the_luhn_exception_the_readme_names_next_to_the_kept_order_numbers(scrub, scanner):
    """A bare order number that happens to pass Luhn is masked as a card.
    The README says so where it promises that order numbers are kept."""
    check(scrub, scanner, "заказ 4242424242424242", "заказ 424242**********")
    assert README.count("see [Known residuals](docs/RESIDUALS.md)") == 2


# --- the documentation and the writer agree -------------------------------------------

def transcript_of(**message_fields) -> str:
    ds = Dataset(
        users={"U00002": AnonUser(vid="U00002", name="Иван", role="client", side="CLIENT"),
               "U00048": AnonUser(vid="U00048", name="Anna", role="support", side="STAFF"),
               "U00071": AnonUser(vid="U00071", name="Northwind Bot", role="bot", side="BOT"),
               "U00090": AnonUser(vid="U00090", name="", role="deleted", side="UNKNOWN")},
        chats={"C01735": AnonChat(vid="C01735", title="C01735", kind=KIND_SUPERGROUP,
                                  participants=["U00002", "U00048", "U00071", "U00090"])},
        messages=[
            AnonMessage(chat="C01735", seq=1, date=T0, sender="U00002", role="client",
                        side="CLIENT", text="экспорт падает"),
            AnonMessage(chat="C01735", seq=2, date=T0, sender="U00048", role="support",
                        side="STAFF", text="смотрю", reply_to=1),
            AnonMessage(chat="C01735", seq=3, date=T0, sender="U00071", role="bot",
                        side="BOT", text="alert"),
            AnonMessage(chat="C01735", seq=4, date=T0, sender="U00090", role="deleted",
                        side="UNKNOWN", text="..."),
            AnonMessage(chat="C01735", seq=5, date=T0, sender=None, role="", side="UNKNOWN",
                        text="", **message_fields),
        ])
    return render_transcript(ds, ds.chats["C01735"], Output(max_chars=0))[0]


def test_the_transcript_header_shows_the_line_shape_the_renderer_writes():
    text = transcript_of(action="pinned")
    header = next(line for line in text.splitlines() if line.startswith("Line format:"))
    quoted = next(line for line in text.splitlines() if "↳#1" in line)
    assert "↳#N U##### \"quote\"" in header, header
    assert re.search(r"↳#1 U\d+ \"", quoted), quoted
    assert "↳#replied" not in text


def test_the_role_suffixes_the_readme_lists_are_the_ones_a_transcript_prints():
    text = transcript_of(action="pinned")
    for suffix in ("(support)", "(bot)", "(deleted)"):
        assert suffix in text, (suffix, text)
    assert "SYSTEM" in text
    roles = README[README.index("The role in\nbrackets is"):README.index("clients carry\nno")]
    for word in ("`support`", "`sales`", "`other`", "`bot`", "`deleted`", "`anonymous admin`"):
        assert word in roles, word
    assert "`SYSTEM`" in README


def test_the_dataset_readme_lists_every_key_a_message_row_can_carry():
    fields = DATASET_README[DATASET_README.index("* `messages.jsonl`"):DATASET_README.index("* `episodes.jsonl`")]
    for key in ("reply_to?", "topic?", "media?", "edited?", "forwarded?", "action?", "code?"):
        assert key in fields, key


def test_the_dataset_readme_says_an_episode_always_carries_a_topic():
    """``write_dataset`` writes "topic" on every episode row, null outside a
    forum, while a message row omits the key."""
    episodes = DATASET_README[DATASET_README.index("* `episodes.jsonl`"):DATASET_README.index("* `users.json`")]
    assert "topic?" not in episodes, episodes
    assert "always" in episodes and "null" in episodes


def test_the_dataset_readme_admits_an_older_mapping_may_mix_id_widths():
    assert "one fixed width per mapping" in DATASET_README
    assert "older version may mix widths" in DATASET_README
    assert "older mappings" not in README or "keeps its ids and its width" in README


# --- README, SETUP and config.example.toml --------------------------------------------

NUMBER_WORDS = {"two": 2, "three": 3, "four": 5 - 1, "five": 5, "six": 6}


def test_the_setup_guide_counts_the_settings_it_then_lists():
    heading = "For a first run four things matter:"
    assert heading in SETUP
    block = SETUP[SETUP.index(heading) + len(heading):SETUP.index("Everything else can stay")]
    bullets = [line for line in block.splitlines() if line.startswith("* ")]
    assert len(bullets) == NUMBER_WORDS["four"], bullets
    assert "three things" not in SETUP


def test_the_readme_sends_the_reader_to_the_residual_list():
    assert (PROJECT_ROOT / "docs" / "RESIDUALS.md").is_file()
    assert README.count("docs/RESIDUALS.md") >= 3
    assert "Known residuals of the anonymizer, by design" not in README


def test_no_limitation_is_called_a_design_decision():
    for name, text in (("README.md", README), ("docs/RESIDUALS.md", RESIDUALS), ("docs/SETUP.md", SETUP)):
        assert "by design" not in text, name


def test_every_residual_item_carries_exactly_one_kind():
    """The list is grouped by kind, so a reader can read the leaks first and
    stop. Each of the three headings appears once, in that order."""
    kinds = ["## Leaks", "## Over-scrubs", "## Verify limits"]
    positions = [RESIDUALS.index(k) for k in kinds]
    assert positions == sorted(positions), positions
    for kind in kinds:
        assert RESIDUALS.count(kind) == 1, kind
    body = RESIDUALS[positions[0]:]
    assert body.count("\n* ") + body.count("\n  * ") > 60, "the residuals are bullets, not one paragraph"


def test_the_residual_list_documents_the_over_scrubs_this_release_leaves_standing():
    for example in ("`test:e2e-ci`", "`credentials: type:oauth2`", "`доступ: role:ReadOnly`",
                    "`аккаунт: shop:12345`"):
        assert example in RESIDUALS, example


@pytest.mark.parametrize("text,expected", [
    ("test:e2e-ci", "<credentials>"),
    ("credentials: type:oauth2", "credentials: <credentials>"),
    ("доступ: role:ReadOnly", "доступ: <credentials>"),
    ("аккаунт: shop:12345", "аккаунт: <credentials>"),
])
def test_the_documented_credential_over_scrubs_are_what_the_code_does(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_a_two_character_custom_term_is_documented_as_uninflected():
    for text in (RESIDUALS, CONFIG_EXAMPLE, README):
        assert "Яру" in text and "яр" in text


@pytest.mark.parametrize("text,expected", [
    ("ЯР подключил", "<org> подключил"),
    ("крутой яр у реки", "крутой <org> у реки"),   # the documented over-scrub
    ("в Яру тепло", "в Яру тепло"),                # the documented residual
])
def test_a_two_character_custom_term_behaves_as_documented(text, expected):
    scrubber = Scrubber(AnonPolicy(custom_terms=["ЯР"]), Roster(org_terms=("ЯР",)))
    assert scrubber.scrub(text) == expected


def test_verify_exempts_allowed_hosts_as_well_as_keep_terms():
    """The scanner exempts what the scrubber exempts, and the scrubber keeps
    an allowed host as well as a keep term."""
    section = README[README.index("* `verify` additionally hunts"):README.index("* `data/anon/anonymize_report.json`")]
    assert "`allow_domains`" in section and "`url_mode`" in section


def test_generic_chat_title_words_are_not_called_organisation_names_twice():
    removed = README[README.index("Removed: Telegram ids"):README.index("Kept: first names")]
    assert "every significant chat-title word" in removed
    assert "(every chat-title word" not in removed
