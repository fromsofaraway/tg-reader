"""Core scrubbing mechanics: keyword rules replace only their value, labels
on their own line, placeholder-aware scanning, rule order, kept links."""

import pytest

from tg_collector import scrub as scrub_module
from conftest import BOT_TOKEN, BOT_TOKEN_DASH, BOT_TOKEN_ID_LIKE, JWT, STRIPE_LIVE_SHORT
from tg_collector.config import AnonPolicy
from tg_collector.model import Entity
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

PUA = set(range(0xE000, 0xE200))


@pytest.fixture
def roster():
    return Roster(by_username={"ivan_petrov": "U0002", "alice": "U0044"}, by_user_id={5: "U0002"},
                  known_ids=(123456789,), person_terms=("Петров",), org_terms=("Ромашка",))


@pytest.fixture
def scrubber(roster):
    return Scrubber(AnonPolicy(card_bins=("400000",)), roster)


def clean(text: str) -> bool:
    return not any(ord(c) in PUA for c in text)


@pytest.mark.parametrize("text,expected", [
    ("cvv карты Петрова 123", "cvv карты <name> <cvv>"),
    ("код для @ivan_petrov: 482913", "код для @U0002: <otp>"),
    ("код для ivan_petrov: 482913", "код для @U0002: <otp>"),
    ("код на ivan.example@gmail.com: 482913", "код на <email>: <otp>"),
    ("пароль от ivan.example@gmail.com: Abc123!", "пароль от <email>: <password>!"),
    ("код с сайта acme-pay.ru: 482913", "код с сайта <domain>: <otp>"),
    ("код от Ромашки: 482913", "код от <org>: <otp>"),
    ("паспорт Петров Иван Иванович 45 09 123456", "паспорт <name> <passport>"),
    ("cvv для карты 4000 0000 0000 0002: 123", "cvv для карты 400000**********: <cvv>"),
    ("код для карты 4000 0000 0000 0002 — 482913", "код для карты 400000********** — <otp>"),
    ("код из смс на https://acme.ru/x: 482913", "код из смс на <url> <otp>"),
    ("пароль от alice.example@mail.ru: hunter22", "пароль от <email>: <password>"),
    ("код для @alice: 482913", "код для @U0044: <otp>"),
    ("код ошибки 40012", "код ошибки 40012"),
    ("тикет #48213, код 482913", "тикет #48213, код <otp>"),
    ("срок 12/27 cvv 123", "срок <exp> cvv <cvv>"),
])
def test_keyword_rules_replace_only_the_value(scrubber, text, expected):
    out = scrubber.scrub(text)
    assert out == expected and clean(out)


def test_sentinels_inside_a_keyword_gap_resolve(scrubber):
    assert scrubber.scrub("код для @ivan_petrov: 482913", [Entity("Mention", 8, 12)]) == "код для @U0002: <otp>"
    assert scrubber.scrub("код для +79991234567: 482913", [Entity("Phone", 8, 12)]) == "код для <phone>: <otp>"
    assert scrubber.scrub("код для Иван: 482913", [Entity("MentionName", 8, 4, user_id=5)]) == "код для @U0002: <otp>"
    assert clean(scrubber.scrub("код 4242 4242 4242 4242 1234"))


@pytest.mark.parametrize("text,expected", [
    ("Пароль:\nQwerty123", "Пароль:\n<password>"),
    ("Логин\nivan2024\nПароль\nQwerty123", "Логин\n@user\nПароль\n<password>"),
    ("код из смс:\n482913", "код из смс:\n<otp>"),
    ("cvv\n123", "cvv\n<cvv>"),
    ("2fa ключ:\nJBSWY3DPEHPK3PXPJBSWY3DP", "2fa ключ:\n<2fa-secret>"),
    (f"api_key:\n{STRIPE_LIVE_SHORT}", "api_key:\n<token>"),
    ("memo:\n1234567", "memo:\n<id>"),
])
def test_label_on_its_own_line(scrubber, text, expected):
    assert scrubber.scrub(text) == expected
    assert LeakScanner(Known()).scan(text) and not LeakScanner(Known()).scan(expected)


@pytest.mark.parametrize("text", [
    "отправил код\nзаказ 48213 не прошёл", "код\nсумма 1500 usd", "код ошибки:\n4001", "error code\n50051",
    "пароль\nне подходит", "промокод\n12345", "пароль неверный\nверсия 2.15.3", "пароль:\n\nQwerty123",
])
def test_next_line_values_that_are_not_secrets(scrubber, text):
    assert scrubber.scrub(text) == text


@pytest.mark.parametrize("text", [
    "400000********** 12 27 123", "cvv <cvv> 456", "sort code <bank-code> account number <account>", "<passport>",
    '{"text": "password: <password>"}', "паспорт: <passport>, password: <password>", "код для @U0002", "pin @U0002",
    "password: <url:docs.acme.com>", "codes <otp> 5678", "pin <pin> 1234", "scan_@U0002.pdf", "[Forwarded from <name>]",
    "<name>, [12.03.2024 10:15]", "https://<sub>.acme.com/x", "act_<id>", "c_user=<cookie>",
])
def test_scanner_ignores_our_own_placeholders(text):
    assert LeakScanner(Known(card_bins=frozenset({"400000"}))).scan(text) == []


def test_scanner_still_reports_real_values():
    sc = LeakScanner(Known(card_bins=frozenset({"400000"})))
    assert [l.kind for l in sc.scan("password: hunter2")] == ["password"]
    assert [l.kind for l in sc.scan('password: "hunter2"')] == ["password"]
    assert [l.kind for l in sc.scan('password: "a<b>c1"')] == ["password"]
    assert [l.kind for l in sc.scan("код 482913")] == ["otp"]


@pytest.mark.parametrize("text,expected", [
    (f"бот {BOT_TOKEN_ID_LIKE} не отвечает", "бот <token> не отвечает"),  # the bot id passes the RNOKPP check
    (f"bot {BOT_TOKEN_DASH} ok", "bot <token> ok"),
    (f"({BOT_TOKEN_DASH})", "(<token>)"),
    (f"bot{BOT_TOKEN}", "bot<token>"),
    ("order 1234567890:paid-and-shipped-to-customer-yes", "order 1234567890:paid-and-shipped-to-customer-yes"),
])
def test_bot_tokens_precede_checksum_rules(scrubber, text, expected):
    assert scrubber.scrub(text) == expected


def test_rule_order_puts_tokens_before_domain_ids():
    names = [r.name for r in scrub_module._RULES]
    assert names.index("bot_token") < names.index("ua_rnokpp") and names.index("jwt") < names.index("kz_id")


@pytest.mark.parametrize("text", ["+4975749118", "+4989555979", "+380336515560", "+380411281517", "+4993296849024"])
def test_plus_means_phone_not_tax_id(scrubber, text):
    assert scrubber.scrub(text) == "<phone>"


def test_plain_ids_still_get_their_checksum_labels(scrubber):
    assert scrubber.scrub("ИНН 7700000425 и 770000000082") == "ИНН <tax-id> и <inn>"
    assert scrubber.scrub("вот 020531600149") == "вот <iin>"


@pytest.mark.parametrize("text", [
    "8 999 123 45 67", "89991234567", "8 (999) 123-45-67", "999 123 45 67", "9991234567", "тел.89991234567",
    "8\u2011999\u2011123\u201145\u201167", "8 9 9 9 1 2 3 4 5 6 7",
])
def test_self_check_recognises_known_phone_in_national_forms(text):
    sc = LeakScanner(Known(phones=frozenset({"79991234567"})), regex_rules=False)
    assert [l.kind for l in sc.scan(text)] == ["phone"]


@pytest.mark.parametrize("text", [
    "заказ №7999123456", "ticket #99912345 v2.10.3", "8 999 765-43-21", "timestamp 1726400000000", "2026-09-15 12:34:56",
])
def test_self_check_does_not_invent_known_phones(text):
    assert LeakScanner(Known(phones=frozenset({"79991234567"})), regex_rules=False).scan(text) == []


LINK = ("https://acme.com/users/ivan_petrov?email=ivan.example@x.io&phone=%2B79991234567&q=Петров&id=123456789&token="
        + JWT)
MASKED = "https://acme.com/users/@U0002?email=<email>&phone=<phone>&q=<name>&id=<id>&token=<token>"


@pytest.mark.parametrize("policy", [
    AnonPolicy(allow_domains=("acme.com",)), AnonPolicy(allow_domains=("*.acme.com",)), AnonPolicy(url_mode="keep"),
])
def test_kept_links_do_not_carry_identifiers(roster, policy):
    s = Scrubber(policy, roster)
    assert s.scrub(LINK) == MASKED
    assert s.scrub("см", [Entity("Url", 0, len(LINK))]) != LINK
    assert s.scrub("см. документацию", [Entity("TextUrl", 0, 3, url="https://acme.com/u/ivan_petrov?email=a@b.io")]) == \
        "см. (https://acme.com/u/@U0002?email=<email>) документацию"


def test_kept_links_keep_product_vocabulary(roster):
    s = Scrubber(AnonPolicy(allow_domains=("acme.com",)), roster)
    text = ("https://acme.com/orders/12345678901?tab=history https://acme.com/errors/1000123456#code-05 "
            "https://acme.com/release/1.2.3.4/notes https://acme.com/t/SUP-1234?page=2")
    assert s.scrub(text) == text


def test_telegram_link_rule_is_anchored(scrubber, roster):
    assert scrubber.scrub("https://revolut.me/ivanp https://about.me/x") == "<url> <url>"
    assert scrubber.scrub("comment.me/x") == "<url>"  # a host with a path is a link
    assert scrubber.scrub("www.t.me/ivanp https://sub.t.me/x t.me/c/1/2 tg://user?id=5") == "<tg-link> <tg-link> <tg-link> <tg-link>"
    kept = Scrubber(AnonPolicy(url_mode="keep", allow_domains=("about.me",)), roster)
    assert kept.scrub("https://about.me/ivanp www.t.me/ivanp https://sub.t.me/x") == "https://about.me/ivanp <tg-link> <tg-link>"
    assert [l.kind for l in LeakScanner(Known()).scan("https://about.me/ivanp")] == ["url"]


def test_report_lists_the_most_frequent_vocabulary_surfaces(scrubber):
    for _ in range(3):
        scrubber.scrub("Петров и Ромашка")
    report = scrubber.report()
    assert report["top_surfaces"]["person"] == {"петров": 3} and report["top_surfaces"]["org"] == {"ромашка": 3}
