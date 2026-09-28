"""Operator custom patterns, pasted Telegram Desktop headers and the places
where the scrubber and the leak scanner have to agree: a header whose name
part also held a handle, an address, a link or a card; a keep term that blocked
the operator's own regex; scanner hits on the scrubber's own renderings
("@user", "@U04217", "424242**********"); patterns that can match the empty
string; an order label read out of a handle; and the IPv6 loopback address.
Every scrubbed case is also flagged by the leak scanner on the raw text and
passes it on the output; every kept case stays byte-identical and the scanner
is silent on it."""

from datetime import datetime, timedelta, timezone

import pytest

from conftest import check
from tg_collector.anonymize import Mapping, anonymize
from tg_collector.config import AnonPolicy, ConfigError, Output, Settings
from tg_collector.dataset import write_dataset
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber
from tg_collector.verify import verify

BINS = ("424242", "400000", "510510")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS)))


# --- a pasted Telegram Desktop header names a person whatever else it holds ------------

@pytest.mark.parametrize("text", [
    "Пётр Иванов, [12.03.2024 10:15]",
    "Пётр Иванов (@some_buyer), [12.03.2024 10:15]",
    "Пётр Иванов pete@example.com, [12.03.2024 10:15]",
    "Пётр Иванов https://example.com, [12.03.2024 10:15]",
    "Пётр Иванов +79161112233, [12.03.2024 10:15]",
    "Пётр 4242424242424242, [12.03.2024 10:15]",
    "ivan.example @ mail.ru, [12.03.2024 10:15]",
    "Олег Северов @oleg_support, [12.03.2024 10:15]",
])
def test_header_name_with_a_value_inside_is_still_a_name(scrub, scanner, text):
    check(scrub, scanner, text, "<name>, [12.03.2024 10:15]")


@pytest.mark.parametrize("text,expected", [
    ("[Forwarded from Пётр Иванов @some_buyer]", "[Forwarded from <name>]"),
    ("[Переслано от Пётр Иванов @some_buyer]", "[Переслано от <name>]"),
    ("[В ответ на Олег Северов pete@example.com]", "[В ответ на <name>]"),
    ("[In reply to Пётр Иванов 4242424242424242]", "[In reply to <name>]"),
])
def test_companion_line_name_with_a_value_inside(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_header_rules_run_before_the_link_and_card_layers(scrub):
    """A pasted conversation keeps one placeholder per header line."""
    pasted = ("Пётр Иванов (@some_buyer), [12.03.2024 10:15]\n"
              "оплата не прошла\n"
              "Анна Смирнова anna@example.com, [12.03.2024 10:16]\n")
    assert scrub(pasted) == ("<name>, [12.03.2024 10:15]\n"
                             "оплата не прошла\n"
                             "<name>, [12.03.2024 10:16]\n")


@pytest.mark.parametrize("text,expected", [
    # No time in the stamp, no header.
    ("Итого: 1500, [12.03.2024]", "Итого: 1500, [12.03.2024]"),
    ("см. [12.03.2024 10:15]", "см. [12.03.2024 10:15]"),
    # A handle in running prose is still only a handle.
    ("пишите @some_buyer, [это важно]", "пишите @user, [это важно]"),
    ("оплата по заказу 4521, [см. вложение]", "оплата по заказу 4521, [см. вложение]"),
])
def test_header_negatives(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_scrubbed_header_is_not_reported_again(scanner):
    for out in ("<name>, [12.03.2024 10:15]", "    <name>, [12.03.2024 10:15]",
                "    #12: <name>, [12.03.2024 10:15]", "[Forwarded from <name>]"):
        assert scanner.scan(out) == []


# --- an operator pattern wins over a keep term, on both sides --------------------------

@pytest.fixture
def northwind():
    policy = AnonPolicy(keep_terms=("Northwind",), custom_patterns=(r"Northwind-\d+",))
    return (Scrubber(policy, Roster(keep_terms=("Northwind",))).scrub,
            LeakScanner(Known(keep_terms=frozenset({"Northwind"})), custom_patterns=policy.custom_patterns))


def test_custom_pattern_beats_a_keep_term_inside_it(northwind):
    scrub, scanner = northwind
    assert scanner.scan("аккаунт Northwind-104233 заблокирован")
    check(scrub, scanner, "аккаунт Northwind-104233 заблокирован", "аккаунт <redacted> заблокирован")


@pytest.mark.parametrize("text", ["Northwind работает", "Northwind лучший", "в Northwind есть отчёты"])
def test_keep_term_outside_the_pattern_stays(northwind, text):
    scrub, scanner = northwind
    check(scrub, scanner, text, text)


def test_custom_pattern_inside_a_kept_link():
    policy = AnonPolicy(url_mode="keep", keep_terms=("Northwind",), custom_patterns=(r"Northwind-\d+",))
    scrub = Scrubber(policy, Roster(keep_terms=("Northwind",))).scrub
    assert scrub("https://example.com/a/Northwind-104233") == "https://example.com/a/<redacted>"


# --- the scanner never reports the scrubber's own renderings ---------------------------

def test_custom_pattern_does_not_flag_our_own_handle():
    scanner = LeakScanner(Known(), custom_patterns=(r"\b[UC]\d{5}\b",))
    assert scanner.scan("@U04217 пишет") == []
    assert scanner.scan("@C01735") == []
    assert [x.kind for x in scanner.scan("клиент U12345")] == ["custom"]
    assert [x.kind for x in scanner.scan("U04217")] == ["custom"]


def test_custom_pattern_does_not_flag_a_masked_card():
    scanner = LeakScanner(Known(), custom_patterns=(r"(?<!\d)\d{6}(?!\d)",))
    assert scanner.scan("карта 424242**********") == []
    assert [x.kind for x in scanner.scan("id 123456")] == ["custom"]


def test_custom_pattern_does_not_flag_the_placeholder_handle():
    assert LeakScanner(Known(), custom_patterns=(r"user\w*",)).scan("пишите @user") == []
    assert [x.kind for x in LeakScanner(Known(), custom_patterns=(r"user\w*",)).scan("username ivan")] == ["custom"]


def test_title_word_does_not_flag_the_placeholder_handle():
    scanner = LeakScanner(Known(titles=frozenset({"User"})))
    assert scanner.scan("пишите @user") == []
    assert [x.kind for x in scanner.scan("User Group")] == ["title"]


def test_custom_pattern_still_reports_a_value_in_a_product_constant():
    """An ALL_CAPS constant is product knowledge, but the operator's own
    regex is an explicit instruction and outranks it."""
    assert [x.kind for x in LeakScanner(Known(), custom_patterns=(r"ACC\d{4}",)).scan("ERR_ACC1234_FAILED")] == ["custom"]


def test_scrubber_output_matches_the_scanner_on_custom_patterns():
    policy = AnonPolicy(card_bins=BINS, custom_patterns=(r"(?<!\d)\d{6}(?!\d)",))
    scanner = LeakScanner(Known(card_bins=frozenset(BINS)), custom_patterns=policy.custom_patterns)
    out = Scrubber(policy, Roster()).scrub("карта 4242 4242 4242 4242")
    assert out == "карта 424242**********"
    assert scanner.scan(out) == []

    policy = AnonPolicy(custom_patterns=(r"\b[UC]\d{5}\b",))
    scanner = LeakScanner(Known(usernames=frozenset({"ivan_petrov"})), custom_patterns=policy.custom_patterns)
    out = Scrubber(policy, Roster(by_username={"ivan_petrov": "U04217"})).scrub("@ivan_petrov пишет")
    assert out == "@U04217 пишет"
    assert scanner.scan(out) == []


# --- a pattern that can match the empty string is a configuration error -----------------

@pytest.mark.parametrize("pattern", [r"\d*", "x*", "", r"(КПП)?\d*", r"(?:\d+)?"])
def test_config_rejects_an_empty_matching_pattern(tmp_path, pattern):
    # TOML literal strings ('...') carry a regex as written, without escaping.
    (tmp_path / "config.toml").write_text(f"[anonymize]\ncustom_patterns = ['{pattern}']\n")
    with pytest.raises(ConfigError, match="empty string"):
        Settings.load(tmp_path)


@pytest.mark.parametrize("pattern,text,expected", [
    (r"КПП\s*\d{9}", "ok 12, КПП 123456789", "ok 12, <redacted>"),
    (r"(?<=КПП\s)\d{9}", "КПП 770701001", "КПП <redacted>"),
    (r"(?<=КПП\s)\d{9}", "КПП 123456789", "КПП <redacted>"),
])
def test_value_only_pattern_loads_and_keeps_the_keyword(tmp_path, pattern, text, expected):
    (tmp_path / "config.toml").write_text(f"[anonymize]\ncustom_patterns = ['{pattern}']\n")
    policy = Settings.load(tmp_path).anon
    assert Scrubber(policy, Roster()).scrub(text) == expected
    assert LeakScanner(Known(), custom_patterns=policy.custom_patterns).scan(expected) == []


@pytest.mark.parametrize("pattern", [r"\d*", r"(?<=КПП )\d*", r"(КПП)?\d*"])
def test_zero_width_match_replaces_nothing(pattern):
    """A policy assembled in code bypasses the configuration check; a
    zero-width match must still leave the text alone instead of shredding it."""
    assert Scrubber(AnonPolicy(custom_patterns=(pattern,)), Roster()).scrub("ok") == "ok"
    assert LeakScanner(Known(), custom_patterns=(pattern,)).scan("ok") == []


def test_zero_width_pattern_still_replaces_what_it_does_match():
    scrub = Scrubber(AnonPolicy(custom_patterns=(r"(КПП)?\d*",)), Roster()).scrub
    assert scrub("ok 12") == "ok <redacted>"


# --- an order label is not read out of a handle ----------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("@order 3184713454", "@user <rnokpp>"),
    ("@order: 3184713454", "@user: <rnokpp>"),
    ("@orders 3184713454", "@user <rnokpp>"),
])
def test_handle_text_is_not_an_order_label(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "#order 3184713454",
    "order 3184713454",
    "заказ 3184713454",
    "заказ № 3184713454",
])
def test_a_real_order_label_still_keeps_its_number(scrub, scanner, text):
    check(scrub, scanner, text, text)


# --- the IPv6 loopback names no host ---------------------------------------------------

@pytest.mark.parametrize("text", [
    "bind [::1]:8080",
    "адрес ::1",
    "слушаем на [::1]:8443",
    "сервер поднят на ::1, порт 8000",
    "0:0:0:0:0:0:0:1 это тот же loopback",
])
def test_loopback_ipv6_stays(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("fe80::1", "<ip>"),
    ("адрес 2001:db8::1", "адрес <ip>"),
    ("подключение к 2001:db8:85a3::8a2e:370:7334", "подключение к <ip>"),
])
def test_a_real_ipv6_address_is_still_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_loopback_inside_a_kept_link():
    scrub = Scrubber(AnonPolicy(url_mode="keep"), Roster()).scrub
    scanner = LeakScanner(Known(), url_allowed=lambda _: True)
    out = scrub("см http://[::1]:8000/x")
    assert out == "см http://[::1]:8000/x"
    assert scanner.scan(out) == []
    assert [x.kind for x in scanner.scan(scrub("см http://[2001:db8::1]:8000/x"))] == ["ipv6"]


# --- the whole run agrees: anonymize writes what verify accepts ------------------------

T0 = datetime(2024, 3, 12, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
CLIENT = RawUser(id=2, first_name="Иван", last_name="Петров")


def test_anonymized_export_with_custom_patterns_verifies_clean(tmp_path):
    policy = AnonPolicy(keep_terms=("Northwind",), custom_patterns=(r"Northwind-\d+",), card_bins=BINS)
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка — Northwind",
                   participant_ids=(ME.id, CLIENT.id))
    store.put_chats([chat])
    store.put_users([ME, CLIENT])
    store.set_me_id(ME.id)
    texts = [
        "аккаунт Northwind-104233 заблокирован, Northwind работает",
        "Пётр Иванов (@some_buyer), [12.03.2024 10:15]\nкарта 4242 4242 4242 4242",
        "слушаем на [::1]:8443, @order 3184713454",
    ]
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=i, date=T0 + timedelta(minutes=i), sender_id=CLIENT.id,
                   sender_kind=SENDER_USER, text=text)
        for i, text in enumerate(texts, 1)
    ])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(timezone="Europe/Berlin"), {"output": {"timezone": "Europe/Berlin"}})
    report = verify(out, store, policy, tmp_path / "verify_report.json")
    assert report.ok, report.leaks

    body = (out / "messages.jsonl").read_text(encoding="utf-8")
    assert "Northwind-104233" not in body and "<redacted>" in body
    assert "Northwind работает" in body            # the keep term outside the pattern stays
    assert "Пётр" not in body and "some_buyer" not in body
    assert "424242**********" in body              # the card is still masked next to the header
    assert "[::1]:8443" in body                    # loopback is product knowledge
    assert "3184713454" not in body
