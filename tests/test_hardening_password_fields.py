"""Passwords next to other fields: the value right after a password label is
the one replaced even when a login, e-mail or another label follows, quoted
passphrases are taken whole, code keys that end in a secret word are
recognised, and the scanner never reads an earlier replacement (a masked
card) as a password. Every scrubbed case is also flagged by the leak scanner
on the raw text and passes it on the output; every kept case stays
byte-identical and the scanner is silent on it."""


import pytest

from conftest import GITHUB_PAT, assert_fast, check
from tg_collector.config import AnonPolicy
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS, keep_terms=("Northwind",)),
                    Roster(keep_terms=("Northwind",))).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS), keep_terms=frozenset({"Northwind"})))


# --- the password is the value, not the next field's value ------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("password: hunter2 user: ivan", "password: <password> user: ivan"),
    ("пароль Qwerty123 логин: ivan", "пароль <password> логин: @user"),
    ("пароль: Qwerty123, логин: ivan_petrov", "пароль: <password>, логин: @user"),
    ("пароль: Qwerty123 логин: ivan_petrov", "пароль: <password> логин: @user"),
    ("пароль Qwerty123 почта: ivan@example.com", "пароль <password> почта: <email>"),
    ("password hunter22 email: ivan@example.com", "password <password> email: <email>"),
    ("пароль от почты: Qwerty123 телефон: +79991234567", "пароль от почты: <password> телефон: <phone>"),
    ("пароль Qwerty123 сервер: 203.0.113.5", "пароль <password> сервер: <ip>"),
    ("пароль Qwerty123 пин: 1234", "пароль <password> пин: <pin>"),
    ("пароль Олег2024 логин: oleg", "пароль <password> логин: @user"),
    ("пароль ivan_petrov логин: ivan", "пароль <password> логин: @user"),
    ("пароль Qwerty123; логин: ivan", "пароль <password>; логин: @user"),
    # Across a line break, in both directions.
    ("пароль Qwerty123\nлогин: ivan", "пароль <password>\nлогин: @user"),
    ("пароль:\nQwerty123\nлогин: ivan", "пароль:\n<password>\nлогин: @user"),
    (f"Доступы к стенду:\nlogin: admin\npassword: S3cretPass\ntoken: {GITHUB_PAT}",
     "Доступы к стенду:\nlogin: @user\npassword: <password>\ntoken: <token>"),
    # A second password label starts a new field: both values go.
    ("пароль Qwerty123 новый пароль: Qwerty456", "пароль <password> новый пароль: <password>"),
    ("новый пароль Qwerty123 старый пароль: Qwerty456", "новый пароль <password> старый пароль: <password>"),
    ("пароль: Qwerty123 и пароль от почты: Qwerty456", "пароль: <password> и пароль от почты: <password>"),
    # A conjunction joins two labels; the values follow in order.
    ("пароль и почта: Qwerty123 ivan@example.com", "пароль и почта: <password> <email>"),
    # Multi-word labels that end in ':' still work, brand names included.
    ("пароль от личного кабинета: Qwerty123", "пароль от личного кабинета: <password>"),
    ("пароль от AnyDesk: Qwerty123", "пароль от AnyDesk: <password>"),
    ("пароль AnyDesk: 123456789", "пароль AnyDesk: <password>"),
    ("password for the ad account: Qwerty123", "password for the ad account: <password>"),
    ("Пароль от ЛК:\nQwerty123", "Пароль от ЛК:\n<password>"),
])
def test_password_before_another_field(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- quoted passphrases --------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ('password: "Qwerty 123"', 'password: "<password>"'),
    ("пароль «Мой пароль 2024»", "пароль «<password>»"),
    ('пароль: "correct horse battery"', 'пароль: "<password>"'),
    ('{"password": "correct horse battery"}', '{"password": "<password>"}'),
    ("'password' => 'correct horse battery'", "'password' => '<password>'"),
    ('"password" => "hunter2"', '"password" => "<password>"'),
    # A quoted message: only its first token can be the password.
    ('password: "hunter2 is wrong"', 'password: "<password> is wrong"'),
    ('пароль: "Qwerty123 не подходит"', 'пароль: "<password> не подходит"'),
    ("пароль: «Qwerty123 не подходит»", "пароль: «<password> не подходит»"),
])
def test_quoted_passphrases_are_taken_whole(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    '{"password": "не менее 8 символов"}',
    'пароль: "не задан"',
    'DB_PASSWORD="not set"',
    '{"db_password": ""}',
    "пароль:\nошибка 4012",
    "Пароль от ЛК:\nверсия 2.3.1 не пускает",
    "пароль не подходит: ошибка 4001",
    "сброс пароля: ошибка",
])
def test_password_messages_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


# --- code keys that end in a secret word ---------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ('{"db_password": "hunter2"}', '{"db_password": "<token>"}'),
    ('"smtp_pass": "S3cret!"', '"smtp_pass": "<token>"'),
    ("{'api_secret': 'abc123XYZ'}", "{'api_secret': '<token>'}"),
    ("'api_secret' => 'abc123XYZ'", "'api_secret' => '<token>'"),
    ("db_password: hunter22", "db_password: <token>"),
    ('DB_PASSWORD="correct horse battery"', 'DB_PASSWORD="<token>"'),
])
def test_code_keys_with_secret_suffixes(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- earlier replacements in the value slot ------------------------------------------------------

@pytest.mark.parametrize("text", [
    "password: 424242**********",
    "пароль от карты 424242**********",
])
def test_masked_card_is_not_a_password(scanner, text):
    assert scanner.scan(text) == []


def test_card_after_a_password_label_is_masked_and_silent(scrub, scanner):
    check(scrub, scanner, "password: 4242424242424242", "password: 424242**********")


# --- speed ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("unit", ["«pw ", "pw «", 'pw "', "пароль Qwerty123 логин: ", 'password: "a ', "пароль от ",
                                  "a1 ", ": ", '"db_password": "'])
def test_password_fields_stay_fast(scrub, scanner, unit):
    text = (unit * 4096)[:4096]

    def pass_over():
        out = scrub(text)
        scanner.scan(text)
        scanner.scan(out)

    assert_fast(pass_over, label=unit)
