"""Phones next to amounts and dates, dotted quads that are versions or
clause numbers, and pasted Telegram Desktop headers on indented transcript
lines. Every case is checked in both directions: what the scrubber keeps
the leak scanner leaves alone, and what it removes the scanner reports."""

import random
from datetime import datetime, timedelta, timezone

import pytest

from conftest import assert_cost_ratio, assert_fast
from tg_collector.anonymize import Mapping, anonymize
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import (KIND_SUPERGROUP, SENDER_USER, Media, RawChat, RawMessage, RawUser,
                                Roles)
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber
from tg_collector.verify import verify


@pytest.fixture(scope="module")
def scrub():
    return Scrubber(AnonPolicy(), Roster()).scrub


@pytest.fixture(scope="module")
def scanner():
    return LeakScanner(Known())


def kinds(scanner, text):
    return {leak.kind for leak in scanner.scan(text)}


# --- amounts and dates are not phones ----------------------------------------------------

@pytest.mark.parametrize("text", [
    "сумма 1500.00 12.03.2026 10:30", "1500.00 12.03.2026", "1500.00 2300.50", "курс 92.50 93.10 94.00",
    "итого: 1500.00 2300.50 3800.50", "5650.07 10591.25 81007.33", "1500.00 2300.50 USD", "1500 2300.50",
    "ставка 12.50 13.75 14.00 15.25", "1500.00\t2300.50", "1500.00\xa02300.50", "списали 1500.00 1500.00",
    "4521 1500.00 12.03.2026 отклонён", "TX-1001\t1500.00\t12.03.2026\tdeclined", "сумма\t1500.00\t12.03.2026",
    "12 500.00 23 000.50", "05.06 07.08 09.10", "10:30 1500.00 2300.50", "15.03 1500.00", "сумма 100.00 12.03.26",
    "баланс 12500.00 13400.50", "10.5 20.25 30.75 40.00", "комиссия 2.5% 1500.00 37.50", "1500.00-2300.50",
    "Иван, вам вернули 1500.00 12.03.2026, срок зачисления 10-14 дней",
    # "т" and a bare "номер" are no phone label (order numbers)
    "т 1500.00 2300.50", "номер 1500.00 2300.50",
])
def test_amount_and_date_columns_are_not_phones(scrub, text):
    assert scrub(text) == text
    assert "phone" not in kinds(LeakScanner(Known(phones=frozenset({"79991234567"}))), text)


@pytest.mark.parametrize("text,expected", [
    # a phone word keeps the run a phone
    ("тел 1500.00 2300.50", "тел <phone>"), ("тел 8 999 123 45.67", "тел <phone>"),
    ("мой телефон 8 999 123 45.67", "мой телефон <phone>"), ("whatsapp: 8 999 123.45 67", "whatsapp: <phone>"),
    ("звоните 999.12 34 56 78", "звоните <phone>"), ("тел 999 123 4567 12.50", "тел <phone> 12.50"),
    ("позвоните 999 123 45.67", "позвоните <phone>"),
    # a Russian number written with a dot
    ("8 999 123.45 67", "<phone>"), ("8 999 123 45.67", "<phone>"), ("999 123 45.67", "<phone>"),
    ("(999) 123.45 67", "<phone>"), ("8-999 123.45 67", "<phone>"), ("8 495 123.45 67", "<phone>"),
    ("+7 999 123 45.67", "<phone>"), ("8.999.123.45.67", "<phone>"), ("+7.999.123.45.67", "<phone>"),
    ("8 999.123.45.67", "<phone>"), ("8 999 123.45.67", "<phone>"), ("999 123.45.67", "<phone>"),
    ("999.123.45.67", "<phone>"), ("8 800 555.35.35", "<phone>"), ("+7 (999) 123.45.67", "<phone>"),
    ("+33 1 23 45 67.89", "<phone>"), ("+1 202.555.0143", "<phone>"), ("1 202.555.0143", "<phone>"),
    ("202.555.0143", "<phone>"), ("8 999 123 45 67", "<phone>"),
    # an amount or a date in front stays, the phone after it is matched on its own
    ("1500.00 8 999 123 45 67", "1500.00 <phone>"), ("1500.00 89991234567", "1500.00 <phone>"),
    ("150.00 999 123 45 67", "150.00 <phone>"), ("сумма 1500.00 999 123 45 67", "сумма 1500.00 <phone>"),
    ("12.50 999 123 4567", "12.50 <phone>"), ("тел: 12.50 999 123 45 67", "тел: 12.50 <phone>"),
    ("звонил 12.03 999 123-45-67", "звонил 12.03 <phone>"), ("12.03.2026 999 123 45 67", "12.03.2026 <phone>"),
    ("2026-03-12 999 123 45 67", "2026-03-12 <phone>"), ("12.50\t999 123 45 67", "12.50\t<phone>"),
    ("99.90 495 123-45-67", "99.90 <phone>"), ("позвоните 1500.00 999 123 45 67", "позвоните 1500.00 <phone>"),
    ("мобильный: 12.03 999 123 45 67", "мобильный: 12.03 <phone>"),
    # a phone the run carries on into an amount is still a phone, and only
    # the number is replaced, so the amount and the time survive
    ("999 123 4567 12.50", "<phone> 12.50"), ("999 123 4567 1500.00", "<phone> 1500.00"),
    ("10:30 999 123.45 67", "10:30 <phone>"),
    # unchanged neighbours
    ("+7 999 123 45 67 1500 руб", "<phone> 1500 руб"), ("сумма 1500.00\n8 999 123 45 67", "сумма 1500.00\n<phone>"),
])
def test_phones_next_to_amounts_are_still_scrubbed(scrub, scanner, text, expected):
    assert scrub(text) == expected
    assert "phone" in kinds(scanner, text)
    assert scanner.scan(expected) == []


def test_known_phone_inside_an_amount_column_is_still_reported():
    sc = LeakScanner(Known(phones=frozenset({"79991234567"})))
    assert "phone" in {leak.kind for leak in sc.scan("1500.00 8 999 123 45 67 2300.50")}
    assert "phone" in {leak.kind for leak in sc.scan("1500.00 8 999 123.45.67 12.03.2026")}


# --- versions, clause numbers and loopback are not addresses -----------------------------

@pytest.mark.parametrize("text", [
    # a version or clause word right before the quad
    "версия 3.4.5.6", "v3.4.5.6", "build 2.15.3.100", "версия: 1.2.3.4", "Версия — 1.2.3.4",
    "версия приложения 2.15.3.100", "Версия приложения: 2.15.3.100", "версия клиента 2.15.3.100",
    "версия sdk 1.2.3.4", "версия конфигурации 3.0.150.25", "версия приложения 5.2.1.0, Android 14",
    "обновите на версию 2.15.3.100", "с версией 2.15.3.100", "сборке 4.1.2.3", "в релизе 2.15.3.100 починили",
    "APP_VERSION=1.2.3.4", "app_version=2.15.3.100", "clientVersion: 2.15.3.100",
    "релиза 2.15.3.100", "в сборке 2.15.3.100 исправлено", "сервер обновили, версия 2.15.3.100",
    "на сервере версия прошивки 1.2.3.4", "раздел 10.1.2.3", "версия 131.0.0.0",
    # a version word as a JSON or YAML key
    '{"version": "2.15.3.100"}', '"app_version": "3.0.150.25"', "version: '2.15.3.100'",
    # products that number their releases in four parts
    "БП 3.0.150.25", "ЗУП 3.1.30.101", "1С:Бухгалтерия 3.0.150.25", "ERP 2.5.12.105", "SDK 12.14.7.228",
    "модуль 8.6.9.149", "плагин 7.28.2.195", "на 1С 8.3.24.120 ошибка",
    "пункт 4.1.2.3 договора", "пункт 3.2.1.4 договора описывает сроки возврата", "п. 4.1.2.3 договора", "п.4.1.2.3",
    "раздел 4.1.2.3", "статья 4.1.2.3", "ст. 4.1.2.3", "глава 4.1.2.3", "section 4.1.2.3", "§ 4.1.2.3",
    # an update word or an app name, for a version-shaped quad
    "обновитесь до 3.4.5.6", "обновитесь до 2.14.0.3, там пофиксили краш на оплате", "после обновления до 2.15.3.100",
    "после обновления приложения до 2.15.3.100", "обновите приложение до 2.15.3.100", "обновите модуль до 2.1.0.5",
    "откатили приложение на 5.2.1.0", "update to 3.4.5.6", "updated the app to 3.4.5.6",
    "приложение 2.15.3.100", "app 2.15.3.100", "apk 2.15.3.100", "Android 14.0.0.1", "Андроид 14.0.0.1", "iOS 16.4.1.2",
    # loopback and the unspecified address
    "localhost 127.0.0.1", "127.0.0.1:5432", "0.0.0.0:8080", "bind 0.0.0.0:8080",
    "localhost:8080/callback не принимает POST, а 127.0.0.1:8080 принимает",
])
def test_versions_clauses_and_loopback_are_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert "ipv4" not in kinds(scanner, text)


@pytest.mark.parametrize("text,expected", [
    # private ranges and bare addresses
    ("10.0.0.1 внутренний", "<ip> внутренний"), ("192.168.0.1 это пример", "<ip> это пример"),
    ("gateway 172.16.0.1", "gateway <ip>"), ("host 192.168.1.10:8080", "host <ip>"), ("ip=10.0.0.1", "ip=<ip>"),
    ("203.0.113.7", "<ip>"), ("203.0.113.7:443", "<ip>"), ("203.0.113.7 не отвечает", "<ip> не отвечает"),
    ("1.1.1.1 не отвечает", "<ip> не отвечает"), ("проверьте 8.8.8.8 и 1.1.1.1", "проверьте <ip> и <ip>"),
    ("127.0.0.1 и 203.0.113.7", "127.0.0.1 и <ip>"), ("0.0.0.0 1.1.1.1", "0.0.0.0 <ip>"),
    ("127.0.0.1 -> 203.0.113.8", "127.0.0.1 -> <ip>"),
    # network words
    ("ip 203.0.113.7", "ip <ip>"), ("сервер 1.1.1.1", "сервер <ip>"), ("адрес: 203.0.113.7", "адрес: <ip>"),
    ("с ip 1.1.1.1 пришел запрос", "с ip <ip> пришел запрос"), ("клиент 1.1.1.1", "клиент <ip>"),
    ("IP клиента 203.0.113.7", "IP клиента <ip>"), ("client 1.1.1.1 connected", "client <ip> connected"),
    ("server_version_ip=1.2.3.4", "server_version_ip=<ip>"), ("conversion 203.0.113.7", "conversion <ip>"),
    ("версия 1.2 ip 1.1.1.1", "версия 1.2 ip <ip>"), ("whitelist 1.1.1.1", "whitelist <ip>"),
    # an update verb without a version: "на" alone, a network word, a customer
    ("IP сменился, обновите на 203.0.113.7", "IP сменился, обновите на <ip>"),
    ("IP обновили с 203.0.113.7 на 203.0.113.8", "IP обновили с <ip> на <ip>"),
    ("обновление с 203.0.113.7 на 203.0.113.8", "обновление с <ip> на <ip>"),
    ("обновили на 203.0.113.7", "обновили на <ip>"), ("обновить на 8.8.8.8 пожалуйста", "обновить на <ip> пожалуйста"),
    ("откатили на 1.1.1.1", "откатили на <ip>"), ("обновили до 203.0.113.7", "обновили до <ip>"),
    ("IP обновили до 1.1.1.1", "IP обновили до <ip>"), ("Обновили IP до 8.8.8.8", "Обновили IP до <ip>"),
    ("обновил ip на 1.1.1.1", "обновил ip на <ip>"), ("обновите IP на 203.0.113.7", "обновите IP на <ip>"),
    ("обновили DNS на 8.8.8.8", "обновили DNS на <ip>"), ("обновите сервер на 1.1.1.1", "обновите сервер на <ip>"),
    ("обновите api на 1.1.1.1", "обновите api на <ip>"), ("обновите клиента на 8.8.8.8", "обновите клиента на <ip>"),
    ("обновили бота на 1.1.1.1", "обновили бота на <ip>"), ("обновите whitelist до 8.8.8.8", "обновите whitelist до <ip>"),
    ("update ip to 1.1.1.1", "update ip to <ip>"), ("update the ip to 1.1.1.1", "update the ip to <ip>"),
    ("update your dns to 8.8.8.8", "update your dns to <ip>"),
    ("IP-адрес сменился, обновите приложение до 2.15.3.100", "IP-адрес сменился, обновите приложение до <ip>"),
    # a bare preposition or an app word with a network role
    ("пинг до 8.8.8.8", "пинг до <ip>"), ("доступ до 203.0.113.7", "доступ до <ip>"),
    ("сервер приложения 203.0.113.7", "сервер приложения <ip>"), ("IP приложения 1.1.1.1", "IP приложения <ip>"),
    ("IP сервера приложения 203.0.113.7", "IP сервера приложения <ip>"),
    ("webhook приложения 203.0.113.7 не отвечает", "webhook приложения <ip> не отвечает"),
    ("в приложении 203.0.113.7 ошибка", "в приложении <ip> ошибка"), ("приложение 203.0.113.7", "приложение <ip>"),
    ("app server 1.1.1.1", "app server <ip>"), ("приложение на 1.1.1.1", "приложение на <ip>"),
    ("приложение ходит на 1.1.1.1", "приложение ходит на <ip>"), ("linux 203.0.113.7", "linux <ip>"),
    ("сервер linux 203.0.113.7", "сервер linux <ip>"), ("у нас windows 203.0.113.7", "у нас windows <ip>"),
    ("IP-адреса: главный 203.0.113.7, резервный 203.0.113.8", "IP-адреса: главный <ip>, резервный <ip>"),
    ("стать 203.0.113.7", "стать <ip>"), ("item 203.0.113.7", "item <ip>"),
    ("переехали с 1.1.1.1 на 8.8.8.8", "переехали с <ip> на <ip>"), ("1.1.1.1 -> 8.8.8.8", "<ip> -> <ip>"),
    # a network word in front of an oblique build/release/version word
    ("сервер сборки 185.22.33.44", "сервер сборки <ip>"),
    ("IP сервера сборки: 10.0.0.12", "IP сервера сборки: <ip>"),
    ("белый IP для релиза: 185.22.33.44", "белый IP для релиза: <ip>"),
    ("хост релиза 185.22.33.44", "хост релиза <ip>"), ("машина для билдов 10.20.30.40", "машина для билдов <ip>"),
    ("IP для версии 185.22.33.44", "IP для версии <ip>"), ("IP сервера ERP 10.1.2.3", "IP сервера ERP <ip>"),
    ("прокси для сборки 185.22.33.44:3128", "прокси для сборки <ip>"),
    # an oblique clause or release word, and a quad that no release is numbered by
    ("в разделе 10.0.0.1 не пингуется", "в разделе <ip> не пингуется"),
    ("после релиза 185.22.33.44 недоступен", "после релиза <ip> недоступен"),
    ("SDK 203.0.113.3", "SDK <ip>"), ("SDK 192.168.1.10", "SDK <ip>"), ("плагин 203.0.113.7", "плагин <ip>"),
    ("подключитесь к 1С 10.0.0.5", "подключитесь к 1С <ip>"),
    ("сервер 10.0.0.1, SDK 12.14.7.228", "сервер <ip>, SDK <ip>"),  # a network word earlier cancels the weak signal
    ('{"ip": "10.0.0.1"}', '{"ip": "<ip>"}'), ('"host": "10.0.0.1"', '"host": "<ip>"'),
])
def test_addresses_are_still_scrubbed(scrub, scanner, text, expected):
    assert scrub(text) == expected
    assert "ipv4" in kinds(scanner, text)
    assert scanner.scan(expected) == []


# --- pasted Telegram Desktop headers on indented transcript lines ------------------------

STAMP = "[12.03.2024 10:15]"


@pytest.mark.parametrize("text", [
    f"<name>, {STAMP}", f"    <name>, {STAMP}", f"\t<name>, {STAMP}", f"\xa0<name>, {STAMP}",
    f"    #2: <name>, {STAMP}", f"    #12: <name>, {STAMP}", f"    <name>, {STAMP} ещё",
    f"@user, {STAMP}", f"    @U0002, {STAMP}",
])
def test_scanner_ignores_the_scrubbed_header(text):
    assert LeakScanner(Known()).scan(text) == []


@pytest.mark.parametrize("text", [
    f"    Иван Петров, {STAMP}", f"\xa0Иван, {STAMP}", f"    #6: Олег Северов, {STAMP}",
    f"    <name> Северов, {STAMP}", f"#2: Олег, {STAMP}", f"Анна Смирнова, {STAMP}",
])
def test_scanner_still_reports_a_real_header(scanner, text):
    assert "td_header" in kinds(scanner, text)


@pytest.mark.parametrize("text,expected", [
    (f"Вот:\n    Иван Петров, {STAMP}\n\tok", f"Вот:\n    <name>, {STAMP}\n\tok"),
    (f"Иван Петров, {STAMP}\nпривет", f"<name>, {STAMP}\nпривет"),
    (" " * 70 + f"Олег, {STAMP}", " " * 70 + f"<name>, {STAMP}"),
    (f"Олег Северов, {STAMP}\r\nтекст", f"<name>, {STAMP}\r\nтекст"),
    (f"#2: Олег Северов, {STAMP}", f"#2: <name>, {STAMP}"),
    (f"\xa0\xa0Олег Северов (Ромашка), {STAMP}", f"\xa0\xa0<name>, {STAMP}"),
    # not a header: text after the stamp, or no name at all
    (f"Ivan, {STAMP} not at end", f"Ivan, {STAMP} not at end"),
    (f"    <name>, {STAMP} ещё", f"    <name>, {STAMP} ещё"),
    (f" , {STAMP}", f" , {STAMP}"),
])
def test_scrubber_keeps_the_line_lead(scrub, scanner, text, expected):
    assert scrub(text) == expected
    assert scanner.scan(expected) == []


def test_pasted_headers_on_continuation_lines_pass_verify(tmp_path):
    """The transcript indents the further lines of a message and puts "#seq:"
    before a merged one; a scrubbed header there is the scrubber's own
    output, a verify run on the written dataset must stay clean."""
    t0 = datetime(2024, 3, 12, 9, 0, tzinfo=timezone.utc)
    me = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
    client = RawUser(id=11, first_name="Иван")
    chat = RawChat(id=-3001, kind=KIND_SUPERGROUP, title="Ромашка / Northwind", participant_ids=(1, 11))
    texts = [
        f"Вот переписка:\nИван Петров, {STAMP}\nне проходит оплата\nАнна Смирнова, [12.03.2024 10:17]\nпроверяю",
        f"Олег Северов, [12.03.2024 10:20]\nуже смотрим\n@oleg_support, [12.03.2024 10:21]\nок",
    ]
    store = RawStore(tmp_path / "raw")
    store.put_chats([chat])
    store.put_users([me, client])
    store.set_me_id(1)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=i + 1, date=t0 + timedelta(seconds=30 * i), sender_id=11,
                   sender_kind=SENDER_USER, text=text)
        for i, text in enumerate(texts)
    ])
    policy = AnonPolicy(keep_terms=("Northwind",))
    mapping = Mapping(tmp_path / "m.json")
    out = tmp_path / "dataset"
    write_dataset(anonymize(store, mapping, Roles.build(1), policy), out, Output(), {})
    transcript = (out / "transcripts" / f"{mapping.chat(chat.id)}.md").read_text(encoding="utf-8")
    assert f"    <name>, {STAMP}" in transcript and "    <name>, [12.03.2024 10:17]" in transcript
    assert "    #2: <name>, [12.03.2024 10:20]" in transcript
    for fragment in ("Петров", "Смирнова", "Северов", "oleg_support"):
        assert fragment not in transcript, fragment
    report = verify(out, store, policy, tmp_path / "verify_report.json")
    assert report.ok, report.leaks


# --- W3: a number hidden inside a longer run of numbers ---------------------------------------

@pytest.mark.parametrize("text,expected", [
    # a rejected run must not swallow the head of the real number
    ("заказ 4471 999 123.45 67", "заказ 4471 <phone>"), ("#4471 999 123.45 67", "#4471 <phone>"),
    ("1500 999 123.45 67", "1500 <phone>"), ("12/03/2026 999 123.45 67", "12/03/2026 <phone>"),
    ("перевод 5 000 999 123.45 67", "перевод 5 000 <phone>"),
    ("id 4521 999 123.45 67", "id 4521 <phone>"), ("id 4521 999 123 45 67", "id 4521 <phone>"),
    ("заказ 4471 999 123-45-67", "заказ 4471 <phone>"), ("заказ 4471 89991234567", "заказ 4471 <phone>"),
    # a landline without a trunk prefix
    ("клиент 495 123.45 67", "клиент <phone>"), ("99.90 495 123-45-67", "99.90 <phone>"),
    # a glued trunk prefix with a stray dot, labelled on either side
    ("8999123.45 67 звоните", "<phone> звоните"), ("звоните 8999123.45 67", "звоните <phone>"),
    ("вотсап 8999123.45 67", "вотсап <phone>"), ("8999123.45.67", "<phone>"),
    # an international number the run carried on into a statement column
    ("+79991234567 1500.00", "<phone> 1500.00"), ("тел +79991234567 1500.00", "тел <phone> 1500.00"),
    ("перевод по СБП +79991234567 1500.00 руб", "перевод по СБП <phone> 1500.00 руб"),
    ("kaspi +77011234567 1500.00", "kaspi <phone> 1500.00"),
    ("+380671234567 1500.00", "<phone> 1500.00"), ("+49 30 1234 5678 1500.00", "<phone> 1500.00"),
    ("+380 67 123 45 67", "<phone>"),
    ("10:30 89991234567 1500.00", "10:30 <phone> 1500.00"), ("в 10:30 89991234567 1500", "в 10:30 <phone> 1500"),
    # the colloquial spellings of the messenger label a bare number too
    ("вотсап 9031234567", "вотсап <phone>"), ("воцап 9031234567", "воцап <phone>"),
    ("в вотсапе 9031234567", "в вотсапе <phone>"),
])
def test_a_number_inside_a_run_of_numbers_is_scrubbed(scrub, scanner, text, expected):
    assert scrub(text) == expected
    assert "phone" in kinds(scanner, text)
    assert scanner.scan(expected) == []


@pytest.mark.parametrize("text", [
    # amount columns, ranges, enumerations and ids the national shape must not take
    "1500.00 2300.50", "92.50 93.10", "92.50 93.10 94", "курс 92.50 93.10", "4521 1500.00 12",
    "итого 8500000.00 15", "перевод 8500000.00 15 руб", "сумма 7495123.45 67", "итого 1234567.89 12",
    "сумма 1 799 912 345.67", "сумма 12 345 678.90", "999 123 456", "к оплате 999 000.00", "999 123.45",
    "10 000 - 20 000", "2024 - 2025 - 2026", "ошибки 7 101 - 102 - 103", "с 8 000 - 10 000 руб",
    "страницы 8 110 - 120 - 30 - 40", "счёт 1500 - 2300 - 45 - 67", "тариф 7 990 - 12 990 руб",
    "с 8 - 00 до 17 - 00", "с 7 до 8 - 900 - 100", "скидка 7 500 - 12 000", "заказ 8 - 1234 - 5678",
    "9991234567", "ticket_89991234567", "ORD-89991234567", "заказ 12345678901", "8999123.45 67",
    "позиции 101 102 103 104", "код 495 123", "вотсап не работает, заказ 1234567890",
    "+1 500 000 руб", "+7 999", "заказ 1234567890",
])
def test_the_national_shape_keeps_amounts_ranges_and_ids(scrub, scanner, text):
    assert scrub(text) == text
    assert "phone" not in kinds(scanner, text)


@pytest.mark.parametrize("text,expected", [
    ("звоните 8 (999) 123 - 45 - 67", "звоните <phone>"), ("тел: 8 - 999 - 123 - 45 - 67", "тел: <phone>"),
    ("моб. 8 999 123 - 45 - 67", "моб. <phone>"), ("номер +7 999 123 – 45 – 67", "номер <phone>"),
    ("+7 999 123 - 4567", "<phone>"), ("телефон 8 (999) 123 45 - 67", "телефон <phone>"),
    ("+7 701 123 - 45 - 67", "<phone>"), ("мой 8 (495) 123 - 45 - 67 офис", "мой <phone> офис"),
    ("8 - 999 - 123 - 4567", "<phone>"), ("8(999)123-45-67", "<phone>"),
])
def test_spaced_dashes_between_phone_groups(scrub, scanner, text, expected):
    assert scrub(text) == expected
    assert "phone" in kinds(scanner, text)
    assert scanner.scan(expected) == []


def test_the_national_shape_is_linear_on_hostile_runs(scrub):
    for text in ("9 " * 2048, " - 9" * 1024, "8 - 999 - 123 - 45 - 67 " * 170, "9.9" * 1365,
                 "999 " * 1024, "1500.00 " * 512, "8 999 123.45 67 1500.00 " * 170, "(999)" * 819,
                 "+79991234567 " * 315, "9\xa0" * 2048):
        assert_fast(lambda text=text: scrub(text), label=text[:40])


# --- W3: a participant's own number in any spelling -------------------------------------------

KNOWN = "79161112233"


@pytest.fixture(scope="module")
def known_scrub():
    return Scrubber(AnonPolicy(), Roster(phones=(KNOWN,))).scrub


@pytest.fixture(scope="module")
def known_scanner():
    return LeakScanner(Known(phones=frozenset({KNOWN})))


@pytest.mark.parametrize("text,expected", [
    ("89161112233", "<phone>"),          # the trunk prefix goes with the number, not "8<phone>"
    ("номер 9161112233", "номер <phone>"),
    ("9161112233", "<phone>"),
    ("8 (916) 111-22-33", "<phone>"),
    ("tx 79161112233000", "tx <phone>000"),
    ("scan_89161112233.pdf", "scan_<phone>.pdf"),
    ("+79161112233ошибка", "<phone>ошибка"),
    ("сумма 1 791 611 122.33", "сумма <phone>"),
    ("9161112233 и 9161112234", "<phone> и 9161112234"),
])
def test_a_known_number_goes_in_every_spelling(known_scrub, known_scanner, text, expected):
    assert known_scrub(text) == expected
    assert "phone" in {leak.kind for leak in known_scanner.scan(text)}
    assert known_scanner.scan(expected) == []


@pytest.mark.parametrize("text,expected", [
    # cutting the known number out of a run can expose another number
    ("7916111223389991234567", "<phone><phone>"),
    ("89991234567 79161112233", "<phone> <phone>"),
    ("9161112233 8 999 123 45 67", "<phone> <phone>"),
    ("заказ 7916111223312345", "заказ <phone>12345"),
])
def test_what_the_known_number_layer_leaves_is_judged_again(known_scrub, known_scanner, text, expected):
    assert known_scrub(text) == expected
    assert known_scanner.scan(expected) == []


@pytest.mark.parametrize("text", [
    "заказ 1234567890", "заказ 9161112234", "вотсап не работает, заказ 1234567890",
    "<phone>", "заказ 9031234567", "сумма 1500.00 2300.50", "916 111 22",
])
def test_a_number_that_is_not_the_known_one_stays(known_scrub, known_scanner, text):
    assert known_scrub(text) == text
    assert known_scanner.scan(text) == []


@pytest.mark.parametrize("text", [
    "9161112233", "номер 9161112233", "tx 79161112233000", "scan_9161112233.pdf",
    "сумма 1 791 611 122.33", "+79161112233ошибка",
])
def test_the_layer_adds_no_rule_without_profile_numbers(scrub, scanner, text):
    """With no participant number known, the same texts keep every digit:
    the layer is the profiles, not a wider phone shape. A national number in
    a file name ("scan_89161112233.pdf") is the general shape's business and
    goes without a profile too (see the file-name tests)."""
    assert scrub(text) == text
    assert scanner.scan(text) == []


def _one_message_store(tmp_path, text, phone, file_name=""):
    """A support chat with one client message; the client's profile carries
    ``phone``, as an export of a private dialog does."""
    t0 = datetime(2026, 3, 12, 9, 0, tzinfo=timezone.utc)
    me = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
    client = RawUser(id=11, first_name="Иван", phone=phone)
    chat = RawChat(id=-3001, kind=KIND_SUPERGROUP, title="Ромашка", participant_ids=(1, 11))
    store = RawStore(tmp_path / "raw")
    store.put_chats([chat])
    store.put_users([me, client])
    store.set_me_id(1)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=1, date=t0, sender_id=11, sender_kind=SENDER_USER, text=text,
                   media=Media(kind="document", file_name=file_name) if file_name else None)])
    return store, chat


def _anonymized_texts(tmp_path, text, phone, policy=None, file_name=""):
    store, chat = _one_message_store(tmp_path, text, phone, file_name)
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), policy or AnonPolicy())
    return [t for _, t in ds.texts()], store, chat


@pytest.mark.parametrize("text,expected", [
    # every shape that the phone rules reject but the self-check hunts for
    ("9161112233", "<phone>"),
    ("логин 9161112233", "логин <phone>"),
    ("переведите по номеру 9161112233", "переведите по номеру <phone>"),
    ("вотсап 9161112233", "вотсап <phone>"),
    ("tx 79161112233000", "tx <phone>000"),
    ("Мой номер 8 916\n111-22-33 звоните", "Мой номер <phone> звоните"),
    ("тел +7 916 111\n22 33", "тел <phone>"),
    ("8 (916) 111 - 22 - 33", "<phone>"),
    ("Заказы:\n12345\n79161112233\n67890", "Заказы:\n12345\n<phone>\n67890"),
    ("карта 9161112233 ок", "карта <phone> ок"),
    ("сумма 1 791 611 122.33", "сумма <phone>"),
])
def test_a_profile_number_never_aborts_the_run(tmp_path, text, expected):
    texts, _, _ = _anonymized_texts(tmp_path, text, KNOWN)
    assert expected in texts, texts
    assert "9161112233" not in " ".join(texts)


@pytest.mark.parametrize("text", ["заказ 12345678 ок", "заказ 9161112234", "заказ 1234567890"])
def test_other_numbers_pass_the_pipeline_unchanged(tmp_path, text):
    texts, _, _ = _anonymized_texts(tmp_path, text, KNOWN)
    assert text in texts, texts


def test_a_profile_number_in_a_kept_link_and_a_file_name(tmp_path):
    texts, _, _ = _anonymized_texts(tmp_path, "пишите в вотсап wa.me/79161112233",
                                    KNOWN, AnonPolicy(url_mode="keep"))
    assert "пишите в вотсап wa.me/<phone>" in texts, texts
    texts, _, _ = _anonymized_texts(tmp_path / "files", "скан", KNOWN,
                                    AnonPolicy(keep_file_names=True), "scan_89161112233.pdf")
    assert "scan_<phone>.pdf" in texts, texts


def test_a_profile_number_in_every_spelling_passes_verify(tmp_path):
    text = ("Мой номер 8 916\n111-22-33, вотсап 9161112233, ещё +79161112233ошибка,\n"
            "заказ 3184713454 на 1500.00 руб")
    texts, store, chat = _anonymized_texts(tmp_path, text, KNOWN)
    policy = AnonPolicy()
    out = tmp_path / "dataset"
    write_dataset(anonymize(store, Mapping(tmp_path / "m2.json"), Roles.build(1), policy), out, Output(), {})
    transcript = (out / "transcripts").glob("*.md")
    body = "\n".join(p.read_text(encoding="utf-8") for p in transcript)
    assert "9161112233" not in body and "111-22-33" not in body
    assert "3184713454" in body and "1500.00" in body  # product knowledge stays
    report = verify(out, store, policy, tmp_path / "verify_report.json")
    assert report.ok, report.leaks


def test_the_scanner_costs_the_same_with_many_known_numbers():
    """Dates and timestamps are digit runs too: the known-number check must
    not walk every profile number for each of them."""
    lines = [f"[2026-01-09 07:48] #{i} CLIENT U12345 заказ {1000000 + i} 2026-01-09T07:48:00Z"
             for i in range(2000)]

    def pass_over(count):
        scanner = LeakScanner(Known(phones=frozenset(f"7999{i:07d}" for i in range(count))),
                              regex_rules=False)
        for line in lines:
            assert not scanner.scan(line), line
        return lambda: [scanner.scan(line) for line in lines]

    assert_cost_ratio(pass_over(0), pass_over(5000), 4, label="known numbers")


def test_the_known_number_check_is_the_substring_test_it_replaced():
    """The length index must decide exactly what a scan of every known
    number against every digit run decided: a number anywhere inside a run,
    padded or not, and never a number cut short."""
    phones = ("79161112233", "380501112233", "77011234567")
    forms = {p for p in phones} | {p[-10:] for p in phones}
    scanner = LeakScanner(Known(phones=frozenset(phones)), regex_rules=False)
    rng = random.Random(7)
    seps = (" ", "-", ".", "(", ")", "", "\u2013", "\t")
    for _ in range(4000):
        pick = rng.choice(sorted(forms))
        core = rng.choice((pick, pick[:rng.randrange(3, 11)],
                           pick + "".join(rng.choice("0123456789") for _ in range(rng.randrange(1, 4))),
                           "".join(rng.choice("0123456789") for _ in range(rng.randrange(7, 18)))))
        head = "".join(rng.choice("0123456789") for _ in range(rng.randrange(0, 4)))
        text = head + "".join(c + (rng.choice(seps) if rng.random() < 0.4 else "") for c in core)
        digits = "".join(c for c in text if c.isdigit())
        assert ("phone" in kinds(scanner, text)) == any(f in digits for f in forms), text


def test_the_known_number_check_still_sees_cut_and_padded_numbers():
    scanner = LeakScanner(Known(phones=frozenset({"79161112233", "380501112233"})))
    for text in ("0079161112233", "9161112233", "tx 79161112233000", "380 50 111 22 33",
                 "8 916 111-22-33", "+7 916 111 22 33"):
        assert "phone" in kinds(scanner, text), text
    for text in ("916111223", "2026-01-09T07:48:00Z", "заказ 1234567890", "<phone>", "12345"):
        assert "phone" not in kinds(scanner, text), text
