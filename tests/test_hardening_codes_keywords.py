"""Codes and keyword spellings in Russian support chats: decline codes with
their reason, glossaries of codes, code kinds ("код товара", "МСС"), the
spellings clients really type for one-time codes, documents, expiry dates and
wallets, counting prose after an address keyword, plural card holders, and
grouped activation keys. Every scrubbed case is also flagged by the leak
scanner on the raw text and passes it on the output; every kept case stays
byte-identical and the scanner is silent on it."""


import pytest

from conftest import assert_fast, check
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


# --- decline codes explained on their own line stay ------------------------------------------

@pytest.mark.parametrize("text", [
    "Код 4003 — карта заблокирована эмитентом",
    "**Код 5003** — Insufficient funds",
    "- код 4001: недостаточно средств",
    "| код 4001 | недостаточно средств |",
    "1. код 3001 — карта заблокирована\n2. код 1001 — неверный CVV",
    "Код 4002 — превышен лимит по карте",
    "Код 4002 — превышена сумма операции",
    "Код 1005\nтаймаут банка",
    "падает с кодом 5003",
    "Код 4010 — отказ эмитента",
    "код 4011 - истёк срок действия карты",
])
def test_decline_codes_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    # A label ends with ':' right after the keyword, so the number is its value.
    ("Код: 4821 — недостаточно средств", "Код: <otp> — недостаточно средств"),
    # Six digits are an SMS code, not a decline code.
    ("Код 482913 — карта заблокирована", "Код <otp> — карта заблокирована"),
    # "лимит попыток" counts attempts, it is no decline reason.
    ("Код 4821 - превышен лимит попыток", "Код <otp> - превышен лимит попыток"),
    ("код 482913, никому не сообщайте", "код <otp>, никому не сообщайте"),
    ("ваш код 4829", "ваш код <otp>"),
])
def test_one_time_codes_are_still_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- glossaries: the keyword of one entry does not take the next entry's code ------------------

@pytest.mark.parametrize("text", [
    "Коды ошибок:\n4001 — неверный CVV\n4002 — неверный PIN\n4003 — неверный пароль\n4004 — истёк токен",
    "- 4001 — неверный CVV\n- 4002 — неверный PIN",
    "- 4001 — неверный CVV\n- 4002 — таймаут",
    "| 1001 | Неверный CVV |\n| 1002 | Неверный PIN |",
    "4005 — неверный код\n4006 — таймаут",
])
def test_code_glossaries_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    # Different code shapes on the two lines: this is no list.
    ("01 — пин\n4821 — такой", "01 — пин\n<pin> — такой"),
    ("1234 пароль\nQwerty123 — вот", "1234 пароль\n<password> — вот"),
    ("4001 — введите CVV\n123 — вот он", "4001 — введите CVV\n<cvv> — вот он"),
    ("4001 — ввёл CVV\n456 — неверный", "4001 — ввёл CVV\n<cvv> — неверный"),
])
def test_values_after_a_line_break_are_still_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- code kinds and the Cyrillic "МСС" ---------------------------------------------------------

@pytest.mark.parametrize("text", [
    "МСС код 5411", "код МСС 5411", "МСС-код 5999", "MCC код 5411",
    "код товара 4001", "код купона 4001", "Код тарифа: 4001", "код услуги 4001",
    "Код ТСП: 12345", "код филиала — 4001", "код кассы 4001", "код акции 4001",
])
def test_code_kinds_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("Ваш код для акции 4821", "Ваш код для акции <otp>"),
    ("Код операции 4821. Никому не сообщайте", "Код операции <otp>. Никому не сообщайте"),
    ("МСС 5411 код 4821", "МСС 5411 код <otp>"),
])
def test_bank_codes_after_a_kind_word_are_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- spellings clients really type -------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("пароль из смс 552211", "пароль из смс <otp>"),
    ("пин из смс 482913", "пин из смс <otp>"),
    ("кодик 482913", "кодик <otp>"),
    ('{"sms_code": "4829"}', '{"sms_code": "<otp>"}'),
    ("confirm_code=482913", "confirm_code=<otp>"),
    ("verification_code: 482913", "verification_code: <otp>"),
    ("цвв 123", "цвв <cvv>"),
    ("дата окончания 12/27", "дата окончания <exp>"),
    ("срок карты 12/27", "срок карты <exp>"),
    ("валидна до 12/27", "валидна до <exp>"),
    ("день рождения 12.03.1990", "день рождения <dob>"),
    ("дата рожд. 12.03.1990", "дата рожд. <dob>"),
    ("д/р 12.03.1990", "д/р <dob>"),
    ("уд.л. 045123456", "уд.л. <passport>"),
    ("уд. личности AB1234567", "уд. личности <passport>"),
    ("вод. уд. 77 АВ 123456", "вод. уд. <driver-licence>"),
    ("по адресу Тверская, 12, кв. 34", "по адресу <address>"),
    ("мой адрес Сатпаева 90/1, кв. 8", "мой адрес <address>"),
    ("кошелёкUQBvW8Z5huBkMJYdnfAEM5JqTNkuWX3diqYENkWsIL0XggGG",
     "кошелёк<wallet>"),
])
def test_russian_keyword_spellings(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "день рождения компании отмечаем",
    '{"code": 4001, "message": "declined"}',
    "кодировка 1251",
])
def test_lookalike_prose_stays(scrub, scanner, text):
    check(scrub, scanner, text, text)


# --- counting prose after an address keyword ---------------------------------------------------

@pytest.mark.parametrize("text", [
    "адрес регистрации: 2 страница паспорта",
    "прописка: страница 5-12 паспорта",
    "адрес доставки: 1-3 дня",
    "адрес: до 255 символов",
    "billing address: step 2 of 4",
    "адрес доставки: в течение 3 дней",
])
def test_counting_prose_after_an_address_keyword_stays(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("адрес доставки: 1-2 дня Абая 10 до обеда", "адрес доставки: <address>"),
    ("адрес доставки: 3 дня, ул. Абая 10", "адрес доставки: <address>"),
    ("адрес доставки: Самал 2, 3 дня", "адрес доставки: <address>"),
    ("прописка: г. Алматы, ул. Абая 10, кв. 5", "прописка: <address>"),
])
def test_real_addresses_next_to_a_count_are_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- plural card holders -----------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "держатели карт Райффайзен Премиум",
    "держатели карт МТС Cashback",
    "держатели карт Совкомбанк Халва",
    "для держателей Visa Gold доступен кэшбэк",
])
def test_card_products_after_a_plural_holder_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("ДЕРЖАТЕЛИ КАРТ IVAN SIDOROV", "ДЕРЖАТЕЛИ КАРТ <cardholder>"),
    ("владельцы карт Анна Мороз", "владельцы карт <cardholder>"),
    ("держатели карт Ivan Petrov", "держатели карт <cardholder>"),
    ("держатели карт Visa Gold Олег Северов", "держатели карт Visa Gold <cardholder>"),
    ("держатели карт Иванов И.И.", "держатели карт <cardholder>"),
    ("держатель карты Иван Сидоров", "держатель карты <cardholder>"),
])
def test_people_after_a_holder_word_are_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- grouped activation keys -------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("ключ активации VK7JG-NPHTM-C97JM-9MPGT-3V66T", "ключ активации <token>"),
    ("лицензия: VK7JG-NPHTM-C97JM-9MPGT-3V66T", "лицензия: <token>"),
    ("Лицензионный ключ: VK7JG-NPHTM-C97JM-9MPGT-3V66T", "Лицензионный ключ: <token>"),
    ("license key ACME-1234-ABCD-5678-EFGH", "license key <token>"),
    ("серийный номер ACME-1234-ABCD-5678", "серийный номер <token>"),
])
def test_licence_keys_are_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "activation failed: ACT-4001-DECLINED-CARD",
    "лицензия ERROR-CODE-TIMEOUT-RETRY",
    "лицензия ЦБ 1234",
    "VK7JG-NPHTM-C97JM-9MPGT-3V66T",
])
def test_grouped_runs_without_a_licence_keyword_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


# --- speed ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("unit", ["код 4001 — ", "- код 4001 ", "| код 4001 | ", "код ", "МСС код 5411 ",
                                  "**код 4001** — превышен лимит ", "адрес доставки: 1-3 дня ",
                                  "держатели карт Visa ", "лицензия ACME-1234-ABCD-5678 "])
def test_code_rules_stay_fast(scrub, scanner, unit):
    text = (unit * 4096)[:4096]

    def pass_over():
        out = scrub(text)
        scanner.scan(text)
        scanner.scan(out)

    assert_fast(pass_over, label=unit)
