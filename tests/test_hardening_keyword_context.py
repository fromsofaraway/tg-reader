"""Keyword rules that must not eat Russian product knowledge: short keywords
are whole words ("пинг" is no PIN, "другая" no birthday), deadlines and
durations after "срок" are no card expiry, error codes and order numbers
after a CVV, PIN or expiry label stay, reference codes after "код" (response,
MCC, terminal, explained decline codes) stay, and outcome words after a
password label are prose. Real values right after a keyword are still
replaced. Every scrubbed case is also flagged by the leak scanner on the raw
text and passes it on the output; every kept case stays byte-identical and
the scanner is silent on it."""


import pytest

from conftest import assert_fast, check
from tg_collector import fintech
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


def kept(scrub, scanner, text):
    check(scrub, scanner, text, text)


# --- short keywords are whole words ------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "кодировка 1251", "пинг 1500 мс", "пинги по 2000 мс", "пинок 1234", "ping 1500 ms", "pinned 12345",
    "pinterest 1234", "ping вернул E1234", "пинг до сервера 45 ms, ошибка E1234",
    "другая дата 12.03.2026", "другой вариант 12.03.2026", "Другую дату 01.02.2026 поставьте",
    "перенесли на другую дату 15.03.2026", "с другой карты 12.03.2026 прошёл платёж", "друг 01.01.1990",
    "дробь 01.01.1990", "дробление 01.02.2026", "драйвер от 12.03.2026",
    "сроки 10.03", "export 12.03.2026 failed", "expected 10.03", "explorer 12/27 tab", "expo 12/27",
    "cscart 123", "вуз 77 АА 123456", "вуаль 123456", "zipped 12345",
    "индексация 123456", "индексация 12345 рублей", "индексы 123456",
    "CODE_4001", "code_id: 4001", "pass_through: enabled", "PASS_THROUGH=enabled",
])
def test_prefix_of_a_longer_word_is_no_keyword(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected,kind", [
    # PIN: Russian case forms, glued digits, a glued word of the other script.
    ("ввод пинкода 1234", "ввод пинкода <pin>", "pin"),
    ("пинкодом 1234 не подходит", "пинкодом <pin> не подходит", "pin"),
    ("пинкоду 1234", "пинкоду <pin>", "pin"), ("пинкоды 1234", "пинкоды <pin>", "pin"),
    ("по пинкодам 1234", "по пинкодам <pin>", "pin"), ("пина 1234", "пина <pin>", "pin"),
    ("пинкод 1234", "пинкод <pin>", "pin"), ("ПИН: 1234", "ПИН: <pin>", "pin"),
    ("пин от карты 1234", "пин от карты <pin>", "pin"), ("pinкод 1234", "pinкод <pin>", "pin"),
    ("PIN1234", "PIN<pin>", "pin"), ("pin_code 1234", "pin_code <pin>", "pin"),
    ("pincode 1234", "pincode <pin>", "pin"), ("pins 1234", "pins <pin>", "pin"),
    ("pin от карты 1234", "pin от карты <pin>", "pin"), ("pin:\n1234", "pin:\n<pin>", "pin"),
    # Expiry: English forms, the singular Russian case forms, a label on its own line.
    ("expired 12/27", "expired <exp>", "expiry"), ("expire 12/27", "expire <exp>", "expiry"),
    ("expiring 12/27", "expiring <exp>", "expiry"), ("expdate 12/27", "expdate <exp>", "expiry"),
    ("ExpDate: 12/27", "ExpDate: <exp>", "expiry"), ("exp_date: 12/27", "exp_date: <exp>", "expiry"),
    ("Exp date\n12/27", "Exp date\n<exp>", "expiry"), ("Exp.12/27", "Exp.<exp>", "expiry"),
    ("exp12/27", "exp<exp>", "expiry"), ("сроком 12/27", "сроком <exp>", "expiry"),
    ("срока действия карты 12/27", "срока действия карты <exp>", "expiry"),
    ("срок действия карты 12/27", "срок действия карты <exp>", "expiry"),
    # CVV: glued forms stay keywords; a CVV-shaped number never takes an IP octet.
    ("cvvшка 123", "cvvшка <cvv>", "cvv"), ("cvvкод 123", "cvvкод <cvv>", "cvv"), ("cvv123", "cvv<cvv>", "cvv"),
    ("cid 123", "cid <cvv>", "cvv"), ("cvc-код 123", "cvc-код <cvv>", "cvv"), ("cvv карты 123", "cvv карты <cvv>", "cvv"),
    ("whitelist cidr 203.0.113.0/24 please", "whitelist cidr <ip>/24 please", "ipv4"),
    ("cvv 203.0.113.44", "cvv <ip>", "ipv4"),
    # Date of birth, driver licence, postcode.
    ("др 01.01.1990", "др <dob>", "dob"), ("ДР: 01.01.1990", "ДР: <dob>", "dob"), ("Др. 01.01.1990", "Др. <dob>", "dob"),
    ("др01.01.1990", "др<dob>", "dob"), ("д.р. 01.01.1990", "д.р. <dob>", "dob"),
    ("дата ДРа: 01.01.1990", "дата ДРа: <dob>", "dob"),
    ("ВУ 77 АА 123456", "ВУ <driver-licence>", "driver_licence"),
    ("правами 77 АА 123456", "правами <driver-licence>", "driver_licence"),
    ("индексом 123456", "индексом <postcode>", "postcode"), ("индекса: 123456", "индекса: <postcode>", "postcode"),
    ("почтового индекса 123456", "почтового индекса <postcode>", "postcode"),
    ("zipcode 12345", "zipcode <postcode>", "postcode"), ("ZIP: 12345", "ZIP: <postcode>", "postcode"),
    # Keywords that were left as they are keep their glued and inflected forms.
    ("3dsecure 123456", "3dsecure <otp>", "otp"), ("otpкод 482913", "otpкод <otp>", "otp"),
    ("3dsкод 482913", "3dsкод <otp>", "otp"), ("пасскода 482913", "пасскода <otp>", "otp"),
    ("2faкод JBSWY3DPEHPK3PXP", "2faкод <2fa-secret>", "2fa_secret"),
    ("инста: buyer_99", "инста: @user", None), ("тел.89991234567", "тел.<phone>", "phone"),
    ("from:Ivan Petrov", "from:<name>", "person"),
    ("карта 4242 4212 3456 7891, с кодом 123", "карта 424242**********, с кодом <cvv>", "card"),
])
def test_keyword_forms_that_still_fire(scrub, scanner, text, expected, kind):
    check(scrub, scanner, text, expected, kind)


# --- deadlines, durations and dates after "срок" are no expiry ---------------------------------

@pytest.mark.parametrize("text", [
    "срок до 12.03.2026", "срок до 12.03.2026, после этого сертификат перестанет работать",
    "в срок до 01.04.2026", "в срок до 01.12.2026", "срок оплаты 05.03.2026", "срок оплаты 10.02",
    "срок выплаты 11.03", "срок зачисления 01.02", "срок до 12.03", "срок до 12.03 включительно", "срок до 12.10",
    "срок с 12.03 по 15.03", "срок 01.03-15.03", "сроки 12.03-15.03", "сроки до 12.03.2026", "срок 12.03.26",
    "срок 12-03-2026", "срок 12. 03. 2026", "срок 12.03.2026", "срок действия до 12.03.2026",
    "срок 10-14 дней", "срок 10-12 дней", "сроки 10-14 дней для возврата на карту, так у всех банков",
    "срок возврата 10-12 рабочих дней", "срок 10-14 раб. дней", "срок 10-15 дн.", "срок 12-15 минут",
    "срок зачисления 10-15 минут", "срок 01-03 месяца", "срок ответа 12 24 часа", "срок 12 2026 года",
    "срок 12.2026 года", "срок 2 дня", "на срок 12 месяцев", "срок 12 месяцев на хранение чеков",
    "Срок действия ссылки на оплату — 72 часа", "exp 12.03.2026", "expiry 12/03/2026", "expensive 12/26",
    "experiment 10/24", "token expired", "статус TOKEN_EXPIRED",
])
def test_deadlines_and_durations_are_kept(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected", [
    ("срок 12/27", "срок <exp>"), ("срок 03.26", "срок <exp>"), ("срок: 12 27", "срок: <exp>"),
    ("срок 12-27", "срок <exp>"), ("срок действия 1227", "срок действия <exp>"),
    ("срока действия 12/27", "срока действия <exp>"), ("Срок действия карты: 12/27", "Срок действия карты: <exp>"),
    ("срок действия карты до 05.27", "срок действия карты до <exp>"), ("срок 12/27-123", "срок <exp>-123"),
    ("срок 12/27 годна", "срок <exp> годна"), ("срок 12/27 годен?", "срок <exp> годен?"),
    ("срок 12/27 работает?", "срок <exp> работает?"), ("срок 12/27 недействителен", "срок <exp> недействителен"),
    ("срок 12.27 недействителен", "срок <exp> недействителен"), ("срок 12/27 года", "срок <exp> года"),
    ("exp 03/26", "exp <exp>"), ("exp 1227", "exp <exp>"), ("exp. 12.27", "exp. <exp>"),
    ("exp.date 12/27", "exp.date <exp>"), ("expiry date 12/27", "expiry date <exp>"),
    ("expires 12/2027", "expires <exp>"), ("exp 12/2027 не принимает", "exp <exp> не принимает"),
    ("exp 03.2027", "exp <exp>"), ("exp 12/27 days", "exp <exp> days"), ("valid thru 1227", "valid thru <exp>"),
    ("годна до 12/27", "годна до <exp>"), ("годна до 12.27", "годна до <exp>"),
    ("действует до 12/27", "действует до <exp>"), ("дата истечения 03/27", "дата истечения <exp>"),
])
def test_card_expiries_are_still_replaced(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "expiry")


@pytest.mark.parametrize("text,expected", [
    ("карта 4242 4212 3456 7891, срок до 12.03.2026", "карта 424242**********, срок до 12.03.2026"),
    ("карта 4242 4212 3456 7891, срок 12/27, код 123", "карта 424242**********, срок <exp>, код <cvv>"),
    ("карта 4242 4212 3456 7891, срок действия карты 12/27, код 123",
     "карта 424242**********, срок действия карты <exp>, код <cvv>"),
    ("карта 4242 4212 3456 7891 срок действия карты 12/27", "карта 424242********** срок действия карты <exp>"),
    ("4242421234567891|03/2026|4567", "424242**********|<exp>|<cvv>"),
    ("4242421234567891|12/27|123", "424242**********|<exp>|<cvv>"),
    ("карта 6011 1111 1111 1117, срок 12.27, cvv 123", "карта 601111**********, срок <exp>, cvv <cvv>"),
])
def test_expiry_next_to_a_card(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "card")


# --- an error code or an order number after a card-companion label -----------------------------

@pytest.mark.parametrize("text", [
    "cvv mismatch, error 4001", "cvc ошибка 4001", "код безопасности неверен, ошибка 4001", "cvv error: 4001",
    "cvv error #4001", "cvv отказ 4001", "cvv status 4001", "cvv не совпал, ошибка 4001", "CVV неверный, ошибка 4001",
    "cvv не подошел, отказ 4001", "cvv, ошибка код 4001", "CVV: ошибка 4001", "CVC2 отказ 4001", "cvv — статус 4001",
    "cvv не совпал, код ошибки 4001", "cvv mismatch, decline 05", "cvv верный, заказ 4821 не прошёл",
    "cvv правильный, сумма 1500", "cvv ok, лимит 5000", "cvv ок, id 12345",
    "пин ошибка 4001", "пин ошибка E1234", "pin error 4001", "pin error 1234", "pin code error 1234", "pin status 1234",
    "exp error 1225", "срок ошибка 1225", "срок статус 1227",
])
def test_error_code_after_a_companion_label_is_kept(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected", [
    ("cvv 123, error 4001", "cvv <cvv>, error 4001"), ("cvv 123 ошибка", "cvv <cvv> ошибка"),
    ("ошибка: cvv 123 не принимается", "ошибка: cvv <cvv> не принимается"), ("Ошибка: cvv 123", "Ошибка: cvv <cvv>"),
    # A rejected span never hides a later value.
    ("cvv ошибка. cvv 123", "cvv ошибка. cvv <cvv>"), ("cvv ошибка 4001, cvv 123", "cvv ошибка 4001, cvv <cvv>"),
    ("CVV ERROR, CVV123", "CVV ERROR, CVV<cvv>"), ("pin wrong. pin 1234", "pin wrong. pin <pin>"),
    # A user's mistake, a preposition before a number label, words that only contain a label.
    ("CVV ошиблась, верный 456", "CVV ошиблась, верный <cvv>"),
    ("cvv ошибся, правильный 456", "cvv ошибся, правильный <cvv>"),
    ("cvv с ошибкой, верный 456", "cvv с ошибкой, верный <cvv>"),
    ("cvv для оплаты заказа 123", "cvv для оплаты заказа <cvv>"), ("cvv к счёту 123", "cvv к счёту <cvv>"),
    ("cvv карты для расчета 123", "cvv карты для расчета <cvv>"),
    ("cvv карты заказчика 123", "cvv карты заказчика <cvv>"),
    ("cvv карты заказчика: 123", "cvv карты заказчика: <cvv>"),
    ("cvv насчет 123", "cvv насчет <cvv>"), ("пин насчет 1234", "пин насчет <pin>"),
    ("cvv для карты Acme 123", "cvv для карты Acme <cvv>"), ("cvv карты Петрова 123", "cvv карты Петрова <cvv>"),
    ("CVV от карты: 123", "CVV от карты: <cvv>"), ("CVC2 код 456", "CVC2 код <cvv>"),
    ("три цифры сзади 456", "три цифры сзади <cvv>"), ("cvv\n123", "cvv\n<cvv>"),
    ("код с обратной стороны 789, срок 03/26", "код с обратной стороны <cvv>, срок <exp>"),
    # An error word before the keyword proves nothing.
    ("Ошибка! Пин 1234 не подходит", "Ошибка! Пин <pin> не подходит"), ("ошибка: pin 1234", "ошибка: pin <pin>"),
    ("пин 1234 это мой?", "пин <pin> это мой?"),
    ("cvv для карты 4242 4212 3456 7891: 123", "cvv для карты 424242**********: <cvv>"),
])
def test_companion_values_are_still_replaced(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- reference codes after "код" ---------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "код 4001 означает недостаточно средств", "код 4001 означает недостаточно средств на карте, это не наша ошибка",
    "code 4001 means insufficient funds", "code 4001 stands for do not honor", "код 4001 = insufficient funds",
    "Код 4001 = недостаточно средств", "У нас код 5003 = таймаут процессинга", "код 4001 — это недостаточно средств",
    "код 4001 - это отказ", "Код 6001 это отказ банка-эквайера", "Код 4001: означает отказ банка",
    "коды 4001 и 4002 означают отказ", "код 4001, 4002 и 4003 означают отказ",
    "коды 4001, 4002 и 4003 означают отказ", "код 10051 означает лимит",
    "код 05 — значит отказ эмитента", "код 51 — это недостаточно средств",
    "код ответа 4001", "Код ответа: 4001", "код ответа от банка 4001", "код ответа - 4001", "коды ответов 4001",
    "код категории 5411", "У мерчанта код категории 5411, поэтому кэшбэк не начисляется",
    "код терминала 12345678", "код магазина 12345", "код мерчанта 12345", "код города 8452", "код валюты 0643",
    "код страны 0643", "код результата 4001", "код возврата 4001", "ответный код 4001", "промо код 12345",
    "промокод 12345", "транзакция отклонена с кодом 4001", "отказ по коду 4001", "платёж отклонён по коду 5051",
    "ошибка с кодом 4001", "отклонено с кодом 4001",
    '{"status": "failed", "code": 4001}', 'Webhook payload:\n{\n  "type": "payment.failed",\n  "code": 4001\n}',
    "result code 4001", "merchant code 12345", "promo code 12345", "coupon code 12345", "category code 5411",
    "terminal code 12345678", "currency code 0840", "area code 8452",
])
def test_reference_codes_are_kept(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected", [
    ("код 482913", "код <otp>"), ("код 1234", "код <otp>"), ("пришёл код 482913", "пришёл код <otp>"),
    ("код подтверждения 482913", "код подтверждения <otp>"), ("код из смс 482913", "код из смс <otp>"),
    # A qualified one-time code is never explained away.
    ("код подтверждения 4829 означает что оплата прошла?", "код подтверждения <otp> означает что оплата прошла?"),
    ("код подтверждения 1234 — не подходит", "код подтверждения <otp> — не подходит"),
    ("смс-код 4471 — неверный", "смс-код <otp> — неверный"), ("3ds код 123456", "3ds код <otp>"),
    ("ввожу 3DS код 88123 — ошибка", "ввожу 3DS код <otp> — ошибка"),
    ("verification code 123456", "verification code <otp>"),
    # Fillers around an arriving code, and six-digit codes, stay one-time codes.
    ("код 482913 не подходит, значит надо новый", "код <otp> не подходит, значит надо новый"),
    ("код 482913 — не подходит", "код <otp> — не подходит"), ("код 482913 (из смс)", "код <otp> (из смс)"),
    ("код 482913 это правильный?", "код <otp> это правильный?"), ("смс код 482913 это тот?", "смс код <otp> это тот?"),
    ("код 482913 значит неверный?", "код <otp> значит неверный?"), ("код 482913 = неверный?", "код <otp> = неверный?"),
    ("код 482913 значит не подходит", "код <otp> значит не подходит"),
    ("код 482913 означает что?", "код <otp> означает что?"),
    ("мне пришел код 482913 это нормально?", "мне пришел код <otp> это нормально?"),
    ("Пришел код 4829 это он?", "Пришел код <otp> это он?"), ("Код 4829 — это тот?", "Код <otp> — это тот?"),
    ("код 4829 значит неверный?", "код <otp> значит неверный?"), ("код 4829 = неверный?", "код <otp> = неверный?"),
    ("код 123456 — вот он", "код <otp> — вот он"),
    # Kind words that are not right after "код", and a new clause, reach the one-time code.
    ("код странно не приходит 482913", "код странно не приходит <otp>"),
    ("код для клиента 482913", "код для клиента <otp>"), ("код от магазина 482913", "код от магазина <otp>"),
    ("сменили код магазина? код 482913 не проходит", "сменили код магазина? код <otp> не проходит"),
    ("Код ответа не пришел, код 482913", "Код ответа не пришел, код <otp>"),
    ("merchant code: n/a, code 482913", "merchant code: n/a, code <otp>"),
    ("Я ошиблась с кодом, правильный 482913", "Я ошиблась с кодом, правильный <otp>"),
    ("У меня ошибка с кодом, вот он 482913", "У меня ошибка с кодом, вот он <otp>"),
    ("отклонили, код 482913", "отклонили, код <otp>"), ("тикет #48213, код 482913", "тикет #48213, код <otp>"),
    ('{"code": "482913"}', '{"code": "<otp>"}'), ("Кодов: 1234", "Кодов: <otp>"), ("codes 1234 5678", "codes <otp> 5678"),
])
def test_one_time_codes_are_still_replaced(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "otp")


@pytest.mark.parametrize("text,expected", [
    # The explanation check is OTP-only: backup codes and a CVV next to a card keep their gate.
    ("коды восстановления 12345678 87654321 это все", "коды восстановления <otp> это все"),
    ("коды восстановления 12345678 означают что?", "коды восстановления <otp> означают что?"),
    ("карта 4242 4212 3456 7891, код 123 это правильный?", "карта 424242**********, код <cvv> это правильный?"),
    ("карта 4242 4212 3456 7891 код 123 это cvv", "карта 424242********** код <cvv> это cvv"),
    ("карта 4242 4212 3456 7891, код 123 означает что?", "карта 424242**********, код <cvv> означает что?"),
    # The kind words are OTP-only too: a password label keeps them.
    ("пароль от ответственного: Qwerty123", "пароль от ответственного: <password>"),
    ("пароль от магазина: Qwerty123", "пароль от магазина: <password>"),
])
def test_other_rules_keep_their_gates(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- outcome words after a password label ------------------------------------------------------

@pytest.mark.parametrize("text", [
    "пароль: неверный", "Пароль: неправильный", "пароль:\nнеправильный", "Пароль Неверный",
    "Пароль Неверный — так пишет форма входа", "пароль: неверен", "пароль: неверна", "пароль: неверный пароль",
    "пароль от кабинета: неверный", "пароль: сброшен", "Пароль: Сброшен", "пароль: сброшен!", "пароль: сбросил",
    "пароль: истёк", "пароль: истек", "Пароль Устарел", "Пароль Заблокирован", "Пароль Сменил", "пароль = старый",
    "пароль: подходит?", "пароль: верный", "пароль: забыла", "пароль: временный", "пароль: любой", "пароль: пустой",
    "пароль: нужен", "пароль: работает", 'пароль: "неверный"', "пароль: новый пароль", "пароль: новый, придёт в смс",
    "пароль: истёк 12.03.2026", "пароль: сброшен 12.03", "пароль: неверный, ошибка 4001",
    "пароль неверный, сбросьте", "пароль от кабинета: не подходит", "пароль: 3ds-check",
    "password: incorrect", "password: expired", "password: reset", "password: same as before", "Password: INVALID",
    "Password: Valid", "did not pass 3ds-check", "didn't pass 3ds-check", "to pass 3dsecure",
    "totp misconfiguration", "2fa reauthentication",
    # An error code after a password label that is itself prose.
    "пароль не подходит: ошибка 4001", "пароль неверный: ошибка 4001", "Пароль не подходит: Ошибка 4001",
    "пароль не принимается: код ошибки 4001",
])
def test_password_prose_is_kept(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected", [
    ("пароль: qwerty", "пароль: <password>"), ("пароль: йцукен", "пароль: <password>"),
    ("пароль: hunter", "пароль: <password>"),
    # A digit makes an outcome word a password again.
    ("пароль: Верный1", "пароль: <password>"), ("пароль: верный1", "пароль: <password>"),
    ("пароль: неверный1", "пароль: <password>"), ("пароль: неверный123", "пароль: <password>"),
    ("пароль: истек12", "пароль: <password>"), ("пароль: истек1", "пароль: <password>"),
    ("пароль: забыл12", "пароль: <password>"), ("пароль: Новый2024", "пароль: <password>"),
    ("password: wrong1", "password: <password>"), ("password: Incorrect1!", "password: <password>!"),
    ("пароль: Sunshine", "пароль: <password>"), ("password: sameold", "password: <password>"),
    ("password: 3dsecure1", "password: <password>"),
    ("pass: hunter2", "pass: <password>"), ("логин admin pass hunter2", "логин admin pass <password>"),
    ("pass от акка Qwerty123", "pass от акка <password>"), ("to pass Qwerty123", "to pass <password>"),
    ("will pass: hunter2", "will pass: <password>"), ("not pass: Hunter22", "not pass: <password>"),
    ("логин: ivan, не pass: Qwerty1", "логин: @user, не pass: <password>"),
    ("пароль: неверный. Новый пароль: Qwerty123", "пароль: неверный. Новый пароль: <password>"),
    ("пароль: Qwerty123!", "пароль: <password>!"), ("пароль Qwerty123", "пароль <password>"),
    ("Пароль:\nQwerty123", "Пароль:\n<password>"),
    ("пароль Северов2026 (с большой буквы)", "пароль <password> (с большой буквы)"),
    ("мой пароль «ЗимаЛето!42», поменяю потом", "мой пароль «<password>», поменяю потом"),
    ("passphrase: correct-horse-2024", "passphrase: <password>"),
    # A state word before the value belongs to the label.
    ("пароль: новый Qwerty123", "пароль: новый <password>"), ("пароль новый Qwerty123", "пароль новый <password>"),
    ("пароль: временный Abc12345", "пароль: временный <password>"),
    ("пароль: неверный Qwerty123", "пароль: неверный <password>"),
    ("пароль: старый Qwerty123, новый пароль: Qwerty456", "пароль: старый <password>, новый пароль: <password>"),
    ("password: new Hunter22", "password: new <password>"),
    ("пароль временный: Abc12345", "пароль временный: <password>"),
])
def test_passwords_are_still_replaced(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "password")


@pytest.mark.parametrize("text,expected", [
    ("2fa: JBSWY3DPEHPK3PXP", "2fa: <2fa-secret>"),
    ("ключ 2fa: jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp", "ключ 2fa: <2fa-secret>"),
])
def test_two_factor_secrets_are_still_replaced(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "2fa_secret")


# --- placeholders and speed --------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "срок <exp>", "срок действия карты <exp>", "cvv <cvv>, error 4001", "пин ошибка <pin>", "код <otp> означает",
    "код ответа <otp>", "пароль: новый <password>", "пароль: <password>", "др <dob>", "индекса: <postcode>",
    '{"code": "<otp>"}', "cvv ошибка. cvv <cvv>",
])
def test_placeholders_are_never_flagged(scanner, text):
    assert scanner.scan(text) == []


@pytest.mark.parametrize("unit", [
    "срок ", "срок 12 ", "срок 12.", "12-", "exp.date ", "cvv ошибка ", "cvv, заказ ", "   12", "коды 4001 и ",
    "код 4001, ", '"code": ', "код ответа ", "отказ по ", "пароль: новый ", "пароль: новый Qwerty1 ", "пинкод",
    "др ", "индекс ", ", ", "E", "это отказ ", "= ",
])
def test_keyword_context_stays_fast(scrub, scanner, unit):
    for tail in ("", "4001", "12/27"):
        text = (unit * 4096)[:4096 - len(tail)] + tail

        def pass_over(text=text):
            out = scrub(text)
            scanner.scan(text)
            scanner.scan(out)

        assert_fast(pass_over, label=(unit, tail))


def test_explanation_check_is_bounded():
    text = ("код 1234" + "   12" * 11 + " x\n") * 20
    assert_fast(lambda: Scrubber(AnonPolicy(), Roster()).scrub(text), label="explanation scrub")
    for unit in (" ", "   12", " и 12", ", 12", "это "):
        assert_fast(lambda unit=unit: fintech._EXPLAINED.match((unit * 4096)[:4096]), label=unit)
