"""The fintech domain rules: bank details, names by keyword, addresses,
spaced ids, dates of birth, seed phrases, secrets in every common shape,
messenger and exchange ids, CVV spellings, cookies."""

import pytest

from conftest import (
    AWS_ACCESS_KEY, DISCORD_TOKEN, GITLAB_PAT, GOOGLE_API_KEY, OPENAI_KEY, SHOPIFY_TOKEN,
    STRIPE_LIVE, STRIPE_WEBHOOK, TWILIO_KEY, assert_fast, check,
)
from tg_collector.bip39 import WORDS
from tg_collector.config import AnonPolicy
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS, keep_terms=("Northwind",)), Roster(person_terms=("Петров",), keep_terms=("Northwind",))).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS), keep_terms=frozenset({"Northwind"})))


@pytest.mark.parametrize("text,expected", [
    ("Routing number 084009519, Account number 8310012345", "Routing number <bank-code>, Account number <account>"),
    ("Wise: account 8310123456 routing 084009519 (ACH)", "Wise: account <account> routing <bank-code> (ACH)"),
    ("Sort code 04-00-04, Account 12345678", "Sort code <bank-code>, Account <account>"),
    ("sort code 040004 account number 12345678", "sort code <bank-code> account number <account>"),
    ("BSB 062-000 Account 12345678", "BSB <bank-code> Account <account>"),
    ("р/с 40702810900000012345", "р/с <account>"),
    ("ad account 1234567890123456", "ad account <ad-account>"),
    ("выставил счёт 1500 руб, счет №123456 оплачен", "выставил счёт 1500 руб, счет №123456 оплачен"),
    ("account 12345 suspended", "account 12345 suspended"),
    ("your account 2024-09-15 12:34", "your account 2024-09-15 12:34"),
    ("decline code 051 account number 0001", "decline code 051 account number 0001"),
    ("время 12:34:56, счёт 1500:3", "время 12:34:56, счёт 1500:3"),
])
def test_bank_details(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("С уважением,\nСергей Иванов\nДиректор ООО Василёк", "С уважением,\n<name>\nДиректор ООО Василёк"),
    ("наш бухгалтер Сергей Иванов подтвердит", "наш бухгалтер <name> подтвердит"),
    ("меня зовут Иван Сидоров", "меня зовут <name>"), ("my name is John Smith", "my name is <name>"),
    ("контактное лицо: Сидоров Пётр Алексеевич, тел +79991234567", "контактное лицо: <name>, тел <phone>"),
    ("ИП Иванов А.А.", "ИП <name>"), ("From: Ivan Sidorov <ivan@x.io>", "From: <name> <<email>>"),
    ("Иванов А.А. подписал", "<name> подписал"), ("А.А. Иванов", "<name>"),
    ("ФИО: Иванов И.И.", "ФИО: <cardholder>"), ("на имя Петрова А. С., карта *1234", "на имя <cardholder>, карта *1234"),
    ("имя на карте IVANOV I.", "имя на карте <cardholder>"), ("ФИО: И.И. Иванов", "ФИО: <cardholder>"),
    ("меня зовут Иван", "меня зовут Иван"), ("Менеджер API Gateway вернул 500", "Менеджер API Gateway вернул 500"),
    ("владелец Apple Pay", "владелец Apple Pay"), ("Менеджер Личный Кабинет не открывается", "Менеджер Личный Кабинет не открывается"),
    ("руководитель Отдела Продаж", "руководитель Отдела Продаж"), ("ИП Ромашка", "ИП Ромашка"), ("ип на УСН", "ип на УСН"),
    ("директор по продажам", "директор по продажам"), ("т.е. Клиент", "т.е. Клиент"),
    ("error E1042 v2.3.1 ticket #4711 сумма 1 000 руб", "error E1042 v2.3.1 ticket #4711 сумма 1 000 руб"),
    ("Best regards, Northwind Support", "Best regards, Northwind Support"),
    ("ФИО: Неверно", "ФИО: Неверно"), ("вписал на имя Другого человека", "вписал на имя Другого человека"), ("на имя ООО", "на имя ООО"),
])
def test_people_named_next_to_a_keyword(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("адрес: г. Алматы, пр. Абая 10, кв 5", "адрес: <address>"), ("адрес - г. Астана, ул. Кенесары 40, кв 7", "адрес - <address>"),
    ("ул. Абая 10 кв 5", "<address>"), ("адрес: 1.2.3.4", "адрес: <ip>"), ("адрес: acme.ru", "адрес: <domain>"),
    ("email адрес: a@b.com", "email адрес: <email>"), ("индекс 123456", "индекс <postcode>"),
    ("прописка: г. Алматы, ул. Абая 10, кв. 5", "прописка: <address>"),
    ("и пр. лимит 100", "и пр. лимит 100"), ("карты, кошельки и пр. 5 штук", "карты, кошельки и пр. 5 штук"),
    ("GEO Казахстан, Россия 5 карт", "GEO Казахстан, Россия 5 карт"), ("Здравствуйте, Виза 2 карты", "Здравствуйте, Виза 2 карты"),
    ("адрес не совпадает с картой", "адрес не совпадает с картой"), ("адрес: используйте любой адрес США", "адрес: используйте любой адрес США"),
    ("индекс потребительских цен 105.2", "индекс потребительских цен 105.2"),
])
def test_addresses(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("ИИН 020531 600149; ИИН: 020531-600149; ИНН 500 100 732 259; СНИЛС 11223344595", "ИИН <tax-id>; ИИН: <tax-id>; ИНН <tax-id>; СНИЛС <snils>"),
    ("СНИЛС 112 233 445 95", "СНИЛС <snils>"), ("ИНН 7707 083893", "ИНН <tax-id>"), ("ИИН 02 05 31 60 01 49", "ИИН <tax-id>"),
    ("ИНН 7700000425 12.03.2026 выписка", "ИНН <tax-id> 12.03.2026 выписка"), ("ИНН 7700000425 2 карты", "ИНН <tax-id> 2 карты"),
    ("ИНН 7700000425, КПП 770701001", "ИНН <tax-id>, КПП 770701001"), ("ошибка ИНН 05", "ошибка ИНН 05"), ("ИНН 1234567", "ИНН 1234567"),
    ("Иванов 01.01.1990 г.р., паспорт 45 09 №123456", "Иванов <dob> г.р., паспорт <passport>"),
    ("родилась 12 мая 1990; born 12 May 1990; 1990-05-12 г. р.", "родилась <dob>; born <dob>; <dob> г. р."),
    ("01.01.1990 года рождения", "<dob> года рождения"),
    ("серия 4509 номер 123456, паспорт: серия 4509, № 123456", "серия <passport>, паспорт: серия <passport>"),
    ("паспорт AB1234567, passport FE123456, паспорт МК123456, загран 75 1234567", "паспорт <passport>, passport <passport>, паспорт <passport>, загран <passport>"),
    ("паспорт РФ 4509123456", "паспорт РФ <passport>"), ("в/у ABC 1234567", "в/у <driver-licence>"),
    ("выписка за 01.01.2026 г. Разберёмся", "выписка за 01.01.2026 г. Разберёмся"), ("оплата 12.03.2026 г. р/с не указан", "оплата 12.03.2026 г. р/с не указан"),
    ("12 мая 2026 оплатил", "12 мая 2026 оплатил"), ("заказ 12.05.2026 г.", "заказ 12.05.2026 г."), ("с 2026 года работаем", "с 2026 года работаем"),
    ("серия карт 4242, ошибка 05", "серия карт 4242, ошибка 05"),
])
def test_identity_documents_and_dates(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_seed_phrases(scrub, scanner):
    twelve = " ".join(WORDS[:12])
    check(scrub, scanner, "seed phrase: " + twelve, "seed phrase: <seed-phrase>")
    check(scrub, scanner, "сид фраза: " + " ".join(WORDS[:24]), "сид фраза: <seed-phrase>")
    check(scrub, scanner, " ".join(f"{i + 1}. {w}" for i, w in enumerate(WORDS[:12])), "<seed-phrase>")
    check(scrub, scanner, "\n".join(f"{i + 1}) {w}" for i, w in enumerate(WORDS[:12])), "<seed-phrase>")
    check(scrub, scanner, ", ".join(WORDS[:12]), "<seed-phrase>")
    check(scrub, scanner, twelve.upper(), "<seed-phrase>")
    check(scrub, scanner, "wallet seed: " + " ".join(WORDS[100:112]), "wallet seed: <seed-phrase>")
    for text in [" ".join(WORDS[:11]), "card declined again error code 05 what can we do now please help",
                 "life world space fun live click one cloud digital agency team money"]:
        assert scrub(text) == text


@pytest.mark.parametrize("text,expected", [
    (f"DB_PASSWORD=S3cr3tP@ss\nSTRIPE_SECRET_KEY={STRIPE_LIVE}\nMY_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf",
     "DB_PASSWORD=<token>\nSTRIPE_SECRET_KEY=<token>\nMY_TOKEN=<token>"),
    (f"export OPENAI_API_KEY={OPENAI_KEY}", "export OPENAI_API_KEY=<token>"),
    ('поставь DB_PASSWORD="Qwerty12" в .env', 'поставь DB_PASSWORD="<token>" в .env'),
    ("MERCHANT_API_KEY: a1b2c3d4e5f6g7h8i9j0", "MERCHANT_API_KEY: <token>"), ("ID=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf", "ID=<token>"),
    (AWS_ACCESS_KEY, "<token>"), (STRIPE_LIVE, "<token>"), (STRIPE_WEBHOOK, "<token>"),
    (GOOGLE_API_KEY, "<token>"), (TWILIO_KEY, "<token>"),
    (SHOPIFY_TOKEN, "<token>"), (GITLAB_PAT, "<token>"),
    (DISCORD_TOKEN, "<token>"),
    (f"API-ключ: {STRIPE_LIVE}", "API-ключ: <token>"), (f"секретный ключ: {GOOGLE_API_KEY}", "секретный ключ: <token>"),
    ("MAX_PASSWORD_LENGTH=64", "MAX_PASSWORD_LENGTH=64"), ("REFRESH_TOKEN_TTL=3600", "REFRESH_TOKEN_TTL=3600"), ("ERROR_CODE=4001", "ERROR_CODE=4001"),
    ("TICKET_KEY=SUP-1234", "TICKET_KEY=SUP-1234"), ("APP_VERSION=1.2.3", "APP_VERSION=1.2.3"), ("ERROR_TOKEN=INVALID", "ERROR_TOKEN=INVALID"),
    ("статус TOKEN_EXPIRED", "статус TOKEN_EXPIRED"), ("bypass: test1234", "bypass: test1234"), ("SKU-2024", "SKU-2024"), ("Skoda", "Skoda"),
    ("GUID 550e8400-e29b-41d4-a716-446655440000", "GUID 550e8400-e29b-41d4-a716-446655440000"),
    ("order_id ord_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c", "order_id ord_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"),
])
def test_secrets_in_common_shapes(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("пароль от личного кабинета: Qwerty123", "пароль от личного кабинета: <password>"),
    ("пароль от аккаунта фб: Qwerty123", "пароль от аккаунта фб: <password>"),
    ("пароль для входа в ЛК: Qwerty123", "пароль для входа в ЛК: <password>"),
    ("password for the ad account: Qwerty123", "password for the ad account: <password>"),
    ("пароль от почты mail.ru: Abc12345", "пароль от почты <domain>: <password>"),
    ("пароль Петрова: Qwerty123", "пароль <name>: <password>"), ("пароль от Петрова Qwerty123", "пароль от <name> <password>"),
    ("пароль неверный, ошибка: 4012", "пароль неверный, ошибка: 4012"), ("пароль не принят, статус: 401", "пароль не принят, статус: 401"),
    ("пароль от лк сбросил версия 2.3.1", "пароль от лк сбросил версия 2.3.1"),
    ("пароль от кабинета не подходит, ошибка 4012", "пароль от кабинета не подходит, ошибка 4012"),
    ("password incorrect: try again", "password incorrect: try again"), ("пароль от кабинета: не подходит", "пароль от кабинета: не подходит"),
    ("Passcode: 482913", "Passcode: <otp>"), ("passcode 482913", "passcode <otp>"), ("passphrase: correct-horse-2024", "passphrase: <password>"),
    ("passcode error 0042", "passcode error 0042"), ("codes 1234 5678", "codes <otp> 5678"), ("Кодов: 1234", "Кодов: <otp>"),
    ("passport: 4515123456", "passport: <passport>"), ("код ошибки 1234", "код ошибки 1234"), ("surpass 12345", "surpass 12345"),
    ("кодировка 1234 не та", "кодировка 1234 не та"), ("код 482913", "код <otp>"), ("Кода: 482913", "Кода: <otp>"),
    ("backup codes: 12345678 23456789 34567890 45678901 56789012", "backup codes: <otp>"),
    ("recovery codes: abcd-1234 efgh-5678 ijkl-9012", "recovery codes: <otp>"),
    ("резервные коды:\n1234 5678\n2345 6789\n3456 7890", "резервные коды:\n<otp>"),
    ("резервные коды не подошли, ошибка 4001", "резервные коды не подошли, ошибка 4001"), ("error codes 4001 4002", "error codes 4001 4002"),
    ("backup codes expired, заказ 12345678", "backup codes expired, заказ 12345678"),
    ("ключ 2fa: jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp", "ключ 2fa: <2fa-secret>"), ("2FA secret: JBSW Y3DP EHPK 3PXP", "2FA secret: <2fa-secret>"),
    ("2FA secret: JBSW-Y3DP-EHPK-3PXP", "2FA secret: <2fa-secret>"), ("Ключ для приложения: JBSWY3DPEHPK3PXPJBSWY3DP", "Ключ для приложения: <2fa-secret>"),
    ("ключ от аутентификатора google: JBSWY3DPEHPK3PXP", "ключ от аутентификатора google: <2fa-secret>"),
    ("2FA secret: JBSW Y3DP EHPK 3PXP done", "2FA secret: <2fa-secret> done"),
    ("2fa code sent last time", "2fa code sent last time"), ("seed data more than some", "seed data more than some"),
    ("ключ: сумма 2345 USDT 3456 USDT", "ключ: сумма 2345 USDT 3456 USDT"), ("ключ 2fa тикет TCKT-2345-6723-4567", "ключ 2fa тикет TCKT-2345-6723-4567"),
    ("ключ для приложения: ошибка 4012 повторите", "ключ для приложения: ошибка 4012 повторите"), ("ключ версии v2.3.4 сборка 2345", "ключ версии v2.3.4 сборка 2345"),
])
def test_passwords_codes_and_totp_secrets(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("мой id 555666777", "мой id <id>"), ("telegram id 555666777", "telegram id <id>"), ("юзер айди 555666777", "юзер айди <id>"),
    ("chat_id=-1001234567890", "chat_id=-<id>"), ("чат id -1001234567890", "чат id -<id>"), ("icq 555666777", "icq <id>"),
    ("добавьте коллегу, его id 555666777", "добавьте коллегу, его id <id>"),
    ("ID заказа 123456", "ID заказа 123456"), ("order id 5556667", "order id 5556667"), ("merchant id 1234567", "merchant id 1234567"),
    ("id мерчанта 123456789", "id мерчанта 123456789"), ("ID 4837", "ID 4837"), ("id: 5556667778", "id: 5556667778"), ("user id 12", "user id 12"),
    ("Bybit ID 12345678", "Bybit ID <id>"), ("мой ID на бинансе 12345678", "мой ID на бинансе <id>"), ("KuCoin: 123456789", "KuCoin: <id>"),
    ("Binance Pay ID 123456789", "Binance Pay ID <id>"), ("акк на байбите 87654321", "акк на байбите <id>"),
    ("binance 2024", "binance 2024"), ("bybit 1000 usdt", "bybit 1000 usdt"), ("вывел с binance 15000 usdt", "вывел с binance 15000 usdt"),
    ("binance error 400 code 2", "binance error 400 code 2"), ("на бинансе комиссия 0.1%", "на бинансе комиссия 0.1%"),
    ("binance версия 2.15.3", "binance версия 2.15.3"), ("okx status 51000", "okx status 51000"),
    ("memo 1234567 и binance uid 98765432", "memo <id> и binance uid <id>"),
])
def test_messenger_and_exchange_ids(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("код на обороте 123", "код на обороте <cvv>"), ("код сзади карты 456, срок 03/26", "код сзади карты <cvv>, срок <exp>"),
    ("карта 4242 4212 3456 7891, срок 12/27, код 123", "карта 424242**********, срок <exp>, код <cvv>"),
    ("номер 6011 1111 1111 1117, код 123", "номер 601111**********, код <cvv>"),
    ("код 123", "код 123"), ("код 404", "код 404"), ("код страны 380", "код страны 380"),
    ("карта 4242 4212 3456 7891 код ошибки 4001", "карта 424242********** код ошибки 4001"),
    ("карта 4242 4212 3456 7891 decline код 05", "карта 424242********** decline код 05"),
])
def test_cvv_spellings(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_session_cookies_of_other_platforms(scrub, scanner):
    check(scrub, scanner,
          "HSID=A0uBQBsN4JBvAaEid; SSID=AbCdEfGhIjKlMnOpQ; APISID=AbCdEfGhIjKlMnOpQrStUvWxYz/AbCdEfGh01; PHPSESSID=q3n8f7d2k1l0m9p8o7i6u5y4t3; remember_token=AbCdEfGh1234567890",
          "HSID=<cookie>; SSID=<cookie>; APISID=<cookie>; PHPSESSID=<cookie>; remember_token=<cookie>")
    assert scrub("order_id=123456 лимит=1000 WD=1 sid=x") == "order_id=123456 лимит=1000 WD=1 sid=x"


def test_hostile_inputs_stay_fast(scrub):
    shapes = ["a-" * 2048, "x." * 2048, "A_" * 2048, "A=" * 2048, "PASS:" * 800, "1. word " * 500, "abandon " * 512,
              "xoxb-" + "b" * 4000, ("a" * 27 + ".") * 140, "код " * 1000, "пароль от " * 400]
    for text in shapes:
        assert_fast(lambda: scrub(text[:4096]), label=text[:40])
