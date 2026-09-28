"""Addresses, cardholders and document series: KYC prose after an address
keyword, card products after a holder word, short prose words before a
number after a document keyword and "пер." as a transfer stay; real
addresses, cardholder names and document numbers are still removed, and
the scanner agrees with the scrubber in both directions."""

import pytest

from conftest import assert_fast, check
from tg_collector.config import AnonPolicy
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS, keep_terms=("Northwind",)), Roster(keep_terms=("Northwind",))).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS), keep_terms=frozenset({"Northwind"})))


# --- the value after a strong address keyword --------------------------------------------

KYC_PROSE = [
    "прописка не нужна",
    "Прописка не требуется для верификации",
    "прописку можно не указывать",
    "прописка не нужна, достаточно паспорта",
    "прописка не нужна, достаточно паспорта РК с 2020 года",
    "прописка в другом городе, это проблема?",
    "прописка в Алматы, а живу в Астане",
    "прописка нужна для лимита 500",
    "прописка не нужна, ошибка E1042 v2.3.1",
    "прописка обязательна с 01.10.2026",
    "адрес регистрации должен совпадать с адресом в паспорте",
    "адрес регистрации и адрес проживания отличаются, ошибка KYC_07",
    "адрес регистрации совпадает, 3 попытки",
    "адрес регистрации совпадает с адресом прописки, 3 попытки",
    "адрес регистрации не совпадает, код 05",
    "Адрес регистрации: не заполнен",
    "Адрес проживания отличается от адреса прописки — это нормально?",
    "Для верификации нужен адрес проживания, как в документе",
    "адрес доставки можно изменить в настройках",
    "адрес доставки можно изменить в течение 24 часов",
    "адрес доставки уточните",
    "адрес доставки: подтвердите до 15:00",
    "адрес доставки не указан, заказ 1234567",
    "Адрес доставки и адрес плательщика могут отличаться, это не фрод",
    "billing address не совпадает с адресом карты",
    "billing address must match the card ending 4242",
    "billing address fails with code 51",
    "Billing address mismatch (AVS) — decline code N7",
    "shipping address is required for physical cards",
    "адрес: используйте любой адрес США",
]


@pytest.mark.parametrize("text", KYC_PROSE)
def test_kyc_prose_after_an_address_keyword_stays(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("прописка: г. Алматы, ул. Абая 10, кв. 5", "прописка: <address>"),
    ("прописка Алматы, Абая 10, кв 5", "прописка <address>"),
    ("прописка алматы абая 10", "прописка <address>"),
    ("прописка алматы абая 10а кв5", "прописка <address>"),
    ("прописка алматы абая д10", "прописка <address>"),
    ("прописка алматы, самал-2 д33", "прописка <address>"),
    ("прописка москва тверская 12с1", "прописка <address>"),
    ("прописка алматы абая 10 второй этаж", "прописка <address>"),
    ("прописка алматы наурызбай батыра 17 а", "прописка <address>"),
    ("прописка: алматы наурызбай батыра 17 второй этаж", "прописка: <address>"),
    ("прописка: алматы абая 150 уг ленина", "прописка: <address>"),
    ("прописка нижний новгород ул горького 10", "прописка <address>"),
    ("прописка: с. Каскелен, ул. Абылай хана", "прописка: <address>"),
    ("адрес проживания село Каскелен", "адрес проживания <address>"),
    ("адрес проживания: город Шымкент, микрорайон Нурсат", "адрес проживания: <address>"),
    ("адрес регистрации москва ленина 5 кв 3", "адрес регистрации <address>"),
    ("адрес регистрации ненашева 5", "адрес регистрации <address>"),
    ("Адрес регистрации не совпадает: г. Алматы, Абая 10", "Адрес регистрации <address>"),
    ("адрес доставки: 050000, Алматы, Абая 10", "адрес доставки: <address>"),
    ("адрес доставки: а/я 15, Алматы", "адрес доставки: <address>"),
    ("адрес доставки: нужно на абая 10а кв5", "адрес доставки: <address>"),
    ("адрес доставки: абая 10 кв 5, почта ivan@example.com", "адрес доставки: <address>"),
    ("проживаю по адресу москва тверская 7 во дворе", "проживаю по адресу <address>"),
    ("проживаю по адресу Абая 150/1, кв 20", "проживаю по адресу <address>"),
    ("прописка: алматы абая, тел 87011234567", "прописка: <address>"),
    ("Прописка:\nАлматы, Абая 10, кв 5", "Прописка:\n<address>"),
    ("прописка:\nг. Алматы, ул. Абая 10", "прописка:\n<address>"),
    ("billing address is 42 Acme Road, Springfield", "billing address <address>"),
    ("shipping address: Musterstraße 12, 10115 Berlin", "shipping address: <address>"),
    ("shipping address: via roma 10 milano", "shipping address: <address>"),
    # A second, labelled address after a sentence is still reached, and the
    # text between two addresses stays.
    ("прописка не нужна, адрес регистрации: абая 10а кв5", "прописка не нужна, адрес регистрации: <address>"),
    ("прописка не нужна, адрес доставки: алматы абая 150 угол ленина",
     "прописка не нужна, адрес доставки: <address>"),
    ("прописка не нужна, адрес: алматы абая 150 угол ленина", "прописка не нужна, адрес: <address>"),
    ("прописка: Алматы, Абая 10, адрес доставки: Астана, Кенесары 40",
     "прописка: <address>, адрес доставки: <address>"),
    # The bare "адрес:" rule keeps its digit-and-letter gate.
    ("адрес: алматы абая 10 2 этаж", "адрес: <address>"),
    ("адрес: москва тверская 7 во дворе", "адрес: <address>"),
    ("адрес: москва тверская 12к2", "адрес: <address>"),
    ("адрес: пер. ленина 5", "адрес: <address>"),
])
def test_real_addresses_after_a_keyword_are_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    # An e-mail or handle next to an address does not hide the address,
    # and the scanner, which sees "<email>", agrees.
    ("адрес: Абая 10 кв 5, почта ivan@example.com", "адрес: <address>"),
    ("email адрес: anna@example.com", "email адрес: <email>"),
    ("адрес: ivan1@example.com", "адрес: <email>"),
    ("адрес: @oleg_support", "адрес: @user"),
    ("адрес: 203.0.113.7", "адрес: <ip>"),
    ("прописка не нужна, пишите @oleg_support", "прописка не нужна, пишите @user"),
    ("прописка: алматы абая, карта 4242424242424242", "прописка: алматы абая, карта 424242**********"),
])
def test_address_gate_ignores_replaced_text(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_address_gate_agrees_with_the_scanner_on_placeholders():
    roster = Roster(by_username={"oleg_support": "U04217"})
    scanner = LeakScanner(Known(usernames=frozenset({"oleg_support"}), card_bins=frozenset(BINS)))
    out = Scrubber(AnonPolicy(), roster).scrub("прописка не нужна, пишите @oleg_support")
    assert out == "прописка не нужна, пишите @U04217"
    assert scanner.scan(out) == []
    domain = Scrubber(AnonPolicy(url_mode="domain"), Roster())
    out = domain.scrub("прописка в другом городе, см. https://kyc1.example.com/rules/2024")
    assert out == "прописка в другом городе, см. <url:kyc1.example.com>"
    assert LeakScanner(Known(), url_allowed=lambda url: False).scan(out) == []
    # Whatever the verdict, the scanner reads the scrubbed text the same way.
    scrub = Scrubber(AnonPolicy(card_bins=BINS), roster).scrub
    for text in ("прописка не нужна, ivan1@example.com 10", "прописка не нужна, пишите @oleg_support 5",
                 "прописка не нужна, @oleg_support, 5", "адрес доставки: см. https://kyc1.example.com/a/2024",
                 "адрес доставки не указан, звоните +7 701 123 45 67", "адрес: 4242424242424242, код 05",
                 "прописка не нужна, карта 4242 4242 4242 4242 ок", "адрес регистрации @oleg_support не совпадает, 12",
                 "прописка: алматы абая 10, anna@example.com", "адрес: +7 701 123 45 67, Абая"):
        out = scrub(text)
        assert scanner.scan(out) == [], (text, out)


# --- street rules --------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "пер. 1500 руб", "Пер. 5000", "пер.1500 на карту", "сделал пер. 2000 руб", "пер. на карту 1500",
    "пер. на 3 карты", "пер. с карты 12", "пер. по номеру 1500", "Пер. на 2000 руб прошел?",
    "пер. от 12.03 на сумму 5000", "Пер. средств 1500 руб", "пер. клиенту 500", "пер. через сбп 1000",
    "пер. отклонен 05", "пер. в тинькофф 3000", "пер. между счетами 100", "пер. не проходит 3 раза",
    "пер. 1500 руб, а пришло 1485 — комиссия 1%", "пер. 1-2 дня",
    "и пр. лимит 100", "карты, кошельки и пр. 5 штук",
    "2 cards by the way", "3 items on the way, eta 2 days", "5 minutes to get there dr", "10 users hit the rate limit st",
    "1 item in the cart pl", "4 attempts on this ct", "100 usd on the way", "sent 5 items to Dr", "2 out of 3 st",
    "1 the way", "2 cards either way", "5 files on google drive", "3 cases in court", "error 403 in the place",
    "3 refunds on the way to the client",
])
def test_transfers_and_english_phrases_are_no_street(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("пер. Столярный, 3", "<address>"), ("пер. Ленина 5", "<address>"), ("Пер.Столярный 3", "<address>"),
    ("пер. ленина 5", "<address>"), ("пер. южный 5", "<address>"), ("пер. маросейка 5", "<address>"),
    ("пер. 1-й колобовский 5", "<address>"), ("пер. 8 Марта 5", "<address>"), ("пер. Денежный 5", "<address>"),
    ("г. Москва, пер. Столярный д. 3 кв. 5", "<address>"), ("г. москва, пер. кривоколенный, 5, кв 3", "<address>"),
    ("москва, пер. кривоколенный 5 кв 3", "москва, <address>"), ("Пер. Садовый, д. 12, кв. 3", "<address>"),
    ("отправьте на пер. сивцев вражек 4", "отправьте на <address>"), ("переулок Сивцев Вражек 4", "<address>"),
    ("наб. реки Мойки 12", "<address>"), ("ул. ленина 5", "<address>"), ("ул. 8 Марта 12", "<address>"),
    ("123 Main St", "<address>"), ("5 Old Kent Road", "<address>"), ("lives at 1 Broad Way", "lives at <address>"),
    ("12 North Main St.", "<address>"), ("3 5th Ave", "<address>"), ("10 St. John's Rd", "<address>"),
    ("123 MAIN ST", "<address>"), ("5 The Drive", "<address>"), ("1 Hacker Way", "<address>"),
    ("42 Oak Drive, Apt 5", "<address>"), ("100 Church St., Apt 4", "<address>"),
    ("123 main st", "<address>"), ("10 downing st", "<address>"), ("123 main st apt 4", "<address>"),
    ("i live at 42 elm street", "i live at <address>"), ("42 wallaby way, sydney", "<address>, sydney"),
    ("ship to 1600 pennsylvania ave nw", "ship to <address>"),
    ("ship to 1600 Pennsylvania Ave NW, Washington", "ship to <address>, Washington"),
    ("billing address: 123 main st", "billing address: <address>"), ("адрес: 10 downing st", "адрес: <address>"),
])
def test_real_streets_are_still_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "пер. 1 @U04217", "пер. на к @U0421 Anna", "ул. 1 @U04217", "ул. Абая @U04217", "наб. 5 @C02222 ок",
    "<address> @U04217 12",
])
def test_street_number_never_starts_inside_a_virtual_id(text):
    assert LeakScanner(Known()).scan(text) == []


def test_street_before_a_mention_scrubs_like_the_scanner_reads_it():
    roster = Roster(by_username={"oleg_support": "U04217"})
    out = Scrubber(AnonPolicy(), roster).scrub("ул. 1 @oleg_support")
    assert out == "ул. 1 @U04217"
    assert LeakScanner(Known(usernames=frozenset({"oleg_support"}))).scan(out) == []


# --- document series -----------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "права на 1234567", "права для 1234567", "права доступа 123456", "правами 123456", "паспортами 1234567",
    "права админа, id 1234567", "права админа, ID 1234567", "права в БМ 1234567", "ву от 1234567",
    "паспорт отклонён, заявка id 1234567", "паспорт по 1234567", "паспорт tx 12345678", "серия ошибок с 1234567",
    "паспорт подтвердили, лимит до 1000000 руб", "права админа есть, спенд до 1000000",
    "паспорт загрузил, с 1234567 проблем нет", "паспорт отклонен, заявка № 1234567", "серия карт 4242, ошибка 05",
])
def test_short_prose_words_are_no_document_series(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("паспорт AB 1234567", "паспорт <passport>"), ("паспорт Мр 1234567", "паспорт <passport>"),
    ("паспорт МК 123456", "паспорт <passport>"), ("паспорт мк 123456", "паспорт <passport>"),
    ("паспорт: mp 1234567", "паспорт: <passport>"), ("паспорт n 12345678", "паспорт <passport>"),
    ("паспорт: кн 123456", "паспорт: <passport>"), ("серия мк 123456", "серия <passport>"),
    ("серия и номер: аа 1234567", "серия и номер: <passport>"),
    ("паспорт ab1234567", "паспорт <passport>"), ("паспорт n12345678", "паспорт <passport>"),
    ("passport fe123456", "passport <passport>"), ("паспорт:AB1234567", "паспорт:<passport>"),
    ("паспорт_AB1234567", "паспорт_<passport>"), ("паспорт N1234567", "паспорт <passport>"),
    ("паспорт ID1234567", "паспорт <passport>"), ("паспорт ID 1234567", "паспорт <passport>"),
    ("удостоверение ID0123456", "удостоверение <passport>"), ("passport no 1234567", "passport <passport>"),
    ("паспорт ок, no 1234567", "паспорт ок, <passport>"),
    ("паспорт отклонён, заявка ID 1234567", "паспорт отклонён, заявка <passport>"),
    ("паспорт id 012345678", "паспорт id <passport>"), ("паспорт: 1234567890", "паспорт: <passport>"),
    ("паспорт в заявке N12345678", "паспорт в заявке <passport>"), ("серия 4509123456", "серия <passport>"),
    ("паспорт/ID-карта 012345678", "паспорт/ID-карта <passport>"),
    ("паспорт серия АН номер 123456", "паспорт серия <passport>"),
    ("паспорт серия АН № 123456", "паспорт серия <passport>"),
    ("паспорт Северов Олег Иванович AB1234567", "паспорт <name> <passport>"),
    ("права АБ 1234567", "права <driver-licence>"), ("права АВ\n1234567", "права <driver-licence>"),
    ("права: ав 1234567", "права: <driver-licence>"), ("права 77 АВ 123456", "права <driver-licence>"),
    ("в/у ав 123456", "в/у <driver-licence>"), ("в/у abc 1234567", "в/у <driver-licence>"),
    ("в/у abc1234567", "в/у <driver-licence>"), ("в/у ABC 1234567", "в/у <driver-licence>"),
    ("в/у 7712 345678", "в/у <driver-licence>"),
])
def test_document_numbers_are_still_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- cardholder -------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "для держателей Visa Gold доступен кэшбэк", "для держателей Visa Gold лимит выше", "держатели Visa Platinum",
    "держатели VISA GOLD", "владельцы карт Visa Infinite получают", "держатели Mastercard World Elite",
    "Держателям Mastercard World Elite доступен бизнес-зал", "владельцам карт Мир Премиальная начисляется кешбэк",
    "holder Premium Plan", "cardholder: Visa Gold", "имя на карте Visa Gold", "держатели Apple Pay",
    "держатели Northwind Pro", "Cardholder Name Mismatch", "Invalid Cardholder Name Format",
    "держатель карты Kaspi Gold", "держатели карт Kaspi Gold могут", "держатели карт Kaspi Gold получают кэшбэк",
    "для держателей Kaspi Gold", "держатели Kaspi Gold", "держатели Tinkoff Black", "держатель карты Тинькофф Блэк",
    "держатель карты Халык Банка не может", "держатели карт Acme Credit", "держатель карты Kaspi Red",
    "держатель Золотой Карты", "для держателей Золотой карты", "cardholder: Visa Card", "держатель карты не отвечает",
    "ФИО: Неверно", "на имя ООО", "вписал на имя Другого человека",
])
def test_card_products_after_a_holder_word_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("держатель карты Олег Северов", "держатель карты <cardholder>"),
    ("Держатель карты Олег Северов", "Держатель карты <cardholder>"),
    ("держатель карты: Олег Северов", "держатель карты: <cardholder>"),
    ("держатель карты - OLEG SEVEROV", "держатель карты - <cardholder>"),
    ("держатель карты IVAN SIDOROV", "держатель карты <cardholder>"),
    ("держателя карты Северова Олега", "держателя карты <cardholder>"),
    ("держателя карты Сидорова Анна", "держателя карты <cardholder>"),
    ("держатель карты И. Сидоров", "держатель карты <cardholder>"),
    ("держатель карты Ким Анна", "держатель карты <cardholder>"),
    ("держатель карточки: Олег Северов", "держатель карточки: <cardholder>"),
    ("держатель карты Visa, Олег Северов", "держатель карты Visa, <cardholder>"),
    ("держатель карты Visa Gold Олег Северов", "держатель карты Visa Gold <cardholder>"),
    ("держатель карты Kaspi Gold Олег Северов", "держатель карты Kaspi Gold <cardholder>"),
    ("держатель карты Альфа Банка Олег Северов", "держатель карты Альфа Банка <cardholder>"),
    ("владелец карты Mastercard World Elite Олег Северов", "владелец карты Mastercard World Elite <cardholder>"),
    ("держатель карты Мир Асланов", "держатель карты <cardholder>"),
    ("держатель карты Иван Банков", "держатель карты <cardholder>"),
    ("держатель карты Майя Золотых", "держатель карты <cardholder>"),
    ("держатель Золотой Карты Олег Северов", "держатель Золотой Карты <cardholder>"),
    ("держатель Visa Card Олег Северов", "держатель Visa Card <cardholder>"),
    ("holder card Anna Doe", "holder card <cardholder>"),
    ("cardholder: Иван Картошкин", "cardholder: <cardholder>"),
    ("cardholder: MIR ASLAM", "cardholder: <cardholder>"), ("имя на карте MIR ASLAM", "имя на карте <cardholder>"),
    ("cardholder: Gold David", "cardholder: <cardholder>"), ("cardholder: Мир Асланов", "cardholder: <cardholder>"),
    ("holder: Maestro Ivan", "holder: <cardholder>"), ("cardholder: IVAN GOLD", "cardholder: <cardholder>"),
    ("cardholder: Мира Иванова", "cardholder: <cardholder>"), ("cardholder Name Anna Doe", "cardholder Name <cardholder>"),
    ("на имя Мира Иванова", "на имя <cardholder>"), ("на имя ИП Северов", "на имя <cardholder>"),
    ("на имя Олега Северова не проходит", "на имя <cardholder> не проходит"),
    ("на имя ООО Ромашка", "на имя <cardholder>"),
    ("имя на карте IVAN PETROV, а в фб Ivan", "имя на карте <cardholder>, а в фб Ivan"),
])
def test_cardholder_names_are_still_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_new_rules_stay_fast_on_hostile_input(scrub):
    scanner = LeakScanner(Known())
    units = ["прописка ", "прописка не ", "адрес доставки: ", "пер. ", "пер. 1", "пер. на ", "ул. 1 @U0421",
             "12 the a b c d ", "держатель карты ", "держатели Visa Gold ", "карты Visa ", "паспорт мк ", "права на ",
             "серия АН номер ", "и ", "абая 10 ", "кв5 ", "прописка: абая 10, адрес доставки: ", "проживаю по адресу ",
             "_ ", "a@b.co ", "<url> "]
    for unit in units:
        text = (unit * (4096 // len(unit) + 1))[:4096]
        assert_fast(lambda: (scrub(text), scanner.scan(text)), label=unit)
