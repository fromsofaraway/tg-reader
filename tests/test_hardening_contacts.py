"""Contact data in every spelling: phones, e-mails, handles, scheme-less
links, IBANs, expiry/CVV after a card, Telegram Desktop lines, patronymics."""

import pytest

from tg_collector.config import AnonPolicy
from tg_collector.model import Entity
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber


@pytest.fixture
def roster():
    return Roster(by_username={"ivan_petrov": "U0002", "ivan": "U0003", "alice": "U0044"}, by_user_id={5: "U0002"},
                  known_ids=(123456789,), person_terms=("Петров",), org_terms=("Ромашка",))


@pytest.fixture
def scrub(roster):
    return Scrubber(AnonPolicy(card_bins=("400000",)), roster).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset({"400000"}), usernames=frozenset({"ivan_petrov", "ivan"}),
                             phones=frozenset({"79991234567"})))


# --- phones ----------------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("мой номер 9991234567", "мой номер <phone>"), ("whatsapp 9991234567", "whatsapp <phone>"),
    ("тел.: 9991234567", "тел.: <phone>"), ("phone 2025550143", "phone <phone>"),
    ("my number is 2025550143", "my number is <phone>"), ("call me 12025550143", "call me <phone>"),
    ("тел: 9991234567, заказ 1234567890", "тел: <phone>, заказ 1234567890"), ("тел:\n1234567890", "тел:\n<phone>"),
    ("8 999 123 45 67:)", "<phone>:)"), ("+79991234567:", "<phone>:"), ("+79991234567-Иван", "<phone>-Иван"),
    ("*+79991234567*", "*<phone>*"), ("+79991234567@whatsapp", "<phone>@whatsapp"), ("+7 999 123-45-67:\nИван", "<phone>:\nИван"),
    ("тел.89991234567", "тел.<phone>"), ("моб.89991234567", "моб.<phone>"), ("тел-89991234567", "тел-<phone>"),
    ("тел89991234567", "тел<phone>"), ("тел.8 999 123 45 67", "тел.<phone>"), ("Телефон:+79991234567", "Телефон:<phone>"),
    ("8\u2011999\u2011123\u201145\u201167", "<phone>"), ("+7–999–123–45–67", "<phone>"),
    ("+7 999 123\u201145\u201167", "<phone>"), ("+7\u2009999\u2009123\u200945\u200967", "<phone>"),
    ("+33 6 12 34 56 78", "<phone>"), ("+32 2 123 45 67", "<phone>"), ("+49 30 12 34 56 78", "<phone>"),
    ("8 9 9 9 1 2 3 4 5 6 7", "<phone>"), ("8-9-9-9-1-2-3-4-5-6-7", "<phone>"), ("+7 99 91 23 45 67", "<phone>"),
    ("+7 999 123 45 67 1500 руб", "<phone> 1500 руб"), ("+33 7 12 34 56 78 1500 руб", "<phone> 1500 руб"),
])
def test_phones_in_every_spelling(scrub, scanner, text, expected):
    assert scrub(text) == expected
    assert "phone" in {l.kind for l in scanner.scan(text)}


@pytest.mark.parametrize("text", [
    "9991234567", "order number 1234567890", "номер заказа 1234567890", "ticket 1234567890", "телефон 1500",
    "phone model 1234567890", "с 10:00-18:00", "заказ 2024-123456-7", "12345678-1234-1234-1234-123456789012",
    "выписка за 01.01.2026-06.01.2026", "8 999 123 45 67-89", "ORD-89991234567", "ticket_89991234567",
    "телефон не работает 12345678901", "мобильное приложение 2.15.3 build 4711", "тикеты 12345–12350",
    "период 12.05.2024–15.05.2024", "2024–2025", "лимит 100 000–500 000 руб", "10 000-20 000",
    "1 500 000 2 300 000", "0 1 2 3 4 5 6 7 8 9", "1 2 3 4 5 6 7 8 9 10", "ставка 1.5 2.5 3.5 4.5 5.5", "+1 500 000 руб",
    "8 9 9 9-1-2 3 4 5 6 7", "8 1 2 3 4 5 6 7 8 9 0", "курс +1 12 34 56 78", "заказ 12345678901", "+1 000 000",
])
def test_numbers_that_are_not_phones(scrub, text):
    assert scrub(text) == text


def test_hand_masked_card_is_not_bitten_by_the_phone_rule(scrub):
    assert scrub("4242 4212 34** **** 7890") == "424242**************"


# --- e-mails ----------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "ivan.example @gmail.com", "ivan.example@ gmail.com", "ivan.example@gmail. com", "ivan.example@gmail .com",
    "ivan.example@gmail,com", "ivan.example@gmail", "ivan.example＠gmail.com", "ivan.example＠mail．ru", "ivan.example@mail\u200b.ru",
    "ivan_petrov@gmail. com", "ivan.example [at] mail [dot] ru", "ivan.example (at) mail (dot) ru", "ivan.example at gmail dot com",
    "ivan.example AT gmail DOT com", "ivan.example собака gmail точка com", "ivan.example(собака)mail.ru", "ivan.example[at]gmail.com",
    "ivan.example @ mail.ru", "ivan.example @mail.ru", "user1_99 {at} yandex {dot} ru",
])
def test_emails_with_typos_and_obfuscation(scrub, text):
    assert scrub(text) == "<email>"
    assert LeakScanner(Known()).scan(text) and not LeakScanner(Known()).scan("<email>")


def test_obfuscated_email_keeps_its_context(scrub):
    assert scrub("моя почта ivan.example @gmail.com проверьте") == "моя почта <email> проверьте"
    assert scrub("почта ivan.example [at] mail [dot] ru пишите") == "почта <email> пишите"


@pytest.mark.parametrize("text,expected", [
    ("спасибо @ivan_petrov. Ok", "спасибо @U0002. Ok"), ("v2.1 @ivan_petrov. It works", "v2.1 @U0002. It works"),
    ("цена 10.5 руб @ 12.30", "цена 10.5 руб @ 12.30"), ("заказ №123 @ 5 pro", "заказ №123 @ 5 pro"),
    ("1.5 @ 2.5 pro", "1.5 @ 2.5 pro"), ("оплата 5 @ list", "оплата 5 @ list"), ("👨\u200d👩\u200d👧 семья", "👨\u200d👩\u200d👧 семья"),
    ("we are at home. it works", "we are at home. it works"), ("код ошибки E1234 at api.pay.kz", "код ошибки E1234 at <domain>"),
    ("version 2.1 at build. ru", "version 2.1 at build. ru"), ("paid at store.app checkout", "paid at <domain> checkout"),
])
def test_prose_around_at_signs_survives(scrub, text, expected):
    assert scrub(text) == expected


# --- handles ----------------------------------------------------------------------------------

def test_handles_glued_to_words_and_after_keywords(scrub):
    assert scrub("пишите@ivan_petrov тг@ivan_petrov e@ivan_petrov @@ivan_petrov _@some_buyer_99_ example.com/@some_buyer_99") == \
        "пишите@U0002 тг@U0002 e@U0002 @@U0002 _@user <url>"
    assert scrub("написал @unknown_guyу, а @ivan_petrovом ответили") == "написал @user, а @U0002 ответили"
    assert scrub("у ivan_petrovа") == "у @U0002"
    assert scrub("@supportпишите") == "@userпишите"
    assert scrub("@ivan_petrov_2 ivan_petrov_2 scan_ivan_petrov.pdf") == "@user ivan_<name>_2 scan_@U0002.pdf"
    assert scrub("пиши @ some_buyer_99") == "пиши @user" and scrub("＠some_buyer_99") == "@user"
    assert scrub("@ ivan_petrov") == "@U0002"


@pytest.mark.parametrize("text,expected", [
    ("skype ivan.petrov", "skype @user"), ("discord: ivan#1234", "discord: @user"), ("инста: somebuyer", "инста: @user"),
    ("тг somebuyer_99", "тг @user"), ("логин somebuyer_99", "логин @user"), ("мой ник в тг ivan", "мой ник в тг @U0003"),
    ("мой ник ivan_petrov, а ivan это слово", "мой ник @U0002, а ivan это слово"),
    ("логин: ivan.example@mail.com:Passw0rd1", "логин: <credentials>"), ("тг @ivan_petrov", "тг @U0002"),
])
def test_keyword_introduced_handles(scrub, text, expected):
    assert scrub(text) == expected


@pytest.mark.parametrize("text", [
    "npm i lodash@latest", "ssh deploy@prod-01", "admin@localhost", "ERR_CODE@retry", "node_modules/@types/node",
    "decline 05 @ Stripe", "I'm @ work now", "v2.3 @ prod", "deployed @ Kubernetes", "@ 5pm",
    "fb pixel", "tiktok shop", "telegram desktop", "instagram reels", "login error 401", "username taken", "steam wallet",
    "facebook business manager", "тг premium", "логин admin", "ivan это слово",
])
def test_words_around_at_and_platform_names_survive(scrub, text):
    assert scrub(text) == text


@pytest.mark.parametrize("text,expected", [
    ("инст: ivan_petrov_99", "инст: @user"), ("инста: ivan_petrov_99", "инста: @user"),
    ("в инсте у меня ivan_petrov_99", "в инсте у меня @user"), ("инстой ivan_petrov_99", "инстой @user"),
    ("инстаграме ivan.petrov.1", "инстаграме @user"),
])
def test_instagram_still_introduces_a_handle(scrub, scanner, text, expected):
    assert scrub(text) == expected
    assert scanner.scan(expected) == []


@pytest.mark.parametrize("text", [
    "инструкция: setup_guide.pdf", "инструмент: Postman", "инструменты: curl_7.88, Postman",
    "инстанс prod_eu_1 упал", "инстанс: payments-api-2", "институт: mipt_2020",
    "инсталлятор: setup_v2.exe", "инсталляция: build_2024_01",
])
def test_everyday_inst_words_do_not_introduce_a_handle(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


def test_scanner_sees_the_same_handles(scanner):
    assert scanner.scan("тг@ivan_petrov") and scanner.scan("@@ivan_petrov") and scanner.scan("@ivan_petrovу")
    assert scanner.scan("ivan_petrov92у".replace("92", "")) and scanner.scan("тг somebuyer_99")
    assert scanner.scan("@U0002 и @user") == [] and scanner.scan("decline 05 @ Stripe") == []


# --- links and IBAN ----------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "instagram.com/some_buyer_99", "tiktok.com/@some_buyer_99", "facebook.com/profile.php?id=100012345678901",
    "vk.com/id987654321", "linkedin.com/in/some-buyer-12345", "instagram.com/some_buyer_99?igsh=abc", "revolut.me/ivanp",
])
def test_schemeless_links_are_links(scrub, text):
    assert scrub(text) == "<url>"
    assert "url" in {l.kind for l in LeakScanner(Known()).scan(text)}


def test_schemeless_links_follow_the_url_policy(roster):
    assert Scrubber(AnonPolicy(url_mode="domain"), roster).scrub("paypal.me/ivanpetrov") == "<url:paypal.me>"
    assert Scrubber(AnonPolicy(allow_domains=("docs.acme.com",)), roster).scrub("docs.acme.com/api/v2 и acme.ru/x") == \
        "docs.acme.com/api/v2 и <url>"
    assert Scrubber(AnonPolicy(scrub_domains=False), roster).scrub("instagram.com/some_buyer_99") == "<url>"


def test_versions_and_paths_are_not_links(scrub):
    text = "версия 1.2.3/4, decline 05/51, index.php/admin, 1.5/2 usd/eur, node.js/npm, 24/7, error.code/x"
    assert scrub(text) == text and scrub("acme.ru") == "<domain>"


@pytest.mark.parametrize("text,expected", [
    ("IBAN PL61 1090 1014 0000 0712 1981 2874", "IBAN <iban>"), ("GB82 WEST 1234 5698 7654 32", "<iban>"),
    ("iban de89370400440532013000", "iban <iban>"), ("IBAN: de89 3704 0044 0532 0130 00", "IBAN: <iban>"),
    ("IBAN DE89-3704-0044-0532-0130-00", "IBAN <iban>"), ("ИБАН: kz86125kzt5004100100", "ИБАН: <iban>"),
    ("ua213223130000026007233566001", "<iban>"), ("gb29 nwbk 6016 1331 9268 19", "<iban>"),
    ("IBAN DE00 3704 0044 0532 0130 00", "IBAN <iban>"),  # mistyped, but labelled
])
def test_ibans_with_checksum_and_separators(scrub, text, expected):
    assert scrub(text) == expected
    assert not LeakScanner(Known()).scan(expected)


@pytest.mark.parametrize("text", [
    "тикет SR12 3456 7890", "ticket AB12CDEF1234", "код ошибки RC05 1234 5678", "промокод NY24 SAVE 2024",
    "PO12 3456 7890 1234 5678", "DE00 3704 0044 0532 0130 00",
])
def test_iban_shaped_references_without_checksum_survive(scrub, text):
    assert scrub(text) == text


# --- expiry and CVV after a card ----------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("4000 0000 0000 0002\n12/27\n123", "400000**********\n<exp>\n<cvv>"),
    ("4000 0000 0000 0002|1227|123", "400000**********|<exp>|<cvv>"),
    ("4000 0000 0000 0002 (12/27, 123)", "400000********** (<exp>, <cvv>)"),
    ("4000 0000 0000 0002 - 12/27 - 123", "400000********** - <exp> - <cvv>"),
    ("номер 4000 0000 0000 0002, до 12/27, код 123", "номер 400000**********, до <exp>, код <cvv>"),
    ("4000000000000002/12/27/123", "400000**********/<exp>/<cvv>"),
    ("4000 0000 0000 0002 (12.05.2025)", "400000********** (12.05.2025)"),
    ("4000 0000 0000 0002\n12.05.2025 списали 300", "400000**********\n12.05.2025 списали 300"),
    ("4000 0000 0000 0002 1227 1500", "400000********** 1227 1500"),
    ("4000 0000 0000 0002\nошибка 05 при оплате", "400000**********\nошибка 05 при оплате"),
])
def test_expiry_and_cvv_after_a_card(scrub, text, expected):
    assert scrub(text) == expected


def test_trailer_after_a_card_entity(scrub, scanner):
    assert scrub("4000 0000 0000 0002 12/27 123", [Entity("BankCard", 0, 19)]) == "400000********** <exp> <cvv>"
    assert scrub("🙂 4000 0000 0000 0002 12/27 123", [Entity("BankCard", 3, 19)]) == "🙂 400000********** <exp> <cvv>"
    assert [l.kind for l in scanner.scan("400000********** 12/27 123")] == ["cvv"]


# --- Telegram Desktop lines and patronymics -------------------------------------------------------

def test_telegram_desktop_companion_lines(scrub):
    text = ("Иван Петров, [12.03.2024 10:15]\n[Forwarded from John Smith]\n[In reply to Anna Smirnova]\n"
            "[Переслано от Ивана Сидорова]\n[В ответ на Анну Смирнову]\ntext")
    assert scrub(text) == ("<name>, [12.03.2024 10:15]\n[Forwarded from <name>]\n[In reply to <name>]\n"
                           "[Переслано от <name>]\n[В ответ на <name>]\ntext")
    assert scrub("Ivan Sidorov, [12.03.2024 10:15] \r\n[Forwarded from Acme News (John Smith)]\r\ntext") == \
        "<name>, [12.03.2024 10:15] \r\n[Forwarded from <name>]\r\ntext"
    for text in ["ошибка E1042 в [Forwarded from John Smith] версия 1.2.3", "[In reply to] something"]:
        assert scrub(text) == text
    assert [l.kind for l in LeakScanner(Known()).scan("[Forwarded from John Smith]")] == ["td_companion"]


@pytest.mark.parametrize("text,expected", [
    ("Иван Сергеевич просил перезвонить, Мария Ивановна оплатила", "<name> просил перезвонить, <name> оплатила"),
    ("передайте Ольге Николаевне", "передайте <name>"), ("от Ивана Сергеевича", "от <name>"),
    ("с Марией Ивановной", "с <name>"), ("Здравствуйте Иван Сергеевич!", "Здравствуйте <name>!"),
    ("Петров Иван Сергеевич", "<name>"), ("Иван Сергеевич Петров звонил", "<name> звонил"),
    ("ФИО: Петров Иван Сергеевич", "ФИО: <cardholder>"),
    ("Заказ Кирпич", "Заказ Кирпич"), ("Москвич", "Москвич"), ("Сергеевич", "Сергеевич"),
    ("ошибка E1042 Excel", "ошибка E1042 Excel"), ("версия 2.15.3", "версия 2.15.3"),
])
def test_patronymics(scrub, text, expected):
    assert scrub(text) == expected


def test_patronymic_is_a_scanner_class():
    assert [l.kind for l in LeakScanner(Known()).scan("Иван Сергеевич просил")] == ["patronymic"]
    assert LeakScanner(Known()).scan("<name> просил") == []
