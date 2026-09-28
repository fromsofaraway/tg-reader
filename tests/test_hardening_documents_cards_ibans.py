"""Documents, cards and IBANs hardening.

A passport series and its number written on two lines; an IBAN whose length
is a multiple of four followed by a currency code; a card dump that writes
expiry and CVV as separate fields; numbers a file name glues to words with
'_'; a number the message itself labels as an identity twice; and the leak
scanner reading the visible BIN of a masked card as a code.

Every case runs in both directions: the raw text is scrubbed as expected and
the scanner reports it, while product knowledge stays byte-identical and the
scanner stays silent on placeholders.
"""

from datetime import datetime, timedelta, timezone

import pytest

from tg_collector.anonymize import Mapping, anonymize
from tg_collector.config import AnonPolicy
from tg_collector.model import KIND_GROUP, SENDER_USER, Media, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(), Roster()).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known())


def removes(scrub, scanner, text, expected, kind=None):
    """The scrubber turns ``text`` into ``expected``, the scanner reports the
    raw text (as ``kind`` when given) and says nothing about the output."""
    out = scrub(text)
    assert out == expected, (text, out)
    kinds = {leak.kind for leak in scanner.scan(text)}
    assert kinds, text
    assert kind is None or kind in kinds, (text, kinds)
    assert not scanner.scan(out), (out, scanner.scan(out))


def keeps(scrub, scanner, text):
    """Product knowledge stays byte-identical and the scanner is silent."""
    assert scrub(text) == text, (text, scrub(text))
    assert not scanner.scan(text), (text, scanner.scan(text))


# --- a passport series and number on separate lines --------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("Паспорт\nСерия 4509\nНомер 123456", "Паспорт\nСерия <passport>"),
    ("Паспорт РФ\nСерия 45 09\nНомер 123456", "Паспорт РФ\nСерия <passport>"),
    ("Серия: 4509\nНомер: 123456", "Серия: <passport>"),
    ("Серия: 4509 Номер: 123456", "Серия: <passport>"),
    ("серия паспорта 4509\nномер паспорта 123456", "серия паспорта <passport>"),
    ("Серия 4509\nномер: 123456\nвыдан 01.02.2015", "Серия <passport>\nвыдан 01.02.2015"),
    ("серия 4509 номер 123456", "серия <passport>"),          # the one-line form, unchanged
])
def test_passport_series_and_number_go_across_a_line_break(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected, "passport")


@pytest.mark.parametrize("text", [
    # Without a number label the next line is any number.
    "Серия 2024\n123456 заказов",
    "серия 2024\nномер заказа 123456",
    "Серия 2024\n\nНомер 123456",
])
def test_an_unlabelled_number_on_the_next_line_stays(scrub, scanner, text):
    keeps(scrub, scanner, text)


# --- an IBAN whose length is a multiple of four ------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("счёт KZ86125KZT5004100100 KZT", "счёт <iban> KZT"),
    ("IBAN: KZ86125KZT5004100100 KZT", "IBAN: <iban> KZT"),
    ("ИИК KZ86 125K ZT50 0410 0100 KZT", "ИИК <iban> KZT"),
    ("KZ86 125K ZT50 0410 0100 KZT", "<iban> KZT"),
    ("KZ86125KZT5004100100 2024", "<iban> 2024"),
    ("перевод на KZ86125KZT5004100100 USD 100", "перевод на <iban> USD 100"),
    ("реквизиты: AT611904300234573201 EUR", "реквизиты: <iban> EUR"),
    ("BY13NBRB3600900000002Z00AB00 BYN", "<iban> BYN"),
    ("LT121000011101001000 EUR", "<iban> EUR"),
    ("NO9386011117947 NOK", "<iban> NOK"),
    ("DE89370400440532013000 EUR", "<iban> EUR"),              # already worked, still does
])
def test_an_iban_before_a_currency_code_is_found(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected, "iban")


@pytest.mark.parametrize("text", [
    "KZ86125KZT5004100101 KZT",        # checksum fails
    "KZ86125KZT5004100199 KZT",
    "AT34 the best ever file",
    "LT12 и 3456",
    "заказ AB12CDEF3456GHIJ7890 KZT",  # no IBAN country
])
def test_a_number_that_is_not_an_iban_stays(scrub, scanner, text):
    keeps(scrub, scanner, text)


# --- card dumps: expiry and CVV as separate fields ----------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("4242424242424242|12|2027|123", "424242**********|<exp>|<cvv>"),
    ("4000005246895164|12|27|123", "400000**********|<exp>|<cvv>"),
    ("4242424242424242:12:2027:123", "424242**********:<exp>:<cvv>"),
    ("4000005246895164,12,27,123", "400000**********,<exp>,<cvv>"),
    ("4242424242424242;12/27;123", "424242**********;<exp>;<cvv>"),
])
def test_a_card_dump_loses_its_expiry_and_cvv(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected, "card")


def test_the_scanner_reports_an_unmasked_dump_trailer(scanner):
    assert {leak.kind for leak in scanner.scan("424242**********|12|2027|123")} == {"cvv"}
    assert not scanner.scan("424242**********|<exp>|<cvv>")
    assert not scanner.scan("424242********** 12 27 123")  # spaced fields are not a dump


def test_two_numbers_after_a_card_without_a_cvv_stay(scrub, scanner):
    removes(scrub, scanner, "4242424242424242|12|27", "424242**********|12|27", "card")
    keeps(scrub, scanner, "заказ|12|27|123")


@pytest.mark.parametrize("text,expected", [
    ("карта 5105 1051 0510 5100, CVV 737, до 03/30", "карта 510510**********, CVV <cvv>, до <exp>"),
    ("карта 4242424242424242 действует до 03-30", "карта 424242********** действует до <exp>"),
])
def test_an_expiry_after_a_bare_do_goes_with_its_card(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected, "card")


@pytest.mark.parametrize("text", [
    "оплатите до 03/30",                                # no card in the message
    "карта 4242424242424242, лимит до 10.50 руб",       # an amount
    "карта 4242424242424242, доставка до 10-15 дней",   # a deadline
    "карта 4242424242424242, ответ до 12.03.2026",      # a date
    "карта 4242424242424242, до 1250 руб",
])
def test_a_deadline_or_an_amount_after_do_stays(scrub, text):
    out = scrub(text)
    assert "<exp>" not in out, out
    assert out == text.replace("4242424242424242", "424242**********"), out


# --- a card number a file name glues to a word ---------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("file_4000000000000002.pdf", "file_400000**********.pdf"),
    ("карта_4242424242424242", "карта_424242**********"),
    ("4242424242424242_front.jpg", "424242**********_front.jpg"),
    ("4242424242424242_scan.pdf", "424242**********_scan.pdf"),
    ("x_4242 4242 4242 4242", "x_424242**********"),
    ("id 1234567_4242424242424242", "id 1234567_424242**********"),
    ("79990001122_5105105105105100", "<phone>_510510**********"),
    ("scan_79161112233_4242424242424242.jpg", "scan_<phone>_424242**********.jpg"),
])
def test_a_card_glued_by_an_underscore_is_masked(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected, "card")


@pytest.mark.parametrize("text", [
    "IMG_20240312150004.jpg",     # a Luhn-valid 14-digit timestamp
    "IMG_20240312_1015.jpg",
    "photo_1710230400130.jpg",    # milliseconds
    "order_1164840180091430",     # Luhn-valid, no network prefix
    "order_4242____4242",
    "4242____4242",
    "a4242424242424242",
    "1234_5678_9012_3456",
])
def test_an_ordinary_numbered_file_name_stays(scrub, scanner, text):
    keeps(scrub, scanner, text)


def test_a_hand_mask_of_underscores_still_reads_as_one_card(scrub, scanner):
    removes(scrub, scanner, "4242 42__ ____ 4242", "424242**********", "card")


def test_a_card_glued_to_a_known_surname_no_longer_stops_anonymize(tmp_path):
    me = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
    ivan = RawUser(id=2, first_name="Иван", last_name="Петров", username="ivan_petrov")
    chat = RawChat(id=-100123, kind=KIND_GROUP, title="Ромашка")
    t0 = datetime(2026, 3, 12, 9, 0, tzinfo=timezone.utc)
    store = RawStore(tmp_path / "raw")
    store.put_chats([chat])
    store.put_users([me, ivan])
    store.set_me_id(me.id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=1, date=t0, sender_id=ivan.id, sender_kind=SENDER_USER,
                   text="Петров_4000000000000002 не проходит"),
        RawMessage(chat_id=chat.id, id=2, date=t0 + timedelta(minutes=1), sender_id=ivan.id, sender_kind=SENDER_USER,
                   text="скан", media=Media(kind="document", ext="pdf", file_name="Петров_4000000000000002.pdf")),
    ])
    # The self-check inside anonymize aborted on the card it could still see.
    ds = anonymize(store, Mapping(tmp_path / "mapping.json"), Roles.build(me.id), AnonPolicy(keep_file_names=True))
    texts = [m.text for m in ds.messages]
    assert texts == ["<name>_400000********** не проходит", "скан"]
    assert ds.messages[1].media["name"] == "<name>_400000**********.pdf"


# --- phones and documents a short file name glues to words ---------------------------------

@pytest.mark.parametrize("text,expected", [
    ("client_79161234567_report.xlsx", "client_<phone>_report.xlsx"),
    ("scan_89161112233.pdf", "scan_<phone>.pdf"),
    ("inn_7700000425.pdf", "inn_<inn>.pdf"),
    ("acc_40817810099910004312.pdf", "acc_<account>.pdf"),
    ("scan_iin_900101300123.pdf", "scan_iin_<tax-id>.pdf"),
    ("snils_11223344595.pdf", "snils_<snils>.pdf"),
    ("passport_4510_123456.jpg", "passport_<passport>.jpg"),
    ("паспорт_4510_123456.jpg", "паспорт_<passport>.jpg"),
    ("скан_паспорт_4509123456.pdf", "скан_паспорт_<passport>.pdf"),
])
def test_a_number_a_file_name_hides_behind_an_underscore_goes(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    # an operation label in front of the '_' keeps its reference
    "ticket_89991234567", "order_7700000425.pdf", "ORDER_ID_7700000425", "TXN_1234567890",
    "заказ_79161234567", "invoice_7700000425",
    # ordinary numbered file names
    "export_1500_rows.csv", "report_2026_03_12.xlsx", "build_20260312_1530", "ERR_4001_TIMEOUT",
    "photo_1710230400.jpg", "scan_9161112233.pdf", "user_1234567890.json",
])
def test_a_reference_or_a_plain_number_in_a_file_name_stays(scrub, scanner, text):
    keeps(scrub, scanner, text)


@pytest.mark.parametrize("text,expected", [
    # A long run stays the secret rules' business: replacing only the number
    # would leave the name beside it in the text.
    ("passport_4510_123456_ivanov_ivan_1985_scan_final.jpg", "<token>.jpg"),
    ("snils_112-233-445-95_scan_front_side_2026_03_12_final", "<token>"),
    ("dogovor_ooo_romashka_inn_7700000425_2026_03_12.pdf", "<token>.pdf"),
])
def test_a_long_file_name_is_still_taken_whole(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected)


# --- the same number labelled twice in one message -----------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("обращение 651214316007 от клиента, иин 651214316007", "обращение <iin> от клиента, иин <iin>"),
    ("обращение 7700000425, инн 7700000425", "обращение <tax-id>, инн <tax-id>"),
    ("ИНН 7700000425, заказ 7700000425", "ИНН <tax-id>, заказ <inn>"),
    ("инн 7700000425 в заказе 7700000425 и в счете 7700000425",
     "инн <tax-id> в заказе <inn> и в счете <inn>"),
])
def test_a_number_labelled_as_an_identity_goes_everywhere_in_the_message(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("заявка 651214316007 (иин)", "заявка <iin> (иин)"),
    ("обращение 651214316007 - ИИН", "обращение <iin> - ИИН"),
])
def test_a_bracketed_label_behind_the_number_names_it_too(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "заказ 651214316007",                            # only ever a reference
    "заказ 7700000425",
    "заказы: 651214316007, 7700000425",
    "заказ 7700000425 (акт)",
    "заказ 7700000425 - оплачен",
    # the word behind a comma or a space introduces the next number instead
    "заказ 7700000425, ИНН плательщика 7701234567",
    "заказ 651214316007, ИИН тот же",
])
def test_an_unlabelled_reference_number_stays(scrub, scanner, text):
    keeps(scrub, scanner, text)


def test_another_number_in_the_message_is_not_the_identity(scrub, scanner):
    removes(scrub, scanner, "иин 651214316007, сумма 6512143160", "иин <iin>, сумма 6512143160")
    removes(scrub, scanner, "заказ 7700000425, ИНН 7700000016", "заказ 7700000425, ИНН <tax-id>")


# --- the scanner and the visible BIN of a masked card ---------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("код: 4242424242424242", "код: 424242**********"),
    ("код 4242 4242 4242 4242", "код 424242**********"),
    ("3DS код 4242424242424242", "3DS код 424242**********"),
    ("СМС код 5105105105105100", "СМС код 510510**********"),
    ("otp 4000000000000002", "otp 400000**********"),
    ("пин 4242424242424242", "пин 424242**********"),
    ("pin: 4242 4242 4242 4242", "pin: 424242**********"),
    ("код карты 4242424242424242", "код карты 424242**********"),
    ("инст P-42424242424242", "инст P-424242********"),
])
def test_a_masked_card_is_not_read_as_a_code(scrub, scanner, text, expected):
    removes(scrub, scanner, text, expected, "card")


@pytest.mark.parametrize("text", [
    "код: 424242**********", "пин 424242**********", "RRN 424242**********", "инст P-424242********",
])
def test_the_scanner_never_flags_a_masked_card_as_a_value(scanner, text):
    assert scanner.scan(text) == []


@pytest.mark.parametrize("text,kind", [
    ("код 482913", "otp"),
    ("код: 424242", "otp"),
    ("пин 1234", "pin"),
    ("код 482913 424242**********", "otp"),
    ("код 4242424242424242", "card"),
])
def test_a_real_code_is_still_reported(scanner, text, kind):
    assert kind in {leak.kind for leak in scanner.scan(text)}, (text, scanner.scan(text))


def test_configured_bins_behave_the_same(scrub, scanner):
    bin_scrub = Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub
    bin_scanner = LeakScanner(Known(card_bins=frozenset(BINS)))
    removes(bin_scrub, bin_scanner, "file_4242424242424242.pdf", "file_424242**********.pdf", "card")
    removes(bin_scrub, bin_scanner, "код 4242 4242 4242 4242", "код 424242**********", "card")
    keeps(bin_scrub, bin_scanner, "photo_1710230400130.jpg")
