"""Card detection hardening: prefixes, slashes, groupings, line breaks,
Unicode separators and digits, and the scanner never re-flagging our masks."""

import pytest

from tg_collector.cards import find_cards
from tg_collector.config import AnonPolicy
from tg_collector.model import Entity
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("400000", "424242")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS)))


def _masked(out: str, bin_: str) -> bool:
    return f"{bin_}**********" in out and not any(c.isdigit() for c in out.split(bin_, 1)[1].split(" ")[0])


@pytest.mark.parametrize("text,expected", [
    ("card #4000 0000 0000 0002 12/27 123", "card #400000********** <exp> <cvv>"),
    ("карта #5105 1051 0510 5100", "карта #510510**********"),
    ("•4242 4212 3456 7891", "•424242**********"),
    ("##4000000000000002##", "##400000************"),
    ("x4242 4212 3456 7891", "x424242**********"),
    ("4000000000000002/12/27/123", "400000**********/<exp>/<cvv>"),
    ("4000 0000 0000 0002/12/27", "400000**********/<exp>"),
    ("4000 0000 00000002", "400000**********"),
    ("40000000 00000002", "400000**********"),
    ("4000 000000000002", "400000**********"),
    ("4000 0000 0000 00002", "400000***********"),
    ("1500 4000 0000 00000002 ок", "1500 400000********** ок"),
    ("40000000 00000002 12/27", "400000********** <exp>"),
    ("карта: 4000 0000\n0000 0002", "карта: 400000**********"),
    ("4000 0000 0000\n0002", "400000**********"),
    ("4000\n0000\n0000\n0002", "400000**********"),
    ("4000 0000 0000 0002\n8 999 123 45 67", "400000**********\n<phone>"),
    ("4000\u200d0000\u200d0000\u200d0002", "400000**********"),
    ("4242\u200c4212\u200c3456\u200c7890", "424242**********"),
    ("4242\u00ad4212\u00ad3456\u00ad7890", "424242**********"),
    ("4242\u20034212\u20033456\u20037890", "424242**********"),
    ("4242 - 4212 - 3456 - 7890", "424242**********"),
    ("5105 - 1051 - 0510 - 5100", "510510**********"),
    ("карта ٤٠٠٠ ٠٠٠٠ ٠٠٠٠ ٠٠٠٢", "карта 400000**********"),
    ("४००००००००००००००२", "400000**********"),
    ("𝟒𝟎𝟎𝟎 𝟎𝟎𝟎𝟎 𝟎𝟎𝟎𝟎 𝟎𝟎𝟎𝟐", "400000**********"),
])
def test_cards_are_found_in_hostile_shapes(scrub, scanner, text, expected):
    out = scrub(text)
    assert out == expected
    assert scanner.scan(text), text
    assert not scanner.scan(out), out


@pytest.mark.parametrize("text", [
    "заказ #1234567890123", "ticket #12345678901234567", "ошибка #500", "error #E1234",
    "заказ 12345678/2 от 12/27/2026 v1.2/3",
    "наши БИНы: 424242 400000 510510", "заказ 400000 123456 не найден", "51051051 05105100",
    "5105 1051\n0510 5100", "карта: 4000 0000\n\n0000 0002",
    "8 999 123-45-67\n8 999 765-43-21", "коды:\n8459\n1912\n3495\n0042", "400000\n400001\n400002",
    "ок 👩\u200d💻 сделаю 👨\u200d👩\u200d👧", "1000   2000   3000   4000", "период 2024 - 2025",
    "4242424242424242 12", "код ошибки ٤٠٤",
])
def test_non_cards_are_left_alone(text):
    # Only the card layer is under test here: other layers may still act on
    # phones and digits, so compare with the bare card finder.
    assert not find_cards(text, BINS) or text in ("4242424242424242 12",)


def test_known_bin_card_followed_by_a_short_number_keeps_the_number(scrub):
    assert scrub("4242424242424242 12") == "424242********** 12"


def test_masked_output_is_never_a_card_again(scanner):
    assert not find_cards("424242********** 12", ("424242",))
    assert not scanner.scan("400000********** 12 27 123")
    assert scanner.scan("4000000000000002 12")[0].kind == "card"
    assert scanner.scan("424242******1234")[0].kind == "card"


def test_astral_digits_do_not_shift_entity_offsets():
    s = Scrubber(AnonPolicy(card_bins=BINS), Roster())
    text = "𝟒𝟎𝟎𝟎 𝟎𝟎𝟎𝟎 𝟎𝟎𝟎𝟎 𝟎𝟎𝟎𝟐 mail x@y.z"
    # Each bold digit is two UTF-16 units: 16 digits and 3 spaces make 35, " mail " adds 6.
    assert s.scrub(text, [Entity("Email", 41, 5)]) == "400000********** mail <email>"


def test_line_break_only_joins_configured_bins(scanner):
    assert find_cards("карта: 4000 0000\n0000 0002", BINS)
    assert not find_cards("5105 1051\n0510 5100", BINS)  # Luhn-valid, unknown BIN, split over lines
