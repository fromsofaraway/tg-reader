"""Rules whose cost must stay proportional to the length of the text, however
hostile the text is, pinned together with the behaviour they must not change.

* The street-address rule, the seed-phrase separator and the person-keyword
  gap take their whitespace runs possessively. A street keyword, a BIP39
  word or "С уважением" in front of a message full of blanks would
  otherwise cost seconds to minutes per pass, and every message is scrubbed
  once and scanned again in verify.
* Vocabulary terms are dispatched on the character they start with, so a
  roster of thousands of names costs about as much per character as a roster
  of ten.
* Keep-term, placeholder and longer-term spans are searched by bisection
  instead of being scanned, so a long text stays linear.
* verify scans each distinct (kind, text) pair once: chunk files are
  verbatim copies of the transcripts, and composed strings repeat on every
  row.

Every rule is checked in both directions: the raw form is scrubbed as
expected and flagged by the scanner, product knowledge stays byte-identical
and the scanner stays silent on it and on our own placeholders. The
rewritten patterns are also compared span by span with the shapes they
replace, over generated text, because each rewrite claims to be exact.
"""

import dataclasses
import json
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from conftest import SCRUB_BUDGET, assert_cost_ratio, assert_fast
from tg_collector import fintech, scrub as scrub_module, verify as verify_module
from tg_collector.anonymize import Mapping, anonymize
from tg_collector.bip39 import WORDS as BIP39_WORDS
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.rules import keyword_rule
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber, translit
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
PLACEHOLDERS = "<name> <org> <address> <seed-phrase> <domain> <phone> @user <redacted>"
# A message Telegram can carry; every budget below is for a text of this size.
MESSAGE_LEN = 4096
# Generous against the measured cost (about 30 ms for a scrub of 4 KB and
# about 28 ms for a scan), tight against the defect (seconds to hours). A
# tighter budget would mostly report the load on the machine running the
# suite; catastrophic backtracking costs seconds on every machine.
BUDGET = SCRUB_BUDGET


def scrub_with(policy=AnonPolicy(), **roster):
    return Scrubber(policy, Roster(**roster)).scrub


def scanner(names=(), titles=(), keep=(), regex_rules=True):
    return LeakScanner(Known(names=frozenset(names), titles=frozenset(titles), keep_terms=frozenset(keep)),
                       regex_rules=regex_rules)


def both_ways(scrub, scan, raw, expected):
    """The raw text is scrubbed as expected and flagged; the output is clean."""
    assert scrub(raw) == expected
    assert scan.scan(raw), raw
    assert scan.scan(scrub(raw)) == []


def unchanged(scrub, scan, text):
    """Product knowledge survives byte for byte and the scanner stays silent."""
    assert scrub(text) == text
    assert scan.scan(text) == []


def rule_named(name, index=0):
    return [r for r in fintech.FINTECH_RULES if r.name == name][index].pattern


def spans(pattern, text):
    return [m.span() for m in pattern.finditer(text)]


# --- the street-address rule ---------------------------------------------------------------

# The shape the possessive rule replaces: overlapping whitespace runs around
# a lazy street name, which made a backtracking engine cost O(name x run^3)
# per starting position.
OLD_STREET_NAME = r"\s*[^\n,;]{2,40}?,?\s*(?:д\.|дом|house|№)?\s*"
OLD_STREET = re.compile(
    rf"(?<![\w]){fintech._CITY}{fintech._STREET}{OLD_STREET_NAME}{fintech._HOUSE_NUMBER_START}"
    rf"\d{{1,4}}[а-яa-z]?{fintech._BLD.replace('*+', '*')}{fintech._BLD.replace('*+', '*')}"
    rf"{fintech._FLAT.replace('*+', '*')}", re.IGNORECASE)

ADDRESSES = [
    ("г. Актау, мкр. 5, д. 12", "<address>"),
    ("г. Алматы, мкр. 1, д. 15, кв. 7", "<address>"),
    ("мкр. 5, д. 10", "<address>"),
    ("мкр. 5, д. 12, кв. 34", "<address>"),
    ("мкр.  \n5, д. 10", "<address>, д. 10"),
    ("ул. А10", "<address>"),
    ("ул. А5", "<address>"),
    ("ул.  10", "<address>"),
    ("ул.  , 5", "<address>"),
    ("наб. 1, 5", "<address>"),
    ("пр-т 5, 10", "<address>"),
    ("живу мкр. 1, 5", "живу <address>"),
    ("ул. Абая 10, кв. 5", "<address>"),
    ("ул. Абая 10, корп. 2, кв. 5", "<address>"),
    ("ул. " + " " * 60 + "Абая 10", "<address>"),
    ("ул. Абая" + " " * 60 + "10", "<address>"),
]


@pytest.mark.parametrize("raw, expected", ADDRESSES)
def test_street_addresses_are_scrubbed_and_flagged(raw, expected):
    both_ways(scrub_with(), scanner(), raw, expected)


@pytest.mark.parametrize("text", [
    "ул. 10",                      # a bare number after the keyword is not an address
    "пер. 1500 руб",               # "пер." is also short for "перевод"
    "пер. 1500 руб на карту",
    "и пр. лимит 100",             # "пр." is also short for "прочее"
    PLACEHOLDERS,
])
def test_street_rule_leaves_product_knowledge_alone(text):
    unchanged(scrub_with(), scanner(), text)


@pytest.mark.parametrize("text", [
    "набережная" + " " * (MESSAGE_LEN - len("набережная")),
    "ул." + " " * (MESSAGE_LEN - 4) + "x",
    "г. Алматы, ул." + " " * (MESSAGE_LEN - 14),
    "ул. Абая 5" + " " * (MESSAGE_LEN - 11) + "x",
    "ул. Абая" + " " * (MESSAGE_LEN - 13) + "итого",
    "мкр." + "\xa0" * (MESSAGE_LEN - 5) + "x",
    "ул." + "\n" * (MESSAGE_LEN - 4) + "x",
    ("ул. Абая" + " " * 90 + "офис" + " " * 90 + "итого\n") * 20,   # an aligned table
])
def test_street_rule_stays_fast_on_hostile_whitespace(text):
    scrub, scan = scrub_with(), scanner()
    assert_fast(lambda: (scrub(text), scan.scan(text)), budget=BUDGET, label=text[:20])


def test_street_rule_cost_grows_with_the_length_of_the_text():
    scrub = scrub_with()
    short = "ул. Абая" + " " * (MESSAGE_LEN - 8)
    long = "ул. Абая" + " " * (4 * MESSAGE_LEN - 8)
    assert_cost_ratio(lambda: scrub(short), lambda: scrub(long), 8, label="street run")


def test_street_rule_finds_exactly_what_the_backtracking_shape_found():
    """The possessive rule claims to be exact, so its spans must equal the
    old ones on every combination of city, keyword, blanks, name, comma,
    house number and building or flat."""
    new = rule_named("address", 1)
    streets = ["ул.", "улица", "пер.", "просп.", "пр-т", "наб.", "мкр.", "б-р", "шоссе", "микрорайон", "көш."]
    blanks = ["", " ", "  ", "   ", "\t", "\xa0", "\n", " \n ", "\n\n", "  \n", "\n  "]
    names = ["", "Абая", "А", "Ромашки", "1-й Колобовский", "8 Марта", "Northwind"]
    cities = ["", "г. Актау, ", "город Алматы, ", "с. Ромашка, ", "пос. Акме, "]
    houses = ["5", "10", "12а", "1234", "д. 7", "дом 7", "№ 7", "house 7"]
    tails = ["", ", кв. 5", " корп. 2, кв. 5", "/3", ", оф. 12", ", стр. 1, кв. 9", " подъезд 2"]
    rnd = random.Random(20260918)
    for _ in range(4000):
        text = (rnd.choice(cities) + rnd.choice(streets) + rnd.choice(blanks) + rnd.choice(names)
                + rnd.choice([",", ""]) + rnd.choice(blanks) + rnd.choice(houses) + rnd.choice(tails))
        assert spans(new, text) == spans(OLD_STREET, text), text


# --- the seed-phrase separator -------------------------------------------------------------

OLD_SEED_SEP = r"(?:[ \t,;]+|\s*\n\s*)(?:\d{1,2}[.)]\s*)?"
OLD_SEED = re.compile(
    rf"(?<![A-Za-z])(?:\d{{1,2}}[.)]\s*)?{fintech._SEED_WORD}"
    rf"(?:{OLD_SEED_SEP}{fintech._SEED_WORD}){{11,}}(?![A-Za-z])", re.IGNORECASE)
TWELVE = ["abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
          "absurd", "abuse", "access", "accident"]


@pytest.mark.parametrize("separator", [" ", "  ", ", ", ",", "\t", "\r\n", " \n", "\n", "\n\n", "\n\n\n", " \n "])
def test_seed_phrase_is_scrubbed_and_flagged_whatever_separates_its_words(separator):
    both_ways(scrub_with(), scanner(), separator.join(TWELVE), "<seed-phrase>")


def test_numbered_seed_phrase_with_blank_lines_is_scrubbed_and_flagged():
    numbered = "\n".join(f"{i}. {w}" for i, w in enumerate(TWELVE, 1)).replace("3. able", "\n3. able")
    both_ways(scrub_with(), scanner(), numbered, "<seed-phrase>")


def test_seed_phrase_followed_by_a_long_newline_run_keeps_the_newlines():
    tail = "\n" * 4000
    both_ways(scrub_with(), scanner(), " ".join(TWELVE) + tail, "<seed-phrase>" + tail)


@pytest.mark.parametrize("text", [
    " ".join(TWELVE[:11]),                                     # eleven words are not a phrase
    "Error access denied\n\n\nbalance list",                   # ordinary English words of the list
    "access balance list release error account address test",
    PLACEHOLDERS,
])
def test_seed_rule_leaves_product_knowledge_alone(text):
    unchanged(scrub_with(), scanner(), text)


@pytest.mark.parametrize("text", [
    "key" + "\n" * (MESSAGE_LEN - 4) + "x",
    "key" + " \n" * ((MESSAGE_LEN - 4) // 2) + "x",
    "access" + "\n\n" * ((MESSAGE_LEN - 7) // 2) + "x",
])
def test_seed_separator_stays_fast_on_hostile_newline_runs(text):
    scrub, scan = scrub_with(), scanner()
    assert_fast(lambda: (scrub(text), scan.scan(text)), budget=BUDGET, label=text[:20])


def test_seed_separator_finds_exactly_what_the_backtracking_shape_found():
    new = rule_named("seed_phrase")
    separators = [" ", "  ", ", ", ",", "\t", "\r\n", " \n", "\n", "\n\n", " \n ", "\xa0", "\u2028", "; "]
    numbering = ["", "1. ", "2) ", "12. ", "3.", "7)"]
    rnd = random.Random(7)
    words = sorted(BIP39_WORDS)
    for _ in range(400):
        chosen = [rnd.choice(words) for _ in range(rnd.choice([11, 12, 13, 24]))]
        text = "".join((rnd.choice(separators) + rnd.choice(numbering) if i else "") + w
                       for i, w in enumerate(chosen))
        text = rnd.choice(["", "seed: ", "фраза "]) + text + rnd.choice(["", " конец", "\n\n\n"])
        assert spans(new, text) == spans(OLD_SEED, text), text[:80]


# --- the person-keyword gap ----------------------------------------------------------------

PERSON_KEYWORDS = (r"меня зовут|его зовут|её зовут|ее зовут|my name is|контактное лицо|контакт\.? лицо"
                   r"|с уважением|best regards|kind regards|regards|sincerely|from:|от:|кому:|to:|cc:")
OLD_PERSON = keyword_rule("person", PERSON_KEYWORDS, fintech._FULL, "<name>",
                          gap=r"[,:;\-–—]?[^\S\n]*\n?[^\S\n]*").pattern


@pytest.mark.parametrize("raw, expected", [
    ("Best regards,\nAnna Smith", "Best regards,\n<name>"),
    ("Кому:   Иван Петров", "Кому:   <name>"),
    ("С уважением,   \n   Олег Северов", "С уважением,   \n   <name>"),
    ("С уважением,\n  Олег Северов", "С уважением,\n  <name>"),
    ("С уважением,\n" + " " * 4000 + "Олег Северов", "С уважением,\n" + " " * 4000 + "<name>"),
])
def test_person_after_a_keyword_is_scrubbed_and_flagged(raw, expected):
    both_ways(scrub_with(), scanner(), raw, expected)


@pytest.mark.parametrize("text", [
    "Best regards,\n\nAnna Smith",        # a blank line is out of the keyword's scope by design
    "С уважением, команда Northwind",
    "С уважением,\nООО Ромашка",
    PLACEHOLDERS,
])
def test_person_keyword_gap_leaves_product_knowledge_alone(text):
    unchanged(scrub_with(), scanner(), text)


@pytest.mark.parametrize("text", [
    "best regards" + " " * (MESSAGE_LEN - 12),
    "кому:" + "\xa0" * (MESSAGE_LEN - 5),
    "кому:" + "\t" * (MESSAGE_LEN - 5),
    "С уважением," + " " * (MESSAGE_LEN - 12),
    "меня зовут" + " " * (MESSAGE_LEN - 10),
])
def test_person_keyword_gap_stays_fast_on_hostile_whitespace(text):
    scrub, scan = scrub_with(), scanner()
    assert_fast(lambda: (scrub(text), scan.scan(text)), budget=BUDGET, label=text[:20])


def test_person_keyword_gap_finds_exactly_what_the_backtracking_shape_found():
    new = [r for r in fintech.FINTECH_RULES
           if r.name == "person" and "уважением" in r.pattern.pattern][0].pattern
    keywords = ["Best regards", "best regards", "С уважением", "Кому:", "от:", "my name is",
                "контактное лицо", "sincerely", "cc:", "to:", "regards"]
    separators = ["", ",", ":", ";", "-", "–", "—"]
    gaps = ["", " ", "  ", "\t", "\xa0", "\n", " \n ", "\n  ", "  \n  ", "\n\n", "   \n   "]
    values = ["Anna Smith", "Олег Северов", "Иван Петров", "ООО Ромашка", "команда Northwind",
              "И. Петров", "Petrov I.", "Анна", "A. B. Smirnov"]
    rnd = random.Random(11)
    for _ in range(4000):
        text = rnd.choice(keywords) + rnd.choice(separators) + rnd.choice(gaps) + rnd.choice(values)
        assert ([(m.span(), m.span("gap"), m.span("val")) for m in new.finditer(text)]
                == [(m.span(), m.span("gap"), m.span("val")) for m in OLD_PERSON.finditer(text)]), text


# --- vocabulary terms dispatched on their first character ----------------------------------

def flat_pattern(terms, org=False):
    """The roster pattern as one flat alternation: the shape the dispatch
    replaces, and the answer every dispatched pattern must reproduce."""
    parts = {}
    for _, fragment in sorted(scrub_module._term_alternatives(terms, org), key=lambda a: (-len(a[0]), a[0])):
        parts.setdefault(fragment.pattern, fragment.first)
    if not parts:
        return None
    return re.compile(r"(?<![^\W_])(?:" + "|".join(parts) + r")" + scrub_module._TERM_END,
                      re.IGNORECASE | re.UNICODE)


@pytest.mark.parametrize("terms, raw, expected", [
    (("Ковальская",), "Ковальского и Kovalskaya", "<name> и <name>"),
    (("İsa Nurlanov", "İsa Kaya"), "Со мной говорил İsa Nurlanov, потом İsa Kaya",
     "Со мной говорил <name>, потом <name>"),
    (("✨Анна Петрова", "Ёлкин", "Щукин"), "писал ✨Анна Петрова и Елкина, Shchukinu",
     "писал <name> и <name>, <name>"),
    (("Ёлкин",), "Елкину, ёлкина, Yolkin, Elkin", "<name>, <name>, <name>, <name>"),
    (("Иван Петров", "Петров", "Ёлкин", "Ковальская", "Кравец"),
     "Ивану Петрову, Ёлкина, Yolkin, Ковальского, Кравца",
     "<name>, <name>, <name>, <name>, <name>"),
    (("Sam Ali", "ſam"), "Sam Ali пришёл", "<name> пришёл"),
])
def test_dispatched_terms_are_scrubbed_and_flagged(terms, raw, expected):
    both_ways(scrub_with(person_terms=terms), scanner(names=terms, regex_rules=False), raw, expected)


@pytest.mark.parametrize("terms, text", [
    (("Марк",), "маркет открыт, заказ #4471"),
    (("Иван Петров",), PLACEHOLDERS),
])
def test_dispatched_terms_leave_product_knowledge_alone(terms, text):
    unchanged(scrub_with(person_terms=terms), scanner(names=terms, regex_rules=False), text)


def test_an_organisation_term_inside_an_all_caps_constant_survives_the_dispatch():
    unchanged(scrub_with(org_terms=("Ромашка",)), scanner(titles=("Ромашка",), regex_rules=False),
              "ERR_ROMASHKA_TIMEOUT в версии 2.10.1")


def test_a_roster_pattern_is_dispatched_on_the_first_character():
    pattern = scrub_module._term_pattern(("Иван Петров", "Ковальская", "Ёлкин"))
    assert "(?=[" in pattern.pattern


def test_a_term_whose_first_character_is_unknown_falls_back_to_a_flat_alternation():
    """An adjectival term of soft signs has a stem that transliterates to
    nothing, so one of its alternatives starts with an ending class rather
    than a literal. The whole roster then uses the flat alternation instead
    of dropping that alternative and leaking the term it stands for."""
    terms = ("ьььььий", "Иван Петров")
    pattern = scrub_module._term_pattern(terms)
    assert "(?=[" not in pattern.pattern
    assert pattern.pattern == flat_pattern(terms).pattern
    assert scrub_with(person_terms=terms)("звонил Иван Петров вчера") == "звонил <name> вчера"


def test_an_alternative_of_unknown_shape_is_kept_rather_than_dropped():
    """The dispatch may only be skipped, never applied by leaving an
    alternative out: whatever the flat alternation matched must still be
    matched."""
    opaque = ("....", scrub_module._Fragment(r"\d+тест", scrub_module._ANY_START))
    pattern = scrub_module._compile_terms([*scrub_module._term_alternatives(("Иван Петров",), org=False), opaque])
    assert "(?=[" not in pattern.pattern
    assert pattern.search("Ивану Петрову") and pattern.search("42тест")


def test_dispatched_terms_match_exactly_what_the_flat_alternation_matched():
    """Random rosters, including letters that fold together across alphabets
    (the dotless "ı", the long "ſ", the dotted "İ"), over inflected,
    transliterated and identifier-glued text."""
    cyrillic, latin = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя", "abcdefghijklmnopqrstuvwxyz"
    odd = "ıſİKÅΩәқғңөұүһiјєіїґўşğçöü"
    rnd = random.Random(99)

    def word(size):
        alphabet = rnd.choice([cyrillic, latin, odd, cyrillic + odd, latin + odd])
        made = "".join(rnd.choice(alphabet) for _ in range(size))
        return rnd.choice([made.capitalize(), made, made.upper(), "✨" + made.capitalize()])

    for _ in range(30):
        org = rnd.random() < 0.3
        terms = []
        for _ in range(rnd.randint(1, 40)):
            terms.append(" ".join(word(rnd.randint(2, 9)) for _ in range(rnd.choice([1, 1, 2, 2, 3]))))
            if rnd.random() < 0.2:
                terms[-1] = terms[-1].replace(" ", "-", 1)
        flat, dispatched = flat_pattern(terms, org), scrub_module._term_pattern(terms, org)
        assert (flat is None) == (dispatched is None)
        if flat is None:
            continue
        chunks = []
        for term in terms:
            chunks += [term, term.lower(), term.upper(), translit(term), term + "ой", term + "ым",
                       term + "1990", "IMG_" + term.replace(" ", "_") + "2.jpg", term[:-1] + "а",
                       "x" + term, term + "z"]
        text = " ".join(rnd.sample(chunks, len(chunks)))
        for glue in ("_", "-", ".", ", ", "\n"):
            text += glue + rnd.choice(chunks)
        assert spans(dispatched, text) == spans(flat, text), terms[:3]


def test_no_character_of_any_text_can_open_two_dispatch_groups():
    """The dispatch keeps the alternatives of the flat alternation in order
    only because at most one group opens at a position. Recomputed over the
    whole of Unicode, so a release that changes case folding fails here
    rather than silently reordering the roster."""
    alphabet = ("абвгдеёжзийклмнопрстуфхцчшщъыьэюя" + "abcdefghijklmnopqrstuvwxyz" + "0123456789"
                + "ıſİKÅΩәқғңөұүһiјєіїґўşğçöü" + "-.'")
    classes = scrub_module._case_insensitive_classes(alphabet)
    assert sorted(len(c) for c in classes if len(c) > 1) == [2, 2, 3]   # K/k, s/ſ, i/İ/ı
    every_character = "".join(map(chr, range(0x110000)))
    owner = {}
    for members in classes:
        group = re.compile("[" + "".join(re.escape(c) for c in members) + "]", re.IGNORECASE)
        for character in set(group.findall(every_character)):
            assert character not in owner, (character, owner.get(character), members)
            owner[character] = members


def test_a_large_roster_costs_about_what_a_small_one_costs():
    rnd = random.Random(3)
    letters = "абвгдежзиклмнопрстуфхцшы"
    names = ["".join(rnd.choice(letters) for _ in range(rnd.randint(4, 9))).capitalize() for _ in range(3000)]
    pattern = scrub_module._term_pattern(names)
    assert "(?=[" in pattern.pattern
    document = json.dumps({f"field_{i}": f"value {i} ромашка northwind" for i in range(200)},
                          indent=1, ensure_ascii=False)[:MESSAGE_LEN]
    prose = ("клиент просит вернуть платёж по заказу 4471, ответьте ему сегодня. " * 80)[:MESSAGE_LEN]
    for text in (document, prose):
        assert_fast(lambda: list(pattern.finditer(text)), budget=BUDGET, label=text[:20])


# --- keep-term and placeholder spans found by bisection ------------------------------------

KEEP = ("Northwind", "Northwind Pay", "Acme")


@pytest.mark.parametrize("keep, raw, expected, flagged", [
    (("ASP.NET Core",), "ASP.NET Core; ASP.NET", "ASP.NET Core; <domain>", [("domain", "ASP.NET")]),
    (("Acme",), "see acme.evilclient.ru and Acme", "see <domain> and Acme",
     [("domain", "acme.evilclient.ru")]),
    (("Northwind",), "northwind.ru northwind.app x.northwind.ru",
     "northwind.ru northwind.app <domain>", [("domain", "x.northwind.ru")]),
    (("Northwind",), "x.northwind.ru northwind.ru acme.evilclient.ru",
     "<domain> northwind.ru <domain>",
     [("domain", "x.northwind.ru"), ("domain", "acme.evilclient.ru")]),
    (("ASP.NET Core", "ASP.NET"), "ASP.NET Core и asp.net.evil.io", "ASP.NET Core и <domain>",
     [("domain", "asp.net.evil.io")]),
])
def test_a_host_is_kept_only_where_it_carries_nothing_beyond_a_keep_term(keep, raw, expected, flagged):
    scrub = scrub_with(AnonPolicy(keep_terms=keep), keep_terms=keep)
    scan = scanner(keep=keep)
    assert scrub(raw) == expected
    assert [(leak.kind, leak.match) for leak in scan.scan(raw)] == flagged
    assert scan.scan(scrub(raw)) == []


def test_a_keep_term_inside_a_longer_organisation_term_stays_visible_to_the_vocabulary():
    keep, org = ("Acme",), ("Acme Corp",)
    scrub = scrub_with(AnonPolicy(keep_terms=keep), keep_terms=keep, org_terms=org)
    scan = scanner(keep=keep, titles=org)
    assert scrub("Acme Corp и Acme") == "<org> и Acme"
    assert [(leak.kind, leak.match) for leak in scan.scan("Acme Corp и Acme")] == [("title", "Acme Corp")]
    assert scan.scan(scrub("Acme Corp и Acme")) == []


def test_a_keep_term_inside_a_longer_keep_term_is_untouched():
    keep = ("Northwind Pay", "Northwind")
    unchanged(scrub_with(AnonPolicy(keep_terms=keep), keep_terms=keep), scanner(keep=keep),
              "Northwind.Pay в Northwind Pay")


@pytest.mark.parametrize("unit", ["acme acme acme x.acme.io ", "x.northwind.ru "])
def test_keep_term_hosts_cost_grows_with_the_length_of_the_text(unit):
    scrub = scrub_with(AnonPolicy(keep_terms=KEEP), keep_terms=KEEP)
    scan = scanner(keep=KEEP)

    def of_size(size):
        return (unit * (size // len(unit) + 1))[:size]
    short, long = of_size(MESSAGE_LEN), of_size(4 * MESSAGE_LEN)
    assert_cost_ratio(lambda: (scrub(short), scan.scan(short)),
                      lambda: (scrub(long), scan.scan(long)), 6, label=unit)
    assert_fast(lambda: (scrub(short), scan.scan(short)), budget=BUDGET, label=unit)


def test_placeholder_dense_text_costs_grow_with_the_length_of_the_text():
    scan = scanner(names=("Иван Петров",), keep=KEEP)
    unit = "оплата <phone> у @user по <card> для <name> в Acme "

    def of_size(size):
        return (unit * (size // len(unit) + 1))[:size]
    short, long = of_size(MESSAGE_LEN), of_size(4 * MESSAGE_LEN)
    assert_cost_ratio(lambda: scan.scan(short), lambda: scan.scan(long), 6, label="placeholders")


# --- verify scans each distinct (kind, text) pair once --------------------------------------

ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
CLIENT = RawUser(id=2, first_name="Иван", last_name="Петров")
POLICY = AnonPolicy(keep_terms=("Northwind",))


def build_dataset(tmp_path, texts):
    """Anonymize one supergroup of ``texts`` and write the dataset."""
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Northwind support",
                   participant_ids=(ME.id, CLIENT.id))
    store.put_chats([chat])
    store.put_users([ME, CLIENT])
    store.set_me_id(ME.id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=i, date=T0 + timedelta(minutes=i), sender_id=CLIENT.id,
                   sender_kind=SENDER_USER, text=text)
        for i, text in enumerate(texts, 1)])
    dataset = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), POLICY)
    out = tmp_path / "dataset"
    write_dataset(dataset, out, Output(timezone="Europe/Berlin"), {"output": {"timezone": "Europe/Berlin"}})
    return store, out


def leaks_of(store, out, tmp_path):
    report = verify(out, store, POLICY, tmp_path / "verify_report.json")
    return sorted((leak.kind, leak.match, leak.location) for leak in report.leaks)


def test_a_clean_dataset_stays_clean(tmp_path):
    store, out = build_dataset(tmp_path, ["не проходит оплата по заказу #4471", "ошибка ERR_TIMEOUT"])
    assert verify(out, store, POLICY, tmp_path / "verify_report.json").ok


def test_a_leak_repeated_in_a_transcript_and_its_chunk_copy_is_reported_at_both_locations(tmp_path):
    """Chunk files are verbatim copies of the transcripts, so the memo has
    their text already; every location must still reach the report."""
    store, out = build_dataset(tmp_path, ["звоните мне"])
    leaking = "перезвоните на +7 999 123 45 67"
    for path in (out / "transcripts", out / "chunks"):
        target = sorted(path.glob("*.md"))[0]
        target.write_text(target.read_text(encoding="utf-8") + "\n" + leaking, encoding="utf-8")
    phones = [leak for leak in leaks_of(store, out, tmp_path) if leak[0] == "phone"]
    assert len(phones) == 2, phones
    assert {leak[2].split("/")[0] for leak in phones} == {"transcripts", "chunks"}


def test_the_same_leaking_line_on_two_rows_is_reported_for_each_row(tmp_path):
    store, out = build_dataset(tmp_path, ["звоните мне"])
    rows = out / "messages.jsonl"
    leaking = json.dumps({"text": "перезвоните на +7 999 123 45 67"}, ensure_ascii=False)
    with open(rows, "a", encoding="utf-8") as fh:
        fh.write(leaking + "\n" + leaking + "\n")
    locations = [leak[2] for leak in leaks_of(store, out, tmp_path) if leak[0] == "phone"]
    assert len(locations) == 2 and len(set(locations)) == 2, locations


def test_the_kind_of_a_unit_stays_part_of_the_memo(tmp_path):
    """The same text is a name leak in a message and not in a transcript,
    which only quotes what the JSON files already audit."""
    store, out = build_dataset(tmp_path, ["звоните мне"])
    leaking = "писал Петров вчера"
    transcript = sorted((out / "transcripts").glob("*.md"))[0]
    transcript.write_text(transcript.read_text(encoding="utf-8") + "\n" + leaking, encoding="utf-8")
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": leaking}, ensure_ascii=False) + "\n")
    names = [leak for leak in leaks_of(store, out, tmp_path) if leak[0] == "name"]
    assert [leak[2].split(":")[0] for leak in names] == ["messages.jsonl"], names


def uncached_leaks(out, store, policy):
    """verify's loop as it reads without the memo: every unit scanned where
    it is found. The reference the memoized report must reproduce."""
    known = known_from_store(store, policy)
    url_policy = Scrubber(policy, Roster(keep_terms=tuple(known.keep_terms)))

    def make(subset):
        return LeakScanner(subset, url_allowed=lambda url: url_policy.url_placeholder(url) == url,
                           domain_allowed=lambda host: url_policy.domain_placeholder(host) == host,
                           custom_patterns=policy.custom_patterns)
    scanners = {
        verify_module._TEXT: make(known),
        verify_module._DISPLAY_NAME: make(dataclasses.replace(known, names=frozenset())),
        verify_module._COMPOSED: make(dataclasses.replace(known, names=frozenset(), titles=frozenset())),
    }
    leaks = []
    for path in sorted(p for p in Path(out).rglob("*") if p.is_file() and p.suffix in (".md", ".json", ".jsonl")):
        if path.name in ("README.md", "index.json"):
            continue
        for location, text, kind in verify_module._units(path, str(path.relative_to(out))):
            leaks.extend(scanners[kind].scan(text, location))
    return sorted((leak.kind, leak.match, leak.location) for leak in leaks)


def test_the_report_is_what_scanning_every_unit_separately_would_give(tmp_path):
    """The memo must change nothing but the number of scans."""
    store, out = build_dataset(tmp_path, ["звоните мне", "оплата не прошла"])
    leaking = "перезвоните на +7 999 123 45 67, писал Петров"
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        for _ in range(3):
            fh.write(json.dumps({"text": leaking, "note": leaking}, ensure_ascii=False) + "\n")
    for path in (out / "transcripts", out / "chunks"):
        target = sorted(path.glob("*.md"))[0]
        target.write_text(target.read_text(encoding="utf-8") + "\n" + leaking, encoding="utf-8")

    scans = []
    original = LeakScanner.scan

    def counted(self, text, location=""):
        scans.append((id(self), text))
        return original(self, text, location)
    verify_module.LeakScanner.scan = counted
    try:
        memoized = leaks_of(store, out, tmp_path)
    finally:
        verify_module.LeakScanner.scan = original
    assert memoized == uncached_leaks(out, store, POLICY)
    assert memoized, "the fixture must leak, or the comparison proves nothing"
    assert len(scans) == len(set(scans)), "a repeated unit was scanned twice"
    scanned = sorted(p for p in out.rglob("*") if p.is_file() and p.suffix in (".md", ".json", ".jsonl"))
    units = sum(1 for path in scanned if path.name not in ("README.md", "index.json")
                for _ in verify_module._units(path, str(path.relative_to(out))))
    assert len(scans) < units, (len(scans), units)
