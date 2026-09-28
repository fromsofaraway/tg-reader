"""What the published source may contain.

The repository is public, so its own text is held to the rules the tool
applies to a chat: no value shaped like a live provider key, no real person,
company or identifier used as an example, no invisible character hiding in a
source line, and no internal review id or change history in a comment.

Every value this file hunts is joined from parts at import time, so the text
it searches for is never itself a line of the repository. Each rule sits next
to the behaviour that has to survive the fictional replacements.
"""

import ast
import io
import re
import tokenize
import unicodedata
from pathlib import Path

import pytest

from conftest import (
    AWS_ACCESS_KEY, BOT_TOKEN, GITHUB_PAT, GITLAB_PAT, GOOGLE_API_KEY, JWT, OPENAI_KEY,
    SENDGRID, SHOPIFY_TOKEN, STRIPE_LIVE, STRIPE_WEBHOOK, TWILIO_KEY, assert_cost_ratio,
    assert_fast, check,
)
from tg_collector.config import AnonPolicy
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BINS = ("424242", "400000", "510510")
NBSP = chr(0x00A0)

# Everything a reader of the published repository sees.
SOURCE_GLOBS = ("src/**/*.py", "tests/**/*.py", "docs/**/*.md", "README.md",
                "config.example.toml", "pyproject.toml", ".env.example")


def sources():
    """Every published text file, as (repository-relative path, contents)."""
    seen = []
    for pattern in SOURCE_GLOBS:
        for path in sorted(PROJECT_ROOT.glob(pattern)):
            if path.is_file():
                seen.append((path.relative_to(PROJECT_ROOT).as_posix(),
                             path.read_text(encoding="utf-8")))
    assert len(seen) > 30, len(seen)
    return seen


def hits(pattern, flags=0):
    """Every ``path:line: match`` the pattern finds in the published tree."""
    rx = re.compile(pattern, flags)
    found = []
    for rel, text in sources():
        for m in rx.finditer(text):
            found.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}: {m.group(0)[:60]}")
    return found


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS)))


# --- no value shaped like a live provider key ------------------------------------------------

# The shapes credential scanners and GitHub push protection match on. A
# literal of any of them in the source would be reported as a leaked key of a
# real account, whatever the file it sits in says about itself. The patterns
# are built from parts for the same reason as the fixtures.
SECRET_SHAPES = {
    "stripe-live": "sk_" + r"live_[0-9A-Za-z]{24,}",
    "stripe-webhook": "whs" + r"ec_[0-9A-Za-z]{32,}",
    "sendgrid": "S" + r"G\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "google-api": "AI" + r"za[0-9A-Za-z_-]{35}",
    "gitlab-pat": "gl" + r"pat-[A-Za-z0-9_-]{20}",
    "shopify": "shp" + r"at_[0-9a-f]{32}",
    "github-pat": "gh" + r"p_[A-Za-z0-9]{36}",
    "aws-access-key": "AK" + r"IA[0-9A-Z]{16}",
    "openai": "sk-" + r"proj-[A-Za-z0-9_-]{40,}",
    "twilio": "S" + r"K[0-9a-f]{32}",
    "telegram-bot": r"[0-9]{8,10}:" + "AA" + r"[0-9A-Za-z_-]{33}",
    "jwt": "ey" + r"J[A-Za-z0-9_-]{10,}\." + "ey" + r"J[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}",
}

SECRET_FIXTURES = {
    "stripe-live": STRIPE_LIVE, "stripe-webhook": STRIPE_WEBHOOK, "sendgrid": SENDGRID,
    "google-api": GOOGLE_API_KEY, "gitlab-pat": GITLAB_PAT, "shopify": SHOPIFY_TOKEN,
    "github-pat": GITHUB_PAT, "aws-access-key": AWS_ACCESS_KEY, "openai": OPENAI_KEY,
    "twilio": TWILIO_KEY, "telegram-bot": BOT_TOKEN, "jwt": JWT,
}


@pytest.mark.parametrize("name", sorted(SECRET_SHAPES))
def test_no_source_file_spells_a_provider_key_shape(name):
    """The fixtures are joined from invented parts at import time, so the
    shape exists at runtime and never in a line of the repository."""
    assert hits(SECRET_SHAPES[name]) == []


@pytest.mark.parametrize("name", sorted(SECRET_FIXTURES))
def test_the_runtime_fixture_still_has_the_shape_it_stands_for(name):
    """Splitting a value changed the source, not the value: each constant
    still matches the provider shape the rule under test must catch."""
    assert re.fullmatch(SECRET_SHAPES[name], SECRET_FIXTURES[name]), name


@pytest.mark.parametrize("name", ["stripe-live", "sendgrid", "google-api", "github-pat",
                                  "openai", "telegram-bot"])
def test_the_runtime_fixture_is_still_removed_and_flagged(scrub, scanner, name):
    value = SECRET_FIXTURES[name]
    raw = f"ключ: {value}"
    out = scrub(raw)
    assert value not in out and out != raw, out
    assert scanner.scan(raw), raw
    assert not scanner.scan(out), out


# --- no real person, company, identifier or card ---------------------------------------------

# Values that identify a real organisation or person, and payment-network
# test card BINs outside the documented list. The replacements are
# checksum-valid numbers in the unassigned 7700 tax office, fictional names,
# and the allowed BINs (424242, 400000, 510510, 520082, 601111, 353011).
FORBIDDEN = {
    "tax id of a real bank": ("7707", "083893"),
    "registration number of a real bank": ("10277", "00132195"),
    "personal tax id from a public example": ("5001", "00732259"),
    "tax id of a real carrier": ("7736", "050003"),
    "card number of unknown origin": ("22525", "38069560423"),
    "a routable public address": ("185.12", ".44.3"),
    "a living sportsman": ("Kap", "il Dev"),
    "a real steel company": ("Север", "сталь"),
    "a real writer": ("Лев ", "Толстой"),
    "a real marketplace": ("Wild", "berries"),
    "another real marketplace": ("Oz", "on.Ru"),
    "a real bank, in Russian": ("Сбер", "банк"),
    "a real bank, in Latin": ("Sber", "bank"),
    "Visa test BIN": ("4111", "11"),
    "Mastercard test card": ("5555", "5555554444"),
    "Amex test BIN": ("3782", "82"),
    "Discover test BIN": ("6759", "64"),
}


@pytest.mark.parametrize("what", sorted(FORBIDDEN))
def test_no_source_file_names_a_real_person_company_or_identifier(what):
    assert hits(re.escape("".join(FORBIDDEN[what]))) == [], what


@pytest.mark.parametrize("text,expected,kind", [
    ("ИНН 7700000425", "ИНН <tax-id>", "inn"),
    ("ИНН 770000000082", "ИНН <tax-id>", "inn"),
    ("ОГРН 1027700000041", "ОГРН <ogrn>", "ogrn"),
    ("5105 1005 0631 3114 1930 ок", "510510************** ок", "card"),
])
def test_the_fictional_identifiers_are_removed_like_the_real_ones(scrub, scanner, text, expected, kind):
    check(scrub, scanner, text, expected, kind)


@pytest.mark.parametrize("text", ["заказ 7700000425", "order_id=7700000425", "заявка: 7700000425"])
def test_the_fictional_identifiers_still_read_as_references(scrub, scanner, text):
    """Product knowledge: a reference label keeps the number, and the scanner
    stays silent on it."""
    check(scrub, scanner, text, text)


@pytest.mark.parametrize("text,expected", [
    ("Acme.Ru, Lutik.Ru, Vasilek.RU, ACME.ru, Acme.Io", "<domain>, <domain>, <domain>, <domain>, <domain>"),
    ("пишите на Ромашка.РФ", "пишите на <domain>"),
])
def test_the_fictional_hosts_are_removed_like_the_real_ones(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "domain")


# --- no invisible character in a source line --------------------------------------------------

# Format characters, non-ASCII spaces, private-use characters and combining
# marks are invisible in a diff and editors normalise them away, so a test
# that depends on one spells it as an escape.
INVISIBLE_CATEGORIES = ("Cf", "Zs", "Zl", "Zp", "Co", "Cs", "Mn", "Me")


def test_no_source_file_carries_an_invisible_character():
    strays = []
    for rel, text in sources():
        for i, ch in enumerate(text):
            if ch in (chr(10), chr(9), " "):
                continue
            if unicodedata.category(ch) in INVISIBLE_CATEGORIES:
                strays.append(f"{rel}:{text.count(chr(10), 0, i) + 1}: U+{ord(ch):04X}")
    assert strays == [], strays


@pytest.mark.parametrize("code", [0x00A0, 0x200B, 0x00AD, 0x0301])
def test_the_escaped_characters_are_the_characters_themselves(code):
    """Writing one of these as an escape changed no test input."""
    assert unicodedata.category(chr(code)) in INVISIBLE_CATEGORIES


def test_the_no_break_space_amount_fixture_still_carries_the_character():
    """The amount column that has to survive is separated by a no-break
    space, written as an escape and scrubbed as the character."""
    source = (PROJECT_ROOT / "tests" / "test_hardening_phones_ip_headers.py").read_text(encoding="utf-8")
    assert "1500.00" + chr(92) + "xa02300.50" in source
    amounts = "1500.00" + NBSP + "2300.50"
    assert Scrubber(AnonPolicy(), Roster()).scrub(amounts) == amounts


# --- comments describe behaviour, not an internal review --------------------------------------

def prose():
    """Every comment and docstring of the published Python files, as
    (repository-relative path, line, text).

    A fixture is not prose: a virtual user id in a transcript or a decline
    code in a message body is a value the rules are tested on, so only what a
    reader reads as English is searched here."""
    found = []
    for rel, text in sources():
        if not rel.endswith(".py"):
            continue
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                found.append((rel, token.start[0], token.string))
        for node in ast.walk(ast.parse(text, rel)):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc:
                    found.append((rel, getattr(node, "lineno", 1), doc))
    assert len(found) > 500, len(found)
    return found


def prose_hits(pattern, flags=0):
    rx = re.compile(pattern, flags)
    return [f"{rel}:{line}: {m.group(0)[:60]}"
            for rel, line, text in prose() for m in rx.finditer(text)]


def test_no_comment_cites_an_internal_review_id():
    """Section headers and docstrings name the behaviour they cover, not the
    review item that asked for it."""
    assert prose_hits(r"(?<![\w])(?:[UN][0-9]{1,3}|[a-z][a-z-]+#[0-9]+)(?![\w])") == []


def test_no_comment_tells_the_story_of_a_change():
    """Present-tense rules, not history: a reader of the published code has
    never seen the version a comment would compare against.

    The phrase for "not any more" is left out of this scan on purpose,
    because it also states a present fact about the data (an account that
    lost read access)."""
    story = "|".join(("us" + "ed to", "old" + "er versions", "pre" + "viously",
                      "add" + "ed by the review", "we " + "changed"))
    assert prose_hits(r"\b(?:" + story + r")\b", re.IGNORECASE) == []


# --- timing budgets catch backtracking, not machine load ---------------------------------------

def test_assert_fast_reports_a_catastrophic_pattern():
    """The budget is generous, so a passing timing test says nothing about
    the speed of the machine; an exponential pattern misses it anyway."""
    exponential = re.compile(r"(a|aa)+$")
    with pytest.raises(AssertionError):
        assert_fast(lambda: exponential.match("a" * 34 + "b"), budget=0.05, label="exponential")


def test_assert_fast_passes_a_linear_pattern():
    assert_fast(lambda: re.compile(r"a+$").match("a" * 4096), label="linear")


def quadratic(text):
    """Cost proportional to the square of the length: one match attempt per
    offset."""
    rx = re.compile(r"(?:a-)+b")
    return [rx.match(text, i) for i in range(len(text))]


def test_assert_cost_ratio_reports_a_quadratic_rule():
    small, large = "a-" * 2048, "a-" * 8192
    with pytest.raises(AssertionError):
        assert_cost_ratio(lambda: quadratic(small), lambda: quadratic(large), 8, label="quadratic")


def test_assert_cost_ratio_passes_a_linear_rule():
    small, large = "a-" * 2048, "a-" * 8192
    assert_cost_ratio(lambda: small.count("a"), lambda: large.count("a"), 8, label="linear")


# --- the shared two-direction assertion is the strict one ---------------------------------------

class _Reporting:
    """A scanner that reports a leak in every text it is given."""

    def scan(self, text):
        return [_Leak()]


class _Silent:
    def scan(self, text):
        return []


class _Leak:
    kind = "planted"


def test_check_fails_when_the_scanner_misses_what_the_scrubber_removed():
    with pytest.raises(AssertionError):
        check(lambda t: "<phone>", _Silent(), "89991234567", "<phone>")


def test_check_fails_when_the_scanner_flags_text_that_was_kept():
    """The weaker helper this one replaced passed such a case: it read the
    scanner only when the scrubber had changed something."""
    with pytest.raises(AssertionError):
        check(lambda t: t, _Reporting(), "заказ 4471", "заказ 4471")


def test_check_fails_when_the_output_still_carries_a_leak(scanner):
    with pytest.raises(AssertionError):
        check(lambda t: t, scanner, "карта 4242424242424242", "карта 4242424242424242")


def test_check_fails_on_the_wrong_kind():
    with pytest.raises(AssertionError):
        check(lambda t: "<phone>", _Reporting(), "89991234567", "<phone>", kind="card")


def test_check_passes_the_two_directions_it_is_meant_to_pass(scrub, scanner):
    check(scrub, scanner, "тел 89991234567", "тел <phone>", "phone")
    check(scrub, scanner, "заказ 4471", "заказ 4471")
