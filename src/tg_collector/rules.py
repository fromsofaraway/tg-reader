"""The shape of a scrubbing rule and helpers to build keyword-gated ones.

A ``Rule`` is a compiled pattern plus how to render a match. The scrubber
applies rules in table order over sentinel-protected text; the leak scanner
walks the same table to detect what the scrubber would have removed, so the
two can never disagree about a class of data.

``keyword_rule`` builds the most common domain shape: a trigger word ("cvv",
"пароль" = password, "ИИН" = Kazakh personal id) followed by a value, on the
same line or at the start of the next line. The pattern exposes the named
groups ``kw``, ``gap`` and ``val``; the scrubber replaces only ``val``, so
the keyword stays and the knowledge base still sees *what kind* of thing the
client mentioned, and anything already scrubbed inside the gap survives.
``holds_replacement`` and ``masked_card_spans`` tell both sides that a value
slot already holds an earlier replacement (a sentinel for the scrubber, a
placeholder or a masked card for the scanner), so neither re-scrubs nor
reports it. ``element_rule`` builds the same shape for an XML or SOAP
element, where the tag names the kind of value ("<Password>...</Password>").
``reads_as_identifier`` tells the secret rules that a long run is
an error constant, a REST path or a file or campaign slug rather than a
token, so both sides keep it. ``NUMBER_START`` / ``NUMBER_END`` are the word
boundaries of the number rules: '_' is no part of a phone, an account or a
document number, so a file name that glues one to words with it
("client_79161234567_report.xlsx") does not hide it. ``HANDLE_START``,
``USERNAME`` and ``MASKED_CARD`` are the shapes more than one layer has to
agree on: the scrubber removes them, and the rules that run before it have
to recognise the same text to stand back from it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

# The scrubber marks text it has already replaced with private-use sentinels
# (see ``scrub``). Character-class fragment of that range: a value class that
# must never reach into an earlier replacement excludes it.
NO_PUA = "\ue000-\ue1ff"
_SENTINEL_CHAR = re.compile(f"[{NO_PUA}]")

# "Пароль:\nQwerty123": the label ends its line and the value starts the next
# one. Exactly one line break, with punctuation only around it; a blank line
# or a sentence on the next line is out of scope on purpose.
_LINE_BREAK_GAP = r"[^\w\n<]{0,4}\n[^\w\n<]{0,4}"
# A file name or an identifier separates its fields with '_'
# ("scan_passport_4509123456.pdf", "inn_7700000425.pdf"). It is a word
# character, so by default it hides both the keyword and the value of a rule;
# ``keyword_rule(..., in_identifier=True)`` reads it as a boundary in front
# of the keyword and as the whole gap before the value.
_IDENTIFIER_GAP = "_"
# Word boundaries that treat '_' as a separator rather than a letter: the
# number rules use them so that a phone, account or document number glued
# into a file name is still one number ("client_79161234567_report.xlsx").
NUMBER_START = r"(?<![^\W_])"
NUMBER_END = r"(?![^\W_])"
# Between two digit groups of one number: a space, a hyphen, or the line
# break a messenger wrapped the number at ("СНИЛС 112-233\n445 95"). At most
# one break, with no blank line, so two numbers under each other stay two.
GROUP_SEP = r"(?:[ \-]|[ \t]*\n[ \t]*)?"
# A Telegram username without its '@': a Latin letter, then three to 31 more
# letters, digits or '_'. Shorter runs are ordinary words.
USERNAME = r"[A-Za-z][A-Za-z0-9_]{3,31}"
# The left boundary of a handle. Only a Latin letter, digit or '/' glued
# before '@' blocks it (the "user@host" and "node_modules/@scope" shapes); a
# Cyrillic word, '.', '@' or '_' does not. Every layer that has to recognise
# the same handles the scrubber removes - the password rules, the address
# noise filter - builds its pattern from these two.
HANDLE_START = r"(?<![A-Za-z0-9/])@"
# A bank card as the card layer renders it: the BIN and a mask
# ("424242**********"). ``cards`` tells its own output apart with a stricter
# class of its own (at least seven stars), so this one stays the loose shape
# every other layer has to stand back from.
MASKED_CARD = r"\d{6}\*{6,13}"

# A run of identifier characters this long is judged as a possible secret
# (``reads_as_identifier`` decides, for the ``b64_secret`` rule): at that
# length random entropy is likelier than a product name.
LONG_TOKEN_MIN = 40
# The characters of such a run. '/' is not one of them: a REST path is route
# structure, which the secret rules keep whole and read segment by segment.
_IDENTIFIER_CHAR = re.compile(r"[A-Za-z0-9+_-]")


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    placeholder: str
    # Extra validation of a match (checksums, context); None means "always".
    accept: Optional[Callable[[re.Match], bool]] = None
    # Replacement text for the whole match; default is ``placeholder``.
    render: Optional[Callable[[re.Match], str]] = None
    # The span of the match to replace, when the pattern has to take in more
    # than it removes: a phone shape matches a whole run of numbers, and only
    # the number in it becomes a placeholder. Absolute offsets into
    # ``m.string``; the rest of the match stays live text, as the ``val``
    # group of a keyword rule does. None means "the whole match".
    part: Optional[Callable[[re.Match], tuple[int, int]]] = None


def _inside_long_identifier(m: re.Match) -> bool:
    """Whether the value of ``m`` sits in a run of identifier characters long
    enough for the secret rules to take it whole
    ("passport_4510_123456_ivanov_ivan_1985_scan_final.jpg" becomes one
    <token>, the name in it included). Replacing only the number there would
    leave the rest of the run - a name, a login - in the text, so a keyword
    rule that reads file names stands back inside one."""
    text = m.string
    start, end = m.span("val")
    # The walk stops as soon as the run is long enough, so a line of glued
    # fields costs the same per match however long it is.
    while start > 0 and end - start < LONG_TOKEN_MIN and _IDENTIFIER_CHAR.match(text, start - 1):
        start -= 1
    while end < len(text) and end - start < LONG_TOKEN_MIN and _IDENTIFIER_CHAR.match(text, end):
        end += 1
    return end - start >= LONG_TOKEN_MIN


def _outside_long_identifier(accept: Optional[Callable[[re.Match], bool]]) -> Callable[[re.Match], bool]:
    return lambda m: not _inside_long_identifier(m) and (accept is None or accept(m))


def keyword_rule(name: str, keywords: str, value: str, placeholder: str, gap: str = r"[^\w\n<]{0,12}",
                 accept: Optional[Callable[[re.Match], bool]] = None, flags: int = re.IGNORECASE,
                 part: Optional[Callable[[re.Match], tuple[int, int]]] = None,
                 in_identifier: bool = False) -> Rule:
    """``keywords`` and ``value`` are regex fragments. The match keeps the
    keyword and the gap verbatim and replaces the value with ``placeholder``.
    The keyword never starts inside one of our own placeholders ("<otp>").
    ``part`` narrows the replacement inside the value slot when the value
    class has to take in more than it removes (see ``Rule.part``).
    ``in_identifier`` also finds the rule where a file name glues keyword and
    value together with '_' ("scan_passport_4509123456.pdf"): only classes
    whose keyword names a document or a number of its own carry it, so an
    ALL_CAPS product constant ("ERROR_CODE 4001") stays a constant, and
    inside a long identifier the rule stands back for the secret rules
    (``_inside_long_identifier``)."""
    # A closing tag is markup, never a keyword with a value after it
    # ("</passwordHash>"); the opening one is excluded by the '<' already.
    start = (r"(?<![^\W_]|<)" if in_identifier else r"(?<![\w<])") + r"(?<!</)"
    gaps = f"(?:{gap})|{_LINE_BREAK_GAP}" + (f"|{_IDENTIFIER_GAP}" if in_identifier else "")
    if in_identifier:
        accept = _outside_long_identifier(accept)
    pattern = re.compile(
        rf"(?P<kw>{start}(?:{keywords}))(?P<gap>{gaps})(?P<val>{value})",
        flags | re.UNICODE,
    )
    return Rule(name, pattern, placeholder, accept, lambda m: m.group("kw") + m.group("gap") + placeholder, part)


# The tag name of an XML or SOAP element, in front of the word that names
# the kind of value: an optional namespace, then an optional prefix that ends
# at '_', '-' or a camelCase boundary ("db_password", "MerchantLogin"), so
# "Spin" and "Shipping" are no tags of ours. The keyword ends the name, which
# leaves settings alone ("TokenType", "PinRequired", "LoginUrl").
_ELEMENT_PREFIX = r"(?:[A-Za-z][\w.-]*:)?(?:[A-Za-z][A-Za-z0-9]*(?:[_-]|(?-i:(?<=[a-z0-9])(?=[A-Z]))))?"
# The text between the tags: one line, no markup, and never reaching into an
# earlier replacement.
_ELEMENT_VALUE = rf"[^<>\s{NO_PUA}](?:[^<>\n{NO_PUA}]{{0,254}}[^<>\s{NO_PUA}])?"


def element_rule(name: str, tags: str, placeholder: str,
                 accept: Optional[Callable[[re.Match], bool]] = None) -> Rule:
    """A rule for the text of an XML or SOAP element whose tag name ends in
    one of ``tags`` ("<Password>Qwerty123</Password>", "<wsse:Password
    Type=...>...</wsse:Password>"). It exposes the same ``val`` group as
    ``keyword_rule``, so both sides replace the text and keep the markup, and
    the scanner reads a scrubbed element as the placeholder it holds. Our own
    output never puts a value between two tags, so the rule never fires
    twice on the same element."""
    pattern = re.compile(
        rf"<(?P<kw>{_ELEMENT_PREFIX}(?:{tags}))(?P<gap>(?:\s[^<>]*)?>\s*)"
        rf"(?P<val>{_ELEMENT_VALUE})\s*</(?P=kw)>", re.IGNORECASE | re.UNICODE)
    return Rule(name, pattern, placeholder, accept)


def value_group(m: re.Match) -> str:
    return m.group("val")


_MASKED_CARD = re.compile(MASKED_CARD)


def masked_card_spans(text: str) -> list[tuple[int, int]]:
    """Where ``text`` carries a masked card ("424242**********"). A value
    slot that reaches into one holds the card layer's own output, not a new
    value: the leak scanner reads scrubbed text, where the six visible BIN
    digits otherwise look like a one-time code or a PIN ("код:
    424242**********")."""
    return [m.span() for m in _MASKED_CARD.finditer(text)]


def holds_replacement(value: str) -> bool:
    """Whether a value slot already holds an earlier replacement instead of a
    new value: a resolved placeholder ("<url>", as the leak scanner sees it),
    a masked card ("424242**********") or, inside the scrubber, sentinels
    with nothing but quoting or punctuation around them ('"<sentinel>',
    '=<sentinel>'). Needed by value classes that accept any non-space
    character."""
    if value.startswith("<") or _MASKED_CARD.fullmatch(value):
        return True
    rest = _SENTINEL_CHAR.sub("", value)
    return rest != value and not any(c.isalnum() for c in rest)


# --- identifiers that are not secrets --------------------------------------------------

# One piece of an identifier between '_', '-', '.' and '/': a number, a short
# tag ("3ds", "2FA", "p2p"), an upper-case word with an optional glued number
# ("PAYMENT", "ERROR4001"), or a word or camelCase name with one ("By",
# "declined", "v2", "sha256", "PaymentV2Status"). A lone letter is not a
# piece (random tokens with many separators are full of them); a word is at
# most 24 letters, so a separator-free base32 or base36 secret never passes;
# every camelCase chunk starts with its capital, so matching stays linear.
_PLAIN_PIECE = re.compile(
    r"\d+|\d{1,4}(?:[a-z]{1,3}|[A-Z]{1,3})|[a-z]\d[a-z]|[A-Z]\d[A-Z]|[A-Z]{2,24}\d{0,8}"
    r"|(?:[A-Z][a-z]{1,24}|[a-z]{2,24}|[A-Za-z](?=\d))(?:[A-Z][a-z]{2,24}|[A-Z]\d{1,4})*\d{0,8}|")
_PIECE_SEPARATOR = re.compile(r"[_\-.]")
# A date, maybe with a time after a separator ("2026-03-12", "2026_03_12_14-30",
# "20260312_153000"), standing on its own: the one long number an identifier
# may carry. Glued to a word ("TXN20260312") it is an ordinary number.
_DATE_TIME = re.compile(
    r"(?<![A-Za-z0-9])(?:19|20)\d\d(?P<sep>[_\-.]?)[01]\d(?P=sep)[0-3]\d"
    r"(?:[_\-.T][0-2]\d[_\-.]?[0-5]\d(?:[_\-.]?[0-5]\d)?(?:[_\-.]\d{1,3})?)?(?![A-Za-z0-9])")
_GLUED_NUMBER = re.compile(r"\d{5}")
# Numbers of this many digits, split into groups or not, are phones, cards,
# accounts, tax and document numbers.
_LONG_NUMBER_DIGITS = 7
# Licence and activation keys: blocks of capitals and digits joined by '-'
# ("ABCDE-FGHIJ-KLMNO-PQRST").
_GROUPED_KEY = re.compile(r"[A-Z0-9]{4,8}(?:-[A-Z0-9]{4,8}){3,}")


def _hides_number(segment: str, whole_number_visible: bool) -> bool:
    """Whether one '/'-free segment carries a number that the phone, INN,
    account and document rules cannot see because it is glued to words
    ("inn_7700000425", "offer-79161234567-landing", "passport_4510_123456",
    "callback-8-916-123-45-67"). A segment that is only a number is seen by
    those rules between the slashes: ``whole_number_visible`` leaves it to
    them, otherwise one of seven or more digits counts as hidden too."""
    rest = _DATE_TIME.sub("#", segment)
    if rest.isascii() and rest.isdigit():
        return not whole_number_visible and len(rest) >= _LONG_NUMBER_DIGITS
    if _GLUED_NUMBER.search(rest):
        return True
    digits = 0
    for piece in _PIECE_SEPARATOR.split(rest):
        digits = digits + len(piece) if piece.isascii() and piece.isdigit() else 0
        if digits >= _LONG_NUMBER_DIGITS:
            return True
    return False


def reads_as_identifier(value: str, *, path_numbers_visible: bool = True) -> bool:
    """True when ``value`` is made only of words, numbers, versions and dates
    joined by '_', '-', '.' or '/': an error constant, a REST path, a file
    name or a campaign slug ("PAYMENT_DECLINED_INSUFFICIENT_FUNDS_4001",
    "/api/v2/merchants/12345/transactions/2026-03-12"). Such a value carries
    product knowledge, not secret entropy. False for anything with a piece
    that mixes letter cases and digits at random ("K7MDENG", "a8f3k2m9"),
    with '+' or '=', for a grouped licence key, and for a value that hides a
    phone, card, account or document number inside its words, so a secret
    rule still takes all of those whole.

    A number that fills a whole path segment ("/users/79161234567/") is left
    to the number rules by default: they see it between the slashes. A
    caller that wants no long number at all in an identifier passes
    ``path_numbers_visible=False``, and then such a segment of seven or more
    digits makes the value a non-identifier too."""
    if _GROUPED_KEY.fullmatch(value):
        return False
    for segment in value.split("/"):
        if _hides_number(segment, path_numbers_visible):
            return False
        if not all(_PLAIN_PIECE.fullmatch(piece) for piece in _PIECE_SEPARATOR.split(segment)):
            return False
    return True
