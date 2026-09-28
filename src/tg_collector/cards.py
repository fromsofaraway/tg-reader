"""Bank card numbers: finding them in free text and masking them.

``find_cards(text, bins)`` returns the spans of card numbers in ``text`` with
their masked form ("424242**********": the BIN stays, everything else is a
star). ``mask_cards(text, bins)`` applies them. Both the scrubber and the
leak scanner use the same function, so whatever one masks the other flags.

A regular expression is not enough here: the same digits mean different
things depending on how they are grouped. Two phone numbers on adjacent
lines, a list of BINs, a date range, a column of amounts and "1500 <card>"
all contain 13-19 digits in a row. So the text is cut into *groups* of card
characters (digits and the characters people use to mask a card by hand),
and only windows of groups shaped like a card are considered:

* one contiguous group of 13-19 characters ("4242421234567890"), or
* groups of four with an optional shorter last group ("4242 4212 3456 7890",
  "4242 4212 3456 7890 123" for a 19-digit Maestro), or
* American Express' 4-6-5, or
* for a configured BIN only: a 4-4-4-4 card with missing spaces or one extra
  digit ("4242 4212 34567890", "42424212 34567890", "4242 4212 3456 78901").

A window is a card when it starts with one of the configured BINs (typos and
hand masks included) or, for all-digit windows, when it passes Luhn. A file
name separates its fields with '_', so a window may begin and end beside one
("file_4000000000000002.pdf", "4242424242424242_front.jpg") and a lone '_'
between two digits separates two numbers; such a window then needs a
configured BIN or a full 16-digit network number, because file names are full
of Luhn-valid timestamps and order numbers. Group
separators are one or two of: any Unicode space (never a line break), an
invisible joiner (zero-width joiner/non-joiner, word joiner, soft hyphen,
byte-order mark), any dash, or a dot; a spaced dash (" - ") also counts.
A single line break joins two groups only for a window that starts with a
configured BIN and has full four-character groups on both sides of the
break: a card split over two lines is far rarer than two phones on adjacent
lines, so only our own cards get that benefit. A "/" right after the number
("PAN/MM/YY", a URL path) does not hide the card; "12/27" after the groups is
an expiry, not a fifth group.

Digits of every script (full-width, Arabic-Indic, Devanagari, mathematical
bold ...) are folded to ASCII before matching so no rule can be dodged with
them. Folding keeps one code point per digit, so the offsets ``find_cards``
returns always refer to the text as given.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable

PLACEHOLDER_CARD = "<card>"  # only for a card whose BIN cannot be read

# Digits plus the characters people type when masking a card by hand. The
# class deliberately contains both Latin x/X and the look-alike Cyrillic х/Х
# ("4242 42хх хххх 1234" typed on a Russian keyboard); do not deduplicate.
_MASK_CHARS = "*xXхХ•●○#_"
_CARD_CHAR = f"[0-9{_MASK_CHARS}]"
# Invisible format characters that survive copy-paste between digit groups:
# zero-width non-joiner / joiner, word joiner, soft hyphen, byte-order mark.
_CF_JOINERS = "\u200c\u200d\u2060\u00ad\ufeff"
# Every Unicode space that is not a line break (a regex character-class fragment).
_SPACES = " \t\u00a0\u1680\u2000-\u200a\u200b\u202f\u205f\u3000"
_DASHES = "\u2010-\u2015\u2212\\-"
_SEP_CHAR = f"[{_SPACES}{_CF_JOINERS}{_DASHES}.]"
_SEP = f"(?:{_SEP_CHAR}{{1,2}}|[ \t\u00a0][{_DASHES}][ \t\u00a0])"  # one or two separators, or " - "
_LINE_SEP = r"[ \t]*\n[ \t]*"
# '_' is a word character, yet it separates the fields of a file name or an
# identifier, so a run may start and end beside one ("file_4000000000000002
# .pdf", "4242424242424242_front.jpg").
_RUN_START, _RUN_END = r"(?<![^\W_])", r"(?![^\W_])"
# "12/27" after a separator is an expiry, never a further card group.
_RUN = re.compile(
    _RUN_START + _CARD_CHAR + r"+(?:(?:" + _SEP + r"|" + _LINE_SEP + r")(?!\d{1,2}\s?/)" + _CARD_CHAR + r"+)*" + _RUN_END
)
# One group of card characters. A lone '_' between two digits separates two
# numbers ("id 1234567_4242424242424242", "79990001122_5105105105105100");
# beside another mask character it is part of a hand mask and stays in the
# group ("4242 42__ ____ 4242").
_HAND_MASK = _MASK_CHARS.replace("_", "")
_GROUP = re.compile(rf"(?:[0-9{_HAND_MASK}]|_(?!\d)|(?<!\d)_)+")
# A window that a '_' glues to a word is a card only with a configured BIN or
# a full 16-digit network number: file names are otherwise full of Luhn-valid
# timestamps and order numbers ("IMG_20240312150004.jpg",
# "order_1164840180091430", "photo_1710230400130.jpg").
_NETWORK_PAN = re.compile(r"4\d{15}|(?:5[1-5]|2[2-7]|6[025]|35)\d{14}")
# Exactly what mask_card emits (BIN plus 7-13 stars): our own output is never a card.
_OWN_MASK = re.compile(r"\d{6}\*{7,13}")


def _digit_table(first: int, last: int) -> dict[int, int]:
    return {
        cp: ord("0") + unicodedata.digit(chr(cp))
        for cp in range(first, last)
        if not 0x30 <= cp <= 0x39 and unicodedata.category(chr(cp)) == "Nd"
    }


# Decimal digits of every script. The BMP table keeps UTF-16 widths (one
# unit in, one unit out), so it may run before Telegram entity offsets are
# applied; astral digits are two UTF-16 units and are folded only afterwards.
_BMP_DIGITS = _digit_table(0, 0x10000)
_ASTRAL_DIGITS = _digit_table(0x10000, 0x20000)


@dataclass(frozen=True)
class CardSpan:
    start: int
    end: int
    masked: str


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def normalize_digits(text: str) -> str:
    """Non-ASCII decimal digits of the Basic Multilingual Plane become ASCII
    (same UTF-16 width, so entity offsets stay valid)."""
    return text.translate(_BMP_DIGITS)


def normalize_astral_digits(text: str) -> str:
    """Decimal digits outside the BMP (mathematical bold digits and the like)
    become ASCII. Changes UTF-16 widths: call it only after entity offsets
    have been applied."""
    return text.translate(_ASTRAL_DIGITS)


def _normalize(text: str) -> str:
    return normalize_astral_digits(normalize_digits(text))


def mask_card(surface: str) -> str:
    """Mask a card surface: "4242 4212 3456 7890" becomes "424242**********".
    The BIN (first six digits) stays, every other digit or mask character
    becomes '*'."""
    chars = "".join(_GROUP.findall(_normalize(surface)))
    if len(chars) < 12 or not chars[:6].isdigit():
        return PLACEHOLDER_CARD
    return chars[:6] + "*" * (len(chars) - 6)


def _card_shaped(groups: list[str]) -> bool:
    lengths = [len(g) for g in groups]
    total = sum(lengths)
    if not 13 <= total <= 19:
        return False
    if len(groups) == 1:
        return True
    if lengths == [4, 6, 5]:
        return True
    return all(n == 4 for n in lengths[:-1]) and 1 <= lengths[-1] <= 4


def _known_shaped(groups: list[str]) -> bool:
    """Missing-space typos of a 4-4-4-4 card, accepted for configured BINs
    only ("4242 4212 34567890", "42424212 34567890"): every group but the
    last is a multiple of four; the last may be 1-5 (5 = one extra digit).
    A list of six-digit BINs never matches."""
    lengths = [len(g) for g in groups]
    if len(groups) == 1:
        return True
    head, last = lengths[:-1], lengths[-1]
    if not all(n % 4 == 0 for n in head):
        return False
    # A short last group is a typo only while the card is still incomplete:
    # "4242424242424242 12" is a card and an unrelated number.
    return last % 4 == 0 or (sum(head) < 16 and 1 <= last <= 5)


def _known(joined: str, bins: tuple[str, ...]) -> bool:
    return joined[:6].isdigit() and any(joined.startswith(b) for b in bins)


def _is_card(groups: list[str], bins: tuple[str, ...], crosses_line: bool = False, glued: bool = False) -> bool:
    joined = "".join(groups)
    if not 13 <= len(joined) <= 19:
        return False
    if any(_OWN_MASK.fullmatch(g) for g in groups):
        return False  # a window touching our own output is never a card
    known = _known(joined, bins)
    if glued and not (known or _NETWORK_PAN.fullmatch(joined)):
        return False  # a number a file name glues to a word (see ``_NETWORK_PAN``)
    if crosses_line and not known:
        return False  # only our own cards may be split over two lines
    masked = sum(c in _MASK_CHARS for c in joined)
    if known and (masked or _card_shaped(groups) or _known_shaped(groups)):
        return True  # our card: typos, missing spaces and any hand-made mask still count
    if not _card_shaped(groups):
        return False
    if joined.isdigit():
        return luhn_ok(joined)
    # Hand-masked card of another issuer: BIN visible, at least four masked
    # positions, typed in card groups. Normalise it so the tail is hidden too.
    return len(groups) > 1 and joined[:6].isdigit() and masked >= 4


def _window_at(groups: list[str], pos: int, bins: tuple[str, ...], breaks: tuple[bool, ...],
               glued: tuple[bool, ...]) -> int | None:
    """End index of the longest card-like window starting at ``pos``, known
    BINs preferred. A card spans at most five groups (4-4-4-4-3), which keeps
    long digit tables linear. ``breaks[k]`` says whether a line break sits
    between groups k and k+1; a break next to a short group ends the window
    (a stray number on the next line is not a card tail). ``glued[k]`` says
    whether a '_' touches group k, which makes the window part of a file name
    or an identifier."""
    best = None
    for j in range(min(len(groups), pos + 5), pos, -1):
        crossing = [k for k in range(pos, j - 1) if breaks[k]]
        if any(len(groups[k]) < 4 or len(groups[k + 1]) < 4 for k in crossing):
            continue
        window = groups[pos:j]
        if not _is_card(window, bins, crosses_line=bool(crossing), glued=any(glued[pos:j])):
            continue
        if _known("".join(window), bins):
            return j
        if best is None:
            best = j
    return best


def _embedded_known_bin(group: str, bins: tuple[str, ...]) -> tuple[int, int] | None:
    """A 16-digit known-BIN card glued into a longer digit run ("1" + card)."""
    if not group.isdigit() or not 17 <= len(group) <= 25:
        return None
    for b in bins:
        k = group.find(b)
        while k != -1:
            if k + 16 <= len(group):
                return k, k + 16
            k = group.find(b, k + 1)
    return None


def find_cards(text: str, bins: Iterable[str] = ()) -> list[CardSpan]:
    """Card numbers in ``text`` as (start, end, masked) spans, left to right,
    non-overlapping. Offsets refer to ``text`` as given."""
    bins = tuple(b for b in bins if b.isdigit())
    norm = _normalize(text)
    spans: list[CardSpan] = []
    for run in _RUN.finditer(norm):
        # A card starts with its BIN, so a leading mask character ("#4242",
        # "•4242", "**4242") is a prefix or markdown, never part of it; a
        # trailing '*' is markdown too (trailing '#'/'x' are hand masks).
        r_start, r_end = run.start(), run.end()
        while r_start < r_end and norm[r_start] in _MASK_CHARS:
            r_start += 1
        while r_end > r_start and norm[r_end - 1] == "*":
            r_end -= 1
        segment = norm[r_start:r_end]
        groups = [(m.start() + r_start, m.end() + r_start, m.group(0)) for m in _GROUP.finditer(segment)]
        texts = [g[2] for g in groups]
        breaks = tuple("\n" in norm[groups[k][1]:groups[k + 1][0]] for k in range(len(groups) - 1))
        glued = tuple(norm[g[0] - 1:g[0]] == "_" or norm[g[1]:g[1] + 1] == "_" for g in groups)
        pos = 0
        while pos < len(groups):
            j = _window_at(texts, pos, bins, breaks, glued)
            if j is None:
                # One long digit run may hide a known-BIN card inside it.
                inner = _embedded_known_bin(texts[pos], bins)
                if inner is not None:
                    gs = groups[pos][0]
                    spans.append(CardSpan(gs + inner[0], gs + inner[1], mask_card(texts[pos][inner[0]:inner[1]])))
                pos += 1
                continue
            # A neighbouring number can form a card-shaped window that passes
            # Luhn by chance ("1500 6011 1111 1111" before the real card): mask
            # the union of overlapping windows so the true card's tail never
            # stays visible. Over-masking an amount is the lesser evil.
            k = pos + 1
            while k < j:
                j2 = _window_at(texts, k, bins, breaks, glued)
                if j2 is not None and j2 > j:
                    j = j2
                k += 1
            start, end = groups[pos][0], groups[j - 1][1]
            spans.append(CardSpan(start, end, mask_card(norm[start:end])))
            pos = j
    return spans


def mask_cards(text: str, bins: Iterable[str] = ()) -> tuple[str, list[CardSpan]]:
    """``text`` with every card masked, plus the spans that were masked."""
    spans = find_cards(text, bins)
    if not spans:
        return text, []
    out = []
    last = 0
    for span in spans:
        out.append(text[last:span.start])
        out.append(span.masked)
        last = span.end
    out.append(text[last:])
    return "".join(out), spans
