"""Text scrubbing and leak scanning.

Two modules share one pattern table so that whatever the scrubber removes,
the scanner knows how to detect:

``Scrubber(policy, roster).scrub(text, entities) -> str``
    Removes identifying data from a message text. Layers, in order:
    1. Telegram's own entities (exact UTF-16 offsets): mentions become stable
       virtual ids, emails/phones/cards/urls become placeholders. The rest of
       the text is then normalised (``plain_text``): invisible characters and
       Russian stress marks dropped, NFC composition.
    2. IBANs (checksum, also pinned to each country's own length), then bank
       cards (shape, Luhn or configured BIN, '_' in a file name included)
       with the expiry/CVV typed after them, written as fields of a dump or,
       anywhere in a message that carries a card, after "код" or "до".
    3. The shared rule table: proxies, links (also scheme-less "host/path"),
       unambiguous tokens, the domain rules of ``fintech`` (keyword-gated:
       only the value is replaced, the keyword and everything between stay
       live text for the later layers), then the generic classes: e-mails
       (also mistyped or obfuscated), handles (also glued to words, spaced,
       inflected or introduced by a keyword), Telegram Desktop copy-paste
       headers and companion lines, name + patronymic pairs (in capitals as
       well), tokens, IPs, Russian legal ids (INN/OGRN/SNILS, bank
       accounts), phones in every spelling; then every further copy of a
       number the message itself labelled as an identity
       (``Scrubber._repeat_identities``); then a participant's own number
       from their Telegram profile, in any digit grouping the scanner can
       see (``KnownPhones``, so the self-check can never abort on a phone);
       then bare domains become
       <domain> (a host that is only a keep term stays), known usernames
       become their virtual id, keep_terms are protected (except inside a
       longer known name or organisation term), and the operator's custom
       patterns run. Domains and usernames go before keep terms: a keep term
       inside a host or a username must not shield the rest of it. A link
       that policy keeps goes through the same layers after its host
       (``Scrubber._mask_inside_link``).
    4. Vocabulary sweep: numeric ids of known people and chats written bare,
       last names (or all names, per policy) of every known person,
       significant tokens of chat titles and custom organisation terms, with
       Cyrillic / Latin case folding, ё/е folding and a closed class of case
       endings (adjectival surnames decline in full, hyphenated ones in both
       halves); '_' and a following number count as word boundaries, and an
       ALL_CAPS product constant keeps an organisation term but never a
       person's name.
    Things that carry product knowledge (ticket numbers, error codes, version
    numbers, feature names, long error constants, REST paths and file names
    that read as identifiers) are deliberately left untouched, and
    ``keep_terms`` are never scrubbed on their own.

``LeakScanner(known).scan(text) -> list[Leak]``
    Finds identifying data that should not be present in the anonymized
    output: known raw ids, usernames (in the same three shapes the scrubber
    handles), the participants' own numbers (the spans ``KnownPhones`` finds,
    the very ones the scrubber removed), names, titles, bare
    domains, custom patterns, plus the same regex classes as above, over the
    same ``plain_text`` form. The scanned text carries resolved placeholders,
    so a rule never fires inside "<...>" or on a value slot that already
    holds one. Used both as a self-check right after scrubbing and by the
    ``verify`` command over the written dataset.

Replacements are inserted as private-use sentinels during processing so no
later layer (including user-supplied patterns) can match text produced by an
earlier one; the sentinels are resolved to their final form (``@U04217``,
``<email>`` ...) at the very end. Sentinels contain no word characters or
digits, so no regular expression over ``\\w``/``\\d`` can see inside them.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from operator import itemgetter
from typing import Any, Callable, Container, Iterable, NamedTuple, Optional, Sequence
from urllib.parse import urlsplit

from .cards import find_cards, mask_card, normalize_astral_digits, normalize_digits
from .config import AnonPolicy
from .fintech import (
    BARE_DOMAIN, CARD_CVV_RULE, CARD_EXPIRY_RULE, DOMAIN_TLDS, ELEMENT_RULES, FINTECH_RULES, PROXY_RULES,
    P as FINTECH_PLACEHOLDERS, not_operation_ref,
)
from .model import Entity
from .rules import (
    HANDLE_START, LONG_TOKEN_MIN, MASKED_CARD, NO_PUA, NUMBER_END, NUMBER_START, USERNAME, Rule as _Rule,
    keyword_rule, masked_card_spans, reads_as_identifier,
)

# Sentinel: U+E000 <index in PUA digits U+E100..U+E109> U+E001, all inside
# the private range that ``rules.NO_PUA`` names.
_S_OPEN, _S_CLOSE = "\ue000", "\ue001"
_PUA_DIGIT_BASE = 0xE100
_SENTINEL_RE = re.compile("\ue000([\ue100-\ue109]+)\ue001")
_PUA_RE = re.compile(f"[{NO_PUA}]")


def _encode_index(n: int) -> str:
    return "".join(chr(_PUA_DIGIT_BASE + int(d)) for d in str(n))


def _decode_index(s: str) -> int:
    return int("".join(str(ord(c) - _PUA_DIGIT_BASE) for c in s))


PLACEHOLDER_EMAIL = "<email>"
PLACEHOLDER_PHONE = "<phone>"
PLACEHOLDER_URL = "<url>"
PLACEHOLDER_TG = "<tg-link>"
PLACEHOLDER_IP = "<ip>"
PLACEHOLDER_IBAN = "<iban>"
PLACEHOLDER_TOKEN = "<token>"
PLACEHOLDER_NAME = "<name>"
PLACEHOLDER_ORG = "<org>"
PLACEHOLDER_USER = "@user"
PLACEHOLDER_ID = "<id>"
PLACEHOLDER_REDACTED = "<redacted>"
PLACEHOLDER_INN = "<inn>"
PLACEHOLDER_OGRN = "<ogrn>"
PLACEHOLDER_SNILS = "<snils>"
PLACEHOLDER_ACCOUNT = "<account>"
PLACEHOLDER_PASSPORT = "<passport>"

TG_HOSTS = frozenset({"t.me", "telegram.me", "telegram.dog", "telesco.pe"})

# Generic words that appear in chat titles without naming an organisation.
TITLE_STOPWORDS = frozenset("""
support саппорт поддержка техподдержка техническая chat чат группа group клиент client клиенты
clients team команда sales продажи продаж and the для ооо ао пао зао ип llc ltd inc gmbh corp
тех tech help помощь проект project integration интеграция продукт product общий general
общая info внедрение implementation onboarding партнер partner партнёр company компания
сервис сервисы карта карты карточки платежи платеж платёж выплаты выплата эквайринг биллинг
billing payments payouts cards api sdk crm erp бухгалтерия финансы отдел склад доставка
договор тариф тест test dev prod demo вопросы обсуждение канал channel новости
""".split())

# Words that only chat titles carry without naming an organisation. They are
# kept apart from TITLE_STOPWORDS because that set also tells the people
# vocabulary which words are not surnames, and "Старый", "Cash", "Merchant"
# or "Card" still are.
_TITLE_ONLY_STOPWORDS = frozenset(
    # Markers of a group that migrated to a supergroup ("Ромашка (old)").
    "old legacy archive archived архив старый старая старое".split()
    # Generic halves of company names and the core fintech and support
    # vocabulary ("Ромашка Групп", "Acme Pay", "Василёк Банк"): as organisation
    # terms they would remove "банк", "в группе" or "Apple Pay" from every
    # message. Cyrillic words also match in their case forms (see
    # ``generic_title_word``), so only forms the stems miss are listed.
    + """
    банк групп груп технологии технология медиа карт магазин магазина магазины маркет маркетплейс
    онлайн диджитал система систем системс софт финанс капитал холдинг студия лаборатория агентство
    экспресс обмен обменник крипто кошелек кошелёк казино трейд инвест бизнес центр сеть мобайл
    облако глобал интернешнл корпорация компани деньги денег кредит перевод процессинг мерчант
    терминал финтех займ брокер страхование логистика консалтинг такси авто туры официальный
    официальная официальные платформа телеком плюс про рус пэй пей служба решения партнеры партнёры
    клиентов сервисов проектов продуктов партнеров партнёров тарифов договоров платежей кредитов
    переводов займов терминалов магазинов
    bank banks pay payment payout card shop store stores market marketplace online digital system
    systems solutions solution software soft finance financial capital holding holdings studio lab
    labs agency express exchange crypto wallet casino games gaming trade trading invest investment
    business center centre network networks mobile cloud global international corporation limited
    plc ventures service services money cash credit transfer processing acquiring merchant terminal
    fintech loan broker insurance logistics consulting delivery taxi auto travel tour official media
    technologies technology platform telecom plus pro groups staff admin bot
    """.split()
    # The feature a chat is about, not the client it belongs to ("Ромашка -
    # вебхуки", "Василёк / Касса", "Лотос [прод]"). Such a title word would
    # otherwise erase that feature from every message of the export, which is
    # exactly the product knowledge the dataset is built for. Genitive plurals
    # in "-ов" are spelled out: an inflected form shaped like a surname is
    # never generic (see ``generic_title_word``).
    + """
    касса подключение вебхуки вебхуков возвраты возвратов подписки песочница миграция сверка
    отчеты отчёты отчетов отчётов чеки чеков фискализация ккт офд сбп 3ds прод кабинет личный
    оплата интернет холдирование рекуррентные автоплатежи сделка безопасная сплит
    webhook webhooks refund refunds subscription subscriptions sandbox checkout widget split
    sbp p2p b2b b2c h2h c2c pos nfc
    """.split()
    # Two-character letter+digit tokens that are product knowledge, not an
    # organisation: versions, support tiers, priorities, quarters and
    # half-years, display/network generations, the accounting software "1С".
    + [f"v{d}" for d in range(10)] + [f"l{d}" for d in range(1, 4)] + [f"t{d}" for d in range(1, 4)]
    + [f"т{d}" for d in range(1, 4)] + [f"p{d}" for d in range(5)] + [f"q{d}" for d in range(1, 5)]
    + "h1 h2 2d 3d 4k 3g 4g 5g 1c 1с".split()
)


# --- checksums ----------------------------------------------------------------------

def _inn_ok(d: str) -> bool:
    def ctrl(weights: list[int], digits: str) -> int:
        return sum(w * int(c) for w, c in zip(weights, digits)) % 11 % 10
    if len(d) == 10:
        return ctrl([2, 4, 10, 3, 5, 9, 4, 6, 8], d) == int(d[9])
    if len(d) == 12:
        return (ctrl([7, 2, 4, 10, 3, 5, 9, 4, 6, 8], d) == int(d[10])
                and ctrl([3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8], d) == int(d[11]))
    return False


def _ogrn_ok(d: str) -> bool:
    if len(d) == 13:
        return int(d[:12]) % 11 % 10 == int(d[12])
    if len(d) == 15:
        return int(d[:14]) % 13 % 10 == int(d[14])
    return False


def _snils_ok(d: str) -> bool:
    if len(d) != 11:
        return False
    total = sum((9 - i) * int(c) for i, c in enumerate(d[:9]))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        check = total % 101
        if check == 100:
            check = 0
    return check == int(d[9:])


# --- accept callbacks ----------------------------------------------------------------

def _digits(m: re.Match) -> str:
    return re.sub(r"\D", "", m.group(0))


def _is_inn(m: re.Match) -> bool:
    return _inn_ok(m.group(0)) and not_operation_ref(m)


def _is_ogrn(m: re.Match) -> bool:
    return _ogrn_ok(m.group(0)) and not_operation_ref(m)


def _is_snils(m: re.Match) -> bool:
    return _snils_ok(_digits(m))


_UNI_SPACE = "\u00a0\u2007\u2009\u200b\u202f"  # no-break, figure, thin, zero-width and narrow no-break spaces
_UNI_DASH = "\u2010-\u2015\u2212"  # typographic dashes and the minus sign
_THOUSANDS = re.compile(rf"\d{{1,3}}(?:[ {_UNI_SPACE}]\d{{3}})+")
_AMOUNT_RANGE = re.compile(rf"{_THOUSANDS.pattern}\s?[{_UNI_DASH}-]\s?{_THOUSANDS.pattern}")  # "10 000-20 000"
_CODE_LIST = re.compile(rf"\d{{5,}}(?:[\s{_UNI_DASH}.-]+\d{{5,}})+")  # "424242 400000": BINs, ids, order numbers side by side
_DATE_LIKE = re.compile(r"\d{4}[-./]\d{1,2}[-./]\d{1,2}|\d{1,2}[-./]\d{1,2}[-./]\d{4}")
# A bare 10-digit number is a phone only when the author labelled it as one
# ("мой номер 9991234567", "whatsapp 9991234567"); bare "номер"/"number"/
# "call" are left out on purpose (order numbers, "call ... failed"). The
# messenger name carries every colloquial Russian spelling ("ватсап",
# "вотсап", "вацап", "воцап", with a case ending). A keyword right after '<'
# is one of our own placeholders ("<phone> 1500.00 2300.50"), not a label the
# author typed, so it never turns the numbers after it into a phone.
_WHATSAPP = r"whatsapp|whats\s*app|[вw][ао][тц]с?апп?\w{0,3}"
_PHONE_CONTEXT = re.compile(
    r"(?:^|[^\w<])(?:"
    r"тел\w*|телефон\w*|(?:мой|ваш|его|её|ее|контактн\w*|рабоч\w*|личн\w*)\s+номер|номер\s+(?:тел\w*|для\s+связи)"
    rf"|моб\w*|сот\w*|phone|mobile|cell|{_WHATSAPP}|viber|вайбер|signal"
    r"|(?:пере|по)?звони\w*(?:\s+(?:мне|нам|по|на))?|call\s+(?:me|us|at)|(?:my|your|contact|phone|mobile|cell)\s+number"
    r")[^\w\n]{0,4}(?:is|это)?[^\w\n]{0,3}$", re.IGNORECASE)
# A phone word right behind the number instead of in front of it ("8999123.45
# 67 звоните"), for the one shape that needs a label on either side.
_PHONE_CONTEXT_AFTER = re.compile(
    rf"[^\w\n]{{0,3}}(?:(?:пере)?звон\w*|(?:на)?пиш\w*|тел\w*|моб\w*|{_WHATSAPP}|viber|вайбер)",
    re.IGNORECASE)
_PSEP = rf"[ \t{_UNI_SPACE}{_UNI_DASH}.-]"  # phone group separators: never a line break (two phones on two lines)
# The same separators with a dash that may carry spaces ("123 - 45 - 67"),
# which is how Russian numbers are often typed in chat.
_PSEP_SPACED = rf"(?:[ \t{_UNI_SPACE}]?[{_UNI_DASH}-][ \t{_UNI_SPACE}]?|{_PSEP})"
_PHONE_DBD = re.compile(rf"[78]{_PSEP}9(?:{_PSEP}\d){{9}}")  # "8 9 9 9 1 2 3 4 5 6 7"
_FIELD = re.compile(rf"[^\s{_UNI_SPACE}]+")
_AMOUNT_FIELD = re.compile(r"\d{3,}\.\d{2}")  # "1500.00", "123.45"
_SHORT_AMOUNT_FIELD = re.compile(r"\d{1,2}\.\d{2}")  # "92.50"; a phone may end in one ("+33 1 23 45 67.89")
# A Russian number keeps its shape whatever the separators: the trunk prefix
# with or without the area code glued to it ("8 495 123.45 67", "8-999
# 123.45 67"), or a bare mobile code ("999 123.45 67", "(999) 123.45 67").
_RU_HEAD = re.compile(r"[78](?:[-.]?\(?\d{3}\)?)?|\(?9\d\d\)?")
_RU_DIGITS = re.compile(r"[78]\d{10}|9\d{9}")


def _only_digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _plus_span(s: str, fields: list[re.Match]) -> tuple[int, int]:
    """The span of a run that carries a '+': one international number,
    unless the run went on into a statement column ("+380671234567
    1500.00", "+49 30 1234 5678 1500.00"). Then the number is the longest
    head in front of the first amount that holds 10-15 digits; a run without
    such a head is judged whole, so a spaced amount stays an amount ("+1 500
    000 руб")."""
    whole = (0, len(s))
    first_amount = next((i for i, f in enumerate(fields) if _AMOUNT_FIELD.fullmatch(f.group(0))), len(fields))
    if first_amount == len(fields) and len(_only_digits(s)) <= 15:
        return whole
    for end in range(first_amount, 0, -1):
        head = (0, fields[end - 1].end())
        if 10 <= len(_only_digits(s[:head[1]])) <= 15:
            return head
    return whole


def _phone_span(s: str, before: str) -> Optional[tuple[int, int]]:
    """The span of a phone-shaped run ``s`` to judge as a phone, or None when
    the run is amounts side by side, as pasted from a statement ("1500
    2300.50", "12 500.00 23 000", "4521 1500.00 12"). An amount is a field
    with two decimals (a short one only before another field).

    A Russian number with a stray dot is judged on its own wherever it sits
    in the run ("8 999 123.45 67"; "30 999 123.45 67" when the run starts on
    the minutes of "10:30"), and so is a complete phone in front of the
    first amount, which the run carried on into the amount ("999 123 4567
    1500.00"). The whole run is judged when it follows a phone word in
    ``before``. Only the span is replaced, so whatever the run swallowed
    around the number stays in the text."""
    fields = list(_FIELD.finditer(s))
    whole = (0, len(s))
    if len(fields) < 2:
        return whole
    if "+" in s:
        return _plus_span(s, fields)
    for start, first in enumerate(fields):
        if _RU_HEAD.fullmatch(first.group(0)):
            for end in range(len(fields), start + 1, -1):
                span = (first.start(), fields[end - 1].end())
                if _RU_DIGITS.fullmatch(_only_digits(s[span[0]:span[1]])):
                    return span
    for i, field in enumerate(fields):
        if _AMOUNT_FIELD.fullmatch(field.group(0)) or (i < len(fields) - 1
                                                       and _SHORT_AMOUNT_FIELD.fullmatch(field.group(0))):
            head = (0, fields[i - 1].end() if i else 0)
            if len(_only_digits(s[head[0]:head[1]])) >= 10:
                return head
            return whole if _PHONE_CONTEXT.search(before) else None
    return whole


def _phone_ok(s: str, before: str = "") -> bool:
    """Whether a phone-shaped run ``s`` is a phone number. ``before`` is the
    text preceding it, consulted for a phone keyword when the run is bare."""
    span = _phone_span(s, before)
    if span is None:
        return False  # amounts side by side
    s = s[span[0]:span[1]]
    digits = _only_digits(s)
    if not 10 <= len(digits) <= 15:
        return False
    # A bare run of digits (no +, no separators) is ambiguous with ids and
    # order numbers; only treat it as a phone in the common national shapes
    # or when the author labelled it as a phone.
    if s.isdigit():
        if len(digits) == 11 and digits[0] in "78":
            return True  # RU/KZ
        if len(digits) == 10 and digits[0] == "0":
            return True  # UA and other national formats with a trunk zero
        if len(digits) == 12 and digits[:3] in ("380", "375", "998", "996", "995", "374", "992", "993"):
            return True
        labelled = len(digits) == 10 or (len(digits) == 11 and digits[0] == "1")
        return labelled and bool(_PHONE_CONTEXT.search(before))
    if _PHONE_DBD.fullmatch(s):
        return len(set(re.findall(_PSEP, s))) == 1  # one consistent separator, not an enumeration
    if _THOUSANDS.fullmatch(s) or _AMOUNT_RANGE.fullmatch(s):
        return False  # a thousands-separated amount or a range of them
    if _CODE_LIST.fullmatch(s):
        return False  # two or more long codes side by side
    if _DATE_LIKE.search(s):
        return False  # a date with a four-digit year, maybe followed by a time
    return True


def _before(m: re.Match) -> str:
    """The text in front of a match, as far back as a keyword can reach."""
    return m.string[max(0, m.start() - 32):m.start()]


def _not_reference_number(m: re.Match) -> bool:
    """A number that '_' glues to the word in front of it is a phone only
    when that word is no operation label: a file name carries the number
    itself ("client_79161234567_report.xlsx"), an identifier a reference
    ("ticket_89991234567", "TXN_1234567890"). The checksum rules make the
    same distinction with ``not_operation_ref``."""
    return m.string[m.start() - 1:m.start()] != "_" or not_operation_ref(m)


def _is_phone(m: re.Match) -> bool:
    return _not_reference_number(m) and _phone_ok(m.group(0), _before(m))


def _is_amount_shaped_ru_phone(m: re.Match) -> bool:
    """A national shape whose own start reads as an amount ("8999123.45 67":
    a glued trunk prefix and a stray dot make a Russian number look like a
    sum of money). Only a phone word beside it decides, before the number as
    for ``_PHONE_AT_AMOUNT`` or right after it ("... звоните")."""
    return _not_reference_number(m) and bool(
        _PHONE_CONTEXT.search(_before(m)) or _PHONE_CONTEXT_AFTER.match(m.string, m.end()))


def _phone_part(m: re.Match) -> tuple[int, int]:
    """The span of a phone match to replace: the judged number alone, so an
    amount or a time the run swallowed stays ("<phone> 1500.00")."""
    span = _phone_span(m.group(0), _before(m))
    return (m.start() + span[0], m.start() + span[1]) if span else m.span()


def _is_keyword_phone(m: re.Match) -> bool:
    return _phone_ok(m.group("val"), m.group("kw") + " ")


def _keyword_phone_part(m: re.Match) -> tuple[int, int]:
    """``_phone_part`` for a keyword rule, whose value slot holds the run."""
    span = _phone_span(m.group("val"), m.group("kw") + " ")
    base = m.start("val")
    return (base + span[0], base + span[1]) if span else m.span("val")


def _is_labelled_phone(m: re.Match) -> bool:
    """A run that starts on an amount or a date: a phone only right after a
    phone word ("тел 1500.00 2300.50")."""
    before = _before(m)
    return _not_reference_number(m) and bool(_PHONE_CONTEXT.search(before)) and _phone_ok(m.group(0), before)


# A clock with a year in front or milliseconds behind ("12/Mar/2026:10:00:00"
# in an access log, "10:00:00:123"): four decimal groups without "::" are
# never an IPv6 address, which needs eight groups or "::".
_CLOCK_GROUPS = re.compile(r"(?:\d{1,4}:)?(?:[01]?\d|2[0-3]):[0-5]\d:[0-5]\d(?::\d{1,3})?")
# Loopback and the unspecified address name no host, as 127.x and 0.0.0.0 do
# not: "::1", "::0" and their written-out forms ("0:0:0:0:0:0:0:1").
_LOCAL_IPV6 = re.compile(r"(?:0{0,4}:){2,7}0{0,3}[01]")


def _is_ipv6(m: re.Match) -> bool:
    s = m.group(0)
    if _LOCAL_IPV6.fullmatch(s):
        return False
    if "::" in s or re.search(r"[a-fA-F]", s):
        return True
    return s.count(":") >= 3 and not _CLOCK_GROUPS.fullmatch(s)


# A dotted quad may be a version or a clause number, not an address, right
# after a version word, also glued into an identifier ("clientVersion:",
# "APP_VERSION=", '"version": "…"'), with at most one software word after it
# ("версия приложения 2.15.3.100", "версия конфигурации 3.0.150.25"), or
# right after a clause word ("пункт 4.1.2.3", "п. 4.1.2.3", "§ 4.1.2.3").
# ``_addresses_a_host`` then decides, because those words also stand in front
# of real addresses ("сервер сборки 10.0.0.5", "в разделе 10.0.0.1"): only
# the strict words can mean nothing but a version, while "сборка" and "релиз"
# name a machine as readily as a release.
_STRICT_VERSION_WORDS = (r"v|ver|versions?|\w*_version|(?-i:[a-z][A-Za-z]*Version)"
                         r"|верси\w*|build|билд\w*|firmware|прошивк\w*")
_VERSION_WORDS = rf"{_STRICT_VERSION_WORDS}|сборк\w*|release|релиз\w*"
_VERSIONED_WORDS = (r"приложени[яе]|app|клиента|client|sdk|сдк|прошивки|firmware|ос|os|ios|android"
                    r"|модул[яь]|module|плагина?|plugin|конфигураци[ия]")
_CLAUSE_WORDS = r"пункт[аеу]?|пп?\.|раздел[аеу]?|стать[яиюе]|ст\.|section|sec\.|clause|§|глав[аеуы]"
_CLAUSE_TAIL = rf"(?:{_CLAUSE_WORDS})[\s.№]*"
# The separators include quotes so that a JSON or YAML key counts as the
# version word before its value ('{"version": "2.15.3.100"}').
_SEP_CHARS = r"\s.:=\-—\"'"


def _version_tail(words: str) -> str:
    """One of ``words`` and what may follow it before the number itself."""
    return rf"(?:{words})(?:\s+(?:{_VERSIONED_WORDS}))?[{_SEP_CHARS}]*"


_VERSION_CONTEXT = re.compile(
    rf"(?:^|[^\w])(?:{_version_tail(_VERSION_WORDS)}|{_CLAUSE_TAIL})$", re.IGNORECASE)
_CLAUSE_CONTEXT = re.compile(rf"(?:^|[^\w]){_CLAUSE_TAIL}$", re.IGNORECASE)
_STRICT_VERSION = re.compile(rf"(?:^|[^\w]){_version_tail(_STRICT_VERSION_WORDS)}$", re.IGNORECASE)
# Weaker signals, trusted only for a version-shaped quad
# (``_reads_as_version``): an update verb with "до"/"to" ("обновитесь до
# 2.14.0.3"), or with a software word and "до"/"to"/"на" ("откатили
# приложение на 5.2.1.0"), or an app, platform or product name right before
# the quad ("приложение 2.15.3.100", "Android 14.0.0.1", "SDK 12.14.7.228").
# A network word never counts, and one earlier in the look-back cancels them:
# "обновите на ...", "IP обновили до ...", "сервер приложения ..." stay
# addresses.
_UPDATE_VERBS = r"updat\w*|upgrad\w*|обнов\w*|апдейт\w*|откат\w*|rollback|downgrad\w*"
# The object of the update verb, in the accusative ("обновите клиент до
# 2.14.0.3"). Deliberately not the same list as ``_VERSIONED_WORDS``, which
# is genitive because it follows a version word ("версия клиента"): the
# genitive "клиента" names the owner of an address as readily as of a
# release, so "обновите клиента на 8.8.8.8" stays an IP.
_UPDATED_WORDS = (r"приложени[ея]|app|клиент|client|sdk|сдк|прошивк[уи]|firmware|ос|os|ios|android"
                  r"|модул[ья]|module|плагина?|plugin|конфигураци[юи]")
# Platforms and products that number their releases in four parts, so a
# version-shaped quad right after one is a release ("Android 14.0.0.1",
# "SDK 12.14.7.228", "БП 3.0.150.25", "на 1С 8.3.24.120").
_PLATFORM_WORDS = (r"приложение|app|apk|ipa|ios|android|андроид|sdk|сдк|плагин\w*|plugin|модул[ья]|module"
                   r"|1с|1c|бп|зуп|унф|erp|бухгалтери\w*|битрикс|bitrix|платформ\w*")
_UPDATE_CONTEXT = re.compile(
    rf"(?:^|[^\w])(?:(?:{_UPDATE_VERBS})\s+(?:(?:the|our|your|ваше|наше)\s+)?(?:(?:{_UPDATED_WORDS})\s+(?:до|to|на)|до|to)"
    rf"|{_PLATFORM_WORDS})\s+$", re.IGNORECASE)
_NETWORK_WORDS = (r"ip|айпи|dns|днс|host\w*|хост\w*|server\w*|сервер\w*|address\w*|адрес\w*|gateway|шлюз\w*"
                  r"|proxy|прокси|whitelist|вайтлист\w*|firewall|vps|впс")
_NETWORK_WORD = re.compile(rf"(?<![^\W\d_])(?:{_NETWORK_WORDS})(?![^\W\d_])", re.IGNORECASE)
# A network word introducing the version or clause word turns the quad back
# into an address: "сервер сборки 10.0.0.5", "IP для релиза: 203.0.113.7",
# "машина для билдов 10.20.30.40". The version word then stands in an oblique
# case, which a version number is never introduced by.
_NETWORK_VERSION = re.compile(
    rf"(?<![^\W\d_])(?:{_NETWORK_WORDS}|стенд\w*|машин\w*|агент\w*)[ \t]+(?:(?:для|под|of|for)[ \t]+)?"
    r"(?:сборк[иуе]|сборок|релиз(?:а|у|ов)|билд(?:а|у|ов)|верси[йию]|раздел[ае]|builds?|releases?)"
    rf"[{_SEP_CHARS}№]*$", re.IGNORECASE)
# Only these parts make a clause number: a section is numbered from one, and
# a zero or a part above 99 in it is an address ("в разделе 10.0.0.1").
_CLAUSE_PART = range(1, 100)
# Loopback and the unspecified address name no host ("bind 0.0.0.0:8080",
# "localhost 127.0.0.1").
_LOCAL_IPV4 = re.compile(r"(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)(?::\d{1,5})?")
# Private and link-local ranges (10/8, 172.16/12, 192.168/16, 169.254/16)
# describe a customer's network and are scrubbed like any other address: no
# product numbers its releases that way ("подключитесь к 1С 10.0.0.5").
_PRIVATE_IPV4 = re.compile(r"(?:10|192\.168|169\.254|172\.(?:1[6-9]|2\d|3[01]))\.")


def _reads_as_version(quad: str) -> bool:
    """Whether the quad itself is shaped like a release number: a small major
    and no private network prefix."""
    return int(quad.split(".", 1)[0]) <= 30 and not _PRIVATE_IPV4.match(quad)


def _addresses_a_host(quad: str, before: str) -> bool:
    """Whether a quad standing in a version or clause context still names a
    host. A port ("прокси для сборки 203.0.113.7:3128") and a network word in
    front of the version word always say it does. Otherwise the number's own
    shape decides: a clause number is a list of small positive parts
    ("пункт 4.1.2.3"), and a release number has a small major unless a word
    that can only mean a version stands right in front of it."""
    if ":" in quad or _NETWORK_VERSION.search(before):
        return True
    if _CLAUSE_CONTEXT.search(before):
        return not all(int(part) in _CLAUSE_PART for part in quad.split("."))
    return not _reads_as_version(quad) and not _STRICT_VERSION.search(before)


def _is_ipv4(m: re.Match) -> bool:
    quad = m.group(0)
    if _LOCAL_IPV4.fullmatch(quad):
        return False
    before = m.string[max(0, m.start() - 48):m.start()]
    if _VERSION_CONTEXT.search(before):
        return _addresses_a_host(quad, before)
    weak = _reads_as_version(quad) and _UPDATE_CONTEXT.search(before)
    return not (weak and not _NETWORK_WORD.search(before))


# An identifier-shaped run still counts as a secret when it names one
# ("prod_secret_2024_backup_01"), is the login of a "login:password" pair, or
# stands right after a login, proxy or password word ("логин customer-acme-
# cc-RU-sessid-abcdef", "под логином ...", "curl -U ..."). Only the Russian
# forms that name the value count: "после логина" and "при смене пароля"
# ("after logging in", "on a password change") are followed by product
# identifiers. The word never starts inside one of our own placeholders
# ("<2fa-secret>", "@user"), so the leak scanner reads the output the way the
# scrubber read the input.
_SECRET_PIECES = frozenset({"secret", "token", "pass", "password", "passwd", "pwd", "apikey", "key", "private"})
_CREDENTIAL_BEFORE = re.compile(
    r"(?<![\w<@-])(?:логин(?:ом)?|login|user(?:name)?|юзер(?:ом)?|прокси|proxy|-U|пароль|паролем|pass(?:word)?"
    r"|secret)[^\w\n]{0,4}$", re.IGNORECASE)


def _is_secret(m: re.Match) -> bool:
    """A long base64-looking run with letters and digits is a secret unless
    it reads as an identifier (``rules.reads_as_identifier``): long error
    constants, REST paths and file or campaign slugs stay. An identifier with
    lower-case letters and no '/' is still a secret in a credential context.
    Only the run itself is judged; the password after it (``pw``) follows
    whatever verdict the run gets."""
    s = m.group("id")
    if not (re.search(r"\d", s) and re.search(r"[A-Za-z]", s)):
        return False
    if not reads_as_identifier(s):
        return True
    if "/" in s or not any(c.islower() for c in s):
        return False  # a REST path or an UPPER_SNAKE constant
    if any(piece.lower() in _SECRET_PIECES for piece in re.split(r"[_\-]", s)):
        return True
    text, end = m.string, m.end("id")
    if text.startswith(":", end) and text[end + 1:end + 2].strip():
        return True
    return _CREDENTIAL_BEFORE.search(text, max(0, m.start() - 24), m.start()) is not None


# A log line often ends in a bracketed stamp too ("ERROR, [2024-03-12
# 10:15:00]"), and its level would then be read as the sender of a pasted
# Telegram Desktop header. Only the shouted spelling is a level: "Error" is
# a name as readily as a level, and a real header carries a real name.
_LOG_LEVEL_RE = re.compile(r"TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRITICAL|FATAL|PANIC")


def _is_td_header(m: re.Match) -> bool:
    if _LOG_LEVEL_RE.fullmatch(m.group("who").strip()):
        return False
    stamp = m.group("stamp")
    return bool(re.search(r"\d{1,2}:\d{2}", stamp)) and bool(re.search(r"\d{1,2}\D\d{1,2}\D\d{2,4}|\d{4}", stamp))


# --- shared regex table ---------------------------------------------------------------

# A bracketed group is consumed whole so an IPv6 literal host
# ("http://[::1]:8000/x") or a bracketed query value stays one link; a
# ']' outside such a group still ends the link ("[see http://x/y]").
_TAIL = f"(?:\\[[^\\s<>\"')\\[\\]{NO_PUA}]*\\]|[^\\s<>\"')\\]{NO_PUA}])+"
_TLD = "(?:" + "|".join(DOMAIN_TLDS) + ")"
_HOST = rf"(?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.)+{_TLD}"
# Not a mail domain: a retina asset suffix ("arr@2x.png") or a package
# version ("lodash@4.17.21"); a four-part IP ("ivan@10.0.0.1") and any real
# suffix ("ivan@163.com") stay mail domains.
_NOT_MAIL_DOMAIN = r"(?!(?:\d(?:\.\d)?x\.(?:png|jpe?g|gif|webp|svg|avif)|\d+(?:\.\d+){1,2})(?![\w-]|\.[\w-]))"
_EMAIL = (r"(?<![\w.+-])[\w.+-]+@" + _NOT_MAIL_DOMAIN
          + r"[\w-]+(?:\.[\w-]+)+")  # left anchor keeps it linear on long words
# Typos around '@' and '.': one stray space, a comma for the dot, a missing
# TLD after a well-known mail host. A spelled-out dot must be followed by a
# lowercase TLD so a handle before a capitalised sentence stays prose.
_MAIL_HOSTS = r"(?:gmail|yandex|ya|mail|rambler|bk|inbox|list|icloud|outlook|hotmail|yahoo|protonmail|proton)"
_EMAIL_TYPO = (
    rf"(?<![\w.+-])[\w.+-]+ ?@ ?(?:[A-Za-z0-9-]+ ?[.,] ?)+(?-i:{_TLD})(?![\w])"
    rf"|(?<![\w.+-])[\w.+-]+@{_MAIL_HOSTS}(?![\w.-])"
)
# An address the sender's app wrapped at the '@': the local part ends one
# line and the domain starts the next. Without it the handle rule claims
# "@example" and leaves the local part standing. The local part must be
# ASCII, as e-mail local parts are, so an ordinary Russian word above a line
# that starts with "@" is not read as somebody's address ("спасибо" over
# "@mail.ru").
_WRAP = r"[ \t]*\n[ \t]*"
_EMAIL_WRAPPED = (rf"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._+-]{{0,63}}(?:{_WRAP}@[ \t]*|@{_WRAP})"
                  + _NOT_MAIL_DOMAIN + r"[\w-]+(?:\.[\w-]+)+")
# "ivan [at] mail [dot] ru", "ivan собака mail точка ru", "ivan @ mail.ru".
# A bare English "at" before a real dotted domain ("E1234 at api.pay.kz") is
# ordinary prose and is left to the bare-domain rule on purpose.
_LABEL = r"[a-z0-9а-я](?:[a-z0-9а-я-]{0,61}[a-z0-9а-я])?"
_OBF_LOCAL = r"(?<![\w.+-])[\w.+-]{1,64}(?<![.])"
_OBF_BR_AT = r"[ \t]*[\[({<][ \t]*(?:at|собака|сабака|dog)[ \t]*[\])}>][ \t]*"
_OBF_SP_AT = r"(?:[ \t]+@[ \t]*|[ \t]*@[ \t]+)"
_OBF_RU_AT = r"[ \t]+(?:собака|сабака)[ \t]+"
_OBF_EN_AT = r"[ \t]+(?:at|dog)[ \t]+"
_OBF_SP_DOT = r"(?:[ \t]*[\[({<][ \t]*(?:dot|точка|тчк)[ \t]*[\])}>][ \t]*|[ \t]+(?:dot|точка|тчк)[ \t]+)"
_OBF_ANY_DOT = rf"(?:\.|{_OBF_SP_DOT})"
_EMAIL_OBFUSCATED = (
    rf"{_OBF_LOCAL}(?:(?:{_OBF_BR_AT}|{_OBF_SP_AT}|{_OBF_RU_AT})(?:{_LABEL}{_OBF_ANY_DOT}){{1,3}}{_TLD}"
    rf"|{_OBF_EN_AT}{_LABEL}(?:{_OBF_ANY_DOT}{_LABEL})*{_OBF_SP_DOT}{_TLD})(?![\w.-])"
)
# Anchored so that a host merely ending in a Telegram host ("revolut.me") is not cut in two.
_TG_LINK = rf"(?<![\w.-])(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog|telesco\.pe)/{_TAIL}|(?<![\w])tg://{_TAIL}"
_URL = rf"(?<![\w])[a-z][a-z0-9+.-]{{1,10}}://{_TAIL}|(?<![\w@.])www\.{_TAIL}"
_BARE_LINK = rf"(?<![\w@/.\-]){_HOST}/{_TAIL}"  # "instagram.com/some_buyer": a host with a path is a link
# Telegram usernames are ASCII, so an ASCII boundary ends them; a short
# Cyrillic case ending glued to the handle ("@ivan_petrovу") is consumed.
# The ending must end the word itself: in "@some_buyerу2" the "у" belongs to
# the handle-like run, and eating it alone would leave "@user2", another
# handle, glued to the placeholder.
_USERNAME_END = r"(?![A-Za-z0-9_])(?:[а-яёА-ЯЁ]{1,3}(?![а-яёА-ЯЁA-Za-z0-9_]))?"
# A known username after '@' is caught anywhere by the roster; this rule
# takes the rest (``rules.HANDLE_START`` explains the left boundary).
_HANDLE = rf"{HANDLE_START}(?P<u>{USERNAME})" + _USERNAME_END
# "@ some_buyer_99": a blank after '@' is weaker evidence than a glued
# handle, so the name's minimum length is one character more than ``USERNAME``.
_HANDLE_SPACED = r"(?<![\w@./])@[ \u00a0](?P<u>[A-Za-z][A-Za-z0-9_]{4,31})\b"
# Messenger handles introduced by a keyword and written without '@'.
_HANDLE_KEYWORDS = (
    # "инст(а|е|у|ой|аграм…)" is Instagram; "инструкция", "инструмент",
    # "инстанс", "институт" and "инсталляция" are everyday support words and
    # never introduce a handle.
    r"skype|скайп|discord|дискорд|steam|стим|wechat|вичат|inst(?:a|agram)|инст(?!ру|итут|ан[сц]|ал)\w{0,7}"
    r"|vk|вк|fb|фб|facebook|фейсбук"
    r"|tiktok|тикток|tg|тг|telegram|телег\w{0,5}|ник(?:нейм)?|nick(?:name)?|username|юзернейм|юзер|handle|хендл|login|логин"
)
_HANDLE_GAP = r"[^\w\n<]{0,4}(?:в|in|on|у меня|мой|my)?[^\w\n<]{0,3}"
_BOT_TOKEN = r"(?<!\d)\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"  # secrets are exactly 35 chars and may end in '-'
_JWT = r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
_HEX_SECRET = r"\b[0-9a-fA-F]{32,}\b"
# A long identifier-shaped run, and the password it is the login of: the
# residential-proxy shape "customer-acme-cc-RU-sessid-abcdef-sesstime-10:Pa55w0rd"
# is one credential, not a token with a password left next to it. The tail
# stops at any character that continues the pair into something else (a host
# after '@', a second colon, a dashed word), which those rules then take.
_B64_SECRET = (rf"(?<![\w/+])(?P<id>[A-Za-z0-9+/_-]{{{LONG_TOKEN_MIN},}}={{0,2}})(?![\w/+=])"
               r"(?P<pw>:[^\s:@/<\"'-]{4,64}(?![\w:@]))?")
_IPV4 = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b(?::\d{1,5})?"
_IPV6 = r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{1,4}(?![\w:])"
# Telegram Desktop copy-paste: "Name, [12.03.2024 10:15]" and the companion
# lines "[Forwarded from Name]" / "[In reply to Name]" (also in Russian).
# The line's lead is kept as it is: indentation, and the "#12: " head the
# transcript puts before a merged message. The transcript indents every
# further line of a message, so the scanner reads "    <name>, [...]" and
# "    #12: <name>, [...]" as the scrubber's own output, while a real name
# after the same lead is still a header.
# A sentinel is allowed inside the name but not as its first character: a
# header whose name part also held a card or an entity link ("Пётр
# 4242424242424242, [...]") still names the person, while a line that is
# nothing but an earlier replacement ("<url>, [...]") is left alone.
_TD_HEADER = (r"^(?P<lead>[^\S\n]*(?:#\d{1,9}:[ \t]+)?)(?P<who>[^\s\[\]" + NO_PUA
              + r"][^\n\[\]]{0,63}?), \[(?P<stamp>[^\]\n]{5,40})\](?=[ \t]*\r?$)")
_TD_COMPANION = (r"^\[(?P<label>Forwarded from|In reply to|Переслано от|В ответ на)[ \t]+"
                 r"(?P<who>[^\]\n" + NO_PUA + r"][^\]\n]{0,79})\](?=[ \t]*\r?$)")
# "Иван Сергеевич", "Петров Иван Сергеевич": a given name with a patronymic
# identifies a person even when the surname is absent. Capitalisation is the
# signal (no IGNORECASE); a bare "-ич" is accepted only for the closed list of
# real patronymic stems, so "Москвич" or "Кирпич" never fire.
_CAP = r"[А-ЯЁ][а-яё]+"
_SURNAME_TAIL = (r"(?:ов|ев|ёв|ин|ын|ский|цкий|ова|ева|ёва|ина|ына|ская|цкая|ко|ук|юк|енко|ян|ич)"
                 r"(?:а|у|ым|ом|е|ой|ого|ому|им|ую)?")
_SURNAME = rf"[А-ЯЁ][а-яё]+{_SURNAME_TAIL}"
_MALE_PATR = r"[А-ЯЁ][а-яё]+(?:ович|евич)|(?:Иль|Кузьм|Лук|Фом|Никит|Савв)ич"
_FEMALE_PATR = r"[А-ЯЁ][а-яё]+(?:овн|евн|ичн)"
_PATR = rf"(?:(?:{_MALE_PATR})(?:а|у|ем|е)?|(?:{_FEMALE_PATR})(?:а|ы|е|у|ой))"
_NSP = r"[ \t\u00a0]+"
_PATRONYMIC = rf"(?<![\w-])(?:{_SURNAME}{_NSP})?{_CAP}{_NSP}{_PATR}(?:{_NSP}{_SURNAME})?(?![\w-])"
# The same run in capitals, as payment details and document copies print it
# ("ПЕТРОВ ИВАН СЕРГЕЕВИЧ"). Shouted prose is full of words that end like a
# female patronymic in an oblique case ("НА УРОВНЕ", "ОСНОВНОЙ", "РОВНЫ",
# "ЛОГИЧНЫ"), so a female one counts only in the nominative, and an "-ИЧНА"
# one only for the closed list of stems. The surname in front may be any
# word (payment details put it first, "КОВАЛЬ" has no surname ending); one
# after the patronymic needs a surname ending.
_UPPER = r"[А-ЯЁ]{2,}"
_UPPER_PATR = (rf"(?:{_UPPER}(?:ОВИЧ|ЕВИЧ)|(?:ИЛЬ|КУЗЬМ|ЛУК|ФОМ|НИКИТ|САВВ)ИЧ)(?:А|У|ЕМ|Е)?"
               rf"|{_UPPER}(?:ОВНА|ЕВНА)|(?:ИЛЬИН|КУЗЬМИН|ЛУКИН|ФОМИН|НИКИТ|САВВ)ИЧНА")
_PATRONYMIC_UPPER = (rf"(?<![\w-])(?:{_UPPER}{_NSP})?{_UPPER}{_NSP}(?:{_UPPER_PATR})"
                     rf"(?:{_NSP}{_UPPER}{_SURNAME_TAIL.upper()})?(?![\w-])")
# A '+' in front means a phone in international format, never a tax id.
# The tax number and the bank account read '_' as a boundary: a file name
# glues them to words ("inn_7700000425.pdf", "acc_40817810099910004312.pdf").
# OGRN keeps the ``\w`` boundary, because a 13-digit millisecond timestamp in
# a file name ("photo_1710230400130.jpg") passes its checksum as often as a
# registration number does; such a number is reached through its keyword.
_INN = NUMBER_START + r"(?<!\+)(?:\d{10}|\d{12})" + NUMBER_END
_OGRN = r"(?<![\w+])(?:\d{13}|\d{15})(?![\w])"
_SNILS = r"(?<![\w])\d{3}-\d{3}-\d{3}[ -]\d{2}(?![\w])"
# A supergroup or channel written the way bots and API logs spell it: the
# "-100" mark and the chat's own digits. Nothing else is shaped like that, so
# it names a chat even when the export never saw it, and the minus belongs to
# the id ("chat_id=-1001234567890" becomes "chat_id=<id>"). A decimal
# fraction is an amount, not an id.
_MARKED_CHAT_ID = r"(?<![\w.,-])-100\d{10,13}(?!\d|[.,]\d)"
_ACCOUNT = NUMBER_START + r"(?:30[12]|40\d|42\d|45\d|47\d)\d{17}" + NUMBER_END
# IBAN: any case, groups split by spaces or dashes, mod-97 checksum; a
# mistyped one is still caught right after the word "IBAN" / "ИИК".
_IBAN_SEP = rf"[ \t{_UNI_SPACE}{_UNI_DASH}-]"
_IBAN = (rf"(?<![A-Za-z0-9])[A-Za-z]{{2}}\d{{2}}(?:{_IBAN_SEP}?[A-Za-z0-9]{{4}}){{2,7}}"
         rf"(?:{_IBAN_SEP}?[A-Za-z0-9]{{1,4}})?(?![A-Za-z0-9])")
_IBAN_LOOSE = rf"[A-Za-z]{{2}}\d{{2}}(?:{_IBAN_SEP}?[A-Za-z0-9]{{2,4}}){{3,8}}(?![A-Za-z0-9])"
# Every country's IBAN has one fixed length. ``_IBAN`` only knows the shape,
# so where that length is a multiple of four it stops after the last full
# group and its optional short group swallows what follows ("KZ86125KZT
# 5004100100 KZT", "AT611904300234573201 EUR"): the checksum then fails on
# the currency code and the account stays in clear. ``_IBAN_EXACT`` pins the
# length per country, so such an account is found as well.
_IBAN_LENGTHS = {c: int(n) for c, n in (e.split(":") for e in """
    AD:24 AE:23 AL:28 AT:20 AZ:28 BA:20 BE:16 BG:22 BH:22 BI:27 BR:29 BY:28 CH:21 CR:22 CY:28 CZ:24 DE:22 DJ:27
    DK:18 DO:28 EE:20 EG:29 ES:24 FI:18 FK:18 FO:18 FR:27 GB:22 GE:22 GI:23 GL:18 GR:27 GT:28 HR:21 HU:28 IE:22
    IL:23 IQ:23 IS:26 IT:27 JO:30 KW:30 KZ:20 LB:28 LC:32 LI:21 LT:20 LU:20 LV:21 LY:25 MC:27 MD:24 ME:22 MK:19
    MN:20 MR:27 MT:31 MU:30 NI:28 NL:18 NO:15 OM:23 PK:24 PL:28 PS:29 PT:25 QA:29 RO:24 RS:22 RU:33 SA:24 SC:31
    SD:18 SE:24 SI:19 SK:24 SM:27 SO:23 ST:25 SV:28 TL:23 TN:24 TR:26 UA:29 VA:22 VG:24 XK:20 YE:30
    """.split())}
_IBAN_COUNTRIES = frozenset(_IBAN_LENGTHS)


def _iban_exact_pattern() -> str:
    """``_IBAN`` with the length pinned: one alternative per IBAN length,
    naming the countries of that length. Digits and letters stay grouped in
    fours as people write them, with an optional separator before each
    group and before the shorter last one."""
    by_length: dict[int, list[str]] = defaultdict(list)
    for country, length in _IBAN_LENGTHS.items():
        by_length[length].append(country)
    alternatives = []
    for length, countries in sorted(by_length.items()):
        groups, rest = divmod(length - 4, 4)
        tail = rf"(?:{_IBAN_SEP}?[A-Za-z0-9]{{{rest}}})" if rest else ""
        alternatives.append(rf"(?:{'|'.join(sorted(countries))})\d{{2}}"
                            rf"(?:{_IBAN_SEP}?[A-Za-z0-9]{{4}}){{{groups}}}{tail}")
    return rf"(?<![A-Za-z0-9])(?:{'|'.join(alternatives)})(?![A-Za-z0-9])"


_IBAN_EXACT = _iban_exact_pattern()


def _iban_ok(d: str) -> bool:
    """``d`` is the IBAN without separators, upper-cased."""
    if not 15 <= len(d) <= 34 or d[:2] not in _IBAN_COUNTRIES:
        return False
    return int("".join(str(ord(c) - 55) if c.isalpha() else c for c in d[4:] + d[:4])) % 97 == 1


def _is_iban(m: re.Match) -> bool:
    return _iban_ok(re.sub(r"[^A-Za-z0-9]", "", m.group(0)).upper())


# Phone shapes, all gated by ``_phone_ok``: "+cc d dd dd dd dd" (single-digit
# first group), "+cc" followed by single digits, RU/KZ digit by digit, and the
# common 2-5 digit groups. The trailing guard never stops in the middle of a
# run ('*' only guards a hand-masked card, ':' and '-' only a continuing
# digit run such as a time or a range) so markdown or punctuation right after
# the number does not hide it.
_PHONE_SHAPES = (
    rf"(?:\+[ \t]?\d{{1,3}}{_PSEP}\d{{1,2}}(?:{_PSEP}\d{{2,4}}){{3,4}}"
    rf"|\+[ \t]?\d{{1,3}}(?:{_PSEP}\d){{9,13}}"
    rf"|[78]{_PSEP}9(?:{_PSEP}\d){{9}}"
    rf"|(?:\+[ \t]?\d{{1,3}}{_PSEP}?|\b\d{{1,3}}{_PSEP}?)?\(?\d{{2,5}}\)?{_PSEP}?\d{{2,4}}{_PSEP}?\d{{2,4}}(?:{_PSEP}?\d{{2,4}})?)"
    rf"(?!\d|[^\W\d_]|\*[\d*]|[:\-{_UNI_DASH}]\d)"
)
# A decimal amount or a date that ends before a separator ("1500.00 ",
# "12.03 ", "12.03.2026 ", "2026-03-12 "). A run never starts on one: the
# amount or date stays, and a phone right after it is matched on its own
# instead of being swallowed into a rejected run ("1500.00 999 123 45 67").
# A dot phone ("8.999.123.45.67", "202.555.0143") goes on with a digit or a
# dot at that point. A run that does start there is a phone only after a
# phone word ("тел 1500.00 2300.50", "звоните 999.12 34 56 78").
_AMOUNT_HEAD = r"(?:\d{1,15}\.\d{2}|\d{1,2}[./]\d{1,2}[./]\d{4}|\d{4}[-./]\d{1,2}[-./]\d{1,2})(?![\d.])"
_PHONE_BODY = rf"(?!{_AMOUNT_HEAD}){_PHONE_SHAPES}"
# A number may start right after '_': that is how file names carry one
# ("client_79161234567_report.xlsx"). The word in front of the '_' still
# decides whether the number is a reference (``_not_reference_number``).
_PHONE = r"(?<![^\W_]|[.@-])" + _PHONE_BODY
_PHONE_AT_AMOUNT = rf"(?<![^\W_]|[.@-])(?={_AMOUNT_HEAD}){_PHONE_SHAPES}"
# A Russian or Kazakh number in national spelling, matched wherever it starts
# so that another number in front of it cannot swallow its head ("id 4521 999
# 123.45 67", "10:30 89991234567 1500.00"): the generic shapes above are
# tried on whole runs of numbers, and a run they reject hides the phone
# inside it. This shape spells out the trunk prefix, the area code and the
# 3-2-2 or 3-4 grouping, so it needs no further check: separators are
# optional after a trunk prefix ("8999123.45 67") and mandatory after a bare
# area code, which keeps amount columns ("1500.00 2300.50", "92.50 93.10")
# and thousands ("999 123 456") out; the area code starts on 3-9, the only
# Russian range, so ranges and enumerations of round numbers stay ("10 000 -
# 20 000", "ошибки 7 101 - 102 - 103"); and a '.' or ',' with a digit behind
# it ends the number, so a run that goes on into an amount is left to the
# generic shapes ("+7 999 123 1500.00").
_RU_TAIL = rf"\d{{3}}(?:{_PSEP_SPACED}?\d{{2}}{_PSEP_SPACED}?\d{{2}}|{_PSEP_SPACED}?\d{{4}})"
_RU_TAIL_SPLIT = rf"\d{{3}}(?:{_PSEP_SPACED}\d{{2}}{_PSEP_SPACED}\d{{2}}|{_PSEP_SPACED}\d{{4}})"
_RU_SHAPES = (
    rf"(?:(?:\+[ \t]?7|[78]){_PSEP_SPACED}?\(?[3-9]\d\d\)?{_PSEP_SPACED}?{_RU_TAIL}"
    rf"|\(?9\d\d\)?{_PSEP_SPACED}{_RU_TAIL}"
    rf"|\(?[3-8]\d\d\)?{_PSEP_SPACED}{_RU_TAIL_SPLIT})"
    rf"(?!\d|[^\W\d_]|\*[\d*]|[.,:\-{_UNI_DASH}]\d)"
)
_RU_PHONE = rf"(?<![^\W_]|[.@-])(?!{_AMOUNT_HEAD}){_RU_SHAPES}"
# The same shape where the number's own start reads as an amount, which a
# glued trunk prefix plus a stray dot produces ("8999123.45 67"): gated by a
# phone word beside it (``_is_amount_shaped_ru_phone``).
_RU_PHONE_AT_AMOUNT = rf"(?<![^\W_]|[.@-])(?={_AMOUNT_HEAD}){_RU_SHAPES}"
# "тел.89991234567": a phone glued to its keyword with punctuation.
_PHONE_KEYWORDS = rf"тел(?:ефон\w*)?|т|моб(?:ильн\w*)?|phone|mob(?:ile)?|{_WHATSAPP}|viber|вайбер|номер"

# The phone rules as one group: they sit in the table in this order, and the
# known-number layer runs them again over what it left of a run of digits.
_PHONE_RULES: tuple[_Rule, ...] = (
    keyword_rule("phone", _PHONE_KEYWORDS, _PHONE_BODY, PLACEHOLDER_PHONE, gap=r"(?:[^\w\n<+]|_){0,6}",
                 accept=_is_keyword_phone, part=_keyword_phone_part),
    # After the keyword rule, so a number glued to its keyword keeps its
    # trunk prefix ("тел.8 999 123 45 67"), and before the generic shapes,
    # which judge whole runs of numbers and would hide a phone inside one.
    _Rule("phone", re.compile(_RU_PHONE), PLACEHOLDER_PHONE, _not_reference_number),
    _Rule("phone", re.compile(_PHONE), PLACEHOLDER_PHONE, _is_phone, part=_phone_part),
    _Rule("phone", re.compile(_PHONE_AT_AMOUNT), PLACEHOLDER_PHONE, _is_labelled_phone, part=_phone_part),
    _Rule("phone", re.compile(_RU_PHONE_AT_AMOUNT), PLACEHOLDER_PHONE, _is_amount_shaped_ru_phone),
)

_LINK_RULES: tuple[_Rule, ...] = (
    _Rule("tg_link", re.compile(_TG_LINK, re.IGNORECASE), PLACEHOLDER_TG),
    _Rule("url", re.compile(_URL, re.IGNORECASE), PLACEHOLDER_URL),
    _Rule("url", re.compile(_BARE_LINK, re.IGNORECASE), PLACEHOLDER_URL),
)

_EMAIL_RULE = _Rule("email", re.compile("|".join((_EMAIL, _EMAIL_TYPO, _EMAIL_WRAPPED)), re.IGNORECASE),
                    PLACEHOLDER_EMAIL)
_BOT_TOKEN_RULE = _Rule("bot_token", re.compile(_BOT_TOKEN), PLACEHOLDER_TOKEN)
_JWT_RULE = _Rule("jwt", re.compile(_JWT), PLACEHOLDER_TOKEN)
_IBAN_RULE = _Rule("iban", re.compile(_IBAN), PLACEHOLDER_IBAN, _is_iban)
_IBAN_EXACT_RULE = _Rule("iban", re.compile(_IBAN_EXACT, re.IGNORECASE), PLACEHOLDER_IBAN, _is_iban)

# Unambiguous secrets go before the checksum-only id rules of ``fintech``: a
# 10-digit bot id passes the RNOKPP mod-11 check about one time in ten, and a
# checksum rule that fires first would leave the 35-character secret in clear.
_TOKEN_RULES: tuple[_Rule, ...] = (_BOT_TOKEN_RULE, _JWT_RULE)

# Applied before card detection: a spaced IBAN contains windows that pass
# Luhn by chance, and a half-masked IBAN would leak the rest.
_PRE_CARD_RULES: tuple[_Rule, ...] = (_IBAN_RULE, _IBAN_EXACT_RULE)

# An npm package scope ("@types/node") is not a handle. "@channel_name/123"
# and "@shop/reels" are handles, so the scope shape counts only inside an
# npm, npx, pnpm or yarn command or a node_modules path.
_NPM_SCOPE_TAIL = re.compile(r"/[a-z0-9][a-z0-9._-]*(?![A-Za-z0-9])")
_NPM_COMMAND = re.compile(r"(?<![\w-])(?:npm|npx|pnpm|yarn)(?:[ \t]+[A-Za-z0-9_@/.:=^~+-]+)*[ \t]+$", re.IGNORECASE)


def _npm_scope(text: str, start: int, end: int) -> bool:
    """Whether ``text[start:end]`` ("@types") is the scope of an npm package
    name: a lowercase package name follows after '/', and the scope is an
    argument of a package manager command or part of a node_modules path."""
    if not _NPM_SCOPE_TAIL.match(text, end):
        return False
    before = text[max(text.rfind("\n", 0, start) + 1, start - 120):start]
    return before.endswith("node_modules/") or _NPM_COMMAND.search(before) is not None


def _is_handle(m: re.Match) -> bool:
    return not _npm_scope(m.string, m.start(), m.end("u"))


def _is_spaced_handle(m: re.Match) -> bool:
    """"@ some_buyer_99" is a handle; "decline 05 @ Stripe" is prose."""
    h = m.group("u")
    return "_" in h or any(c.isdigit() for c in h)


def _is_bare_handle(m: re.Match) -> bool:
    """A keyword-introduced handle: field-like ("инста: x") or handle-shaped
    (digits, '_', '.', '#'); "username taken" and "login error" are prose."""
    v, gap = m.group("val"), m.group("gap")
    if re.fullmatch(r"U\d+|user", v):
        # Our own placeholders (verify runs the same table). A chat's id is
        # only ever rendered with '@', so a bare "логин: C12345" is a login.
        return False
    if any(ch in gap for ch in ":="):
        return True
    return any(c.isdigit() or c in "_.#" for c in v)


# A pasted Telegram Desktop header names a person whatever else the name part
# spells. The rules run before every other layer because their `who` group
# stops at a sentinel: once a handle, an address or a card inside the name has
# been replaced, the header no longer reads as one and the name survives.
_TD_RULES: tuple[_Rule, ...] = (
    _Rule("td_header", re.compile(_TD_HEADER, re.MULTILINE), PLACEHOLDER_NAME, _is_td_header,
          lambda m: f"{m.group('lead')}{PLACEHOLDER_NAME}, [{m.group('stamp')}]"),
    _Rule("td_companion", re.compile(_TD_COMPANION, re.MULTILINE | re.IGNORECASE), PLACEHOLDER_NAME, None,
          lambda m: f"[{m.group('label')} {PLACEHOLDER_NAME}]"),
)

_GENERIC_RULES: tuple[_Rule, ...] = (
    _Rule("email_obfuscated", re.compile(_EMAIL_OBFUSCATED, re.IGNORECASE), PLACEHOLDER_EMAIL),
    _EMAIL_RULE,
    _Rule("handle", re.compile(_HANDLE), PLACEHOLDER_USER, _is_handle),
    _Rule("handle_spaced", re.compile(_HANDLE_SPACED), PLACEHOLDER_USER, _is_spaced_handle),
    _Rule("patronymic", re.compile(_PATRONYMIC), PLACEHOLDER_NAME),
    _Rule("patronymic", re.compile(_PATRONYMIC_UPPER), PLACEHOLDER_NAME),
    _Rule("hex_secret", re.compile(_HEX_SECRET), PLACEHOLDER_TOKEN),
    _Rule("b64_secret", re.compile(_B64_SECRET), PLACEHOLDER_TOKEN, _is_secret,
          lambda m: FINTECH_PLACEHOLDERS["credentials"] if m.group("pw") else PLACEHOLDER_TOKEN),
    _Rule("ipv4", re.compile(_IPV4), PLACEHOLDER_IP, _is_ipv4),
    _Rule("ipv6", re.compile(_IPV6), PLACEHOLDER_IP, _is_ipv6),
    _IBAN_RULE,
    _IBAN_EXACT_RULE,
    keyword_rule("iban", r"iban|ибан|иик", _IBAN_LOOSE, PLACEHOLDER_IBAN,
                 gap=r"[^\w\n<]{0,6}(?:№|#|no\.?)?[^\w\n<]{0,3}"),
    _Rule("snils", re.compile(_SNILS), PLACEHOLDER_SNILS, _is_snils),
    # Before the numeric identity rules: a marked chat id is 13 to 16 digits
    # and would otherwise pass for a registration number.
    _Rule("chat_id", re.compile(_MARKED_CHAT_ID), PLACEHOLDER_ID),
    _Rule("account", re.compile(_ACCOUNT), PLACEHOLDER_ACCOUNT),
    _Rule("ogrn", re.compile(_OGRN), PLACEHOLDER_OGRN, _is_ogrn),
    _Rule("inn", re.compile(_INN), PLACEHOLDER_INN, _is_inn),
    *_PHONE_RULES,
    keyword_rule("kw_handle", _HANDLE_KEYWORDS, r"(?<![@\w])(?:live:)?[A-Za-z][\w.#-]{2,40}[\w#]", PLACEHOLDER_USER,
                 gap=_HANDLE_GAP, accept=_is_bare_handle),
)

# Order: pasted chat headers (their name part must be read whole), then
# proxies (credentials disguised as links), then links as a whole (an
# explorer URL is one <url>, not <url><txid>), then unambiguous tokens, then
# XML elements (a keyword rule would read the markup around the value as its
# own gap), then the domain rules (more specific than the generic ones: a
# credential dump before its e-mail, a wallet before "some long token"), then
# everything else.
_RULES: tuple[_Rule, ...] = (*_TD_RULES, *PROXY_RULES, *_LINK_RULES, *_TOKEN_RULES, *ELEMENT_RULES, *FINTECH_RULES,
                             *_GENERIC_RULES)

# Rules that read a number as somebody's identity rather than as a reference
# to an operation. Wherever else the message spells that same number it is
# the same identity (``Scrubber._repeat_identities``); a shorter number
# repeats itself by chance too often to follow.
_IDENTITY_RULES = frozenset({"by_id", "inn", "kg_pin", "kz_id", "ogrn", "passport", "snils", "tax_id", "ua_rnokpp"})
_IDENTITY_MIN_DIGITS = 8

# Same-width folding of full-width punctuation keeps UTF-16 widths, so it
# runs before entity offsets are applied; ``plain_text`` changes widths and
# runs after them.
_FULLWIDTH_PUNCT = {0xFF20: "@", 0xFF0E: "."}
# Format characters that carry no meaning in the text we scrub and hide
# identifiers from the rules ("Пет\u00adров"): soft hyphen, combining grapheme
# joiner, Arabic letter mark, Mongolian vowel separator, zero-width space and
# non-joiner, bidi marks, embeddings, overrides and isolates, word joiner,
# invisible operators, byte-order mark.
_INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u061c\u180e\u200b\u200c\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]")
# A zero-width joiner or a variation selector only between two letters or
# digits: inside emoji sequences ("\U0001f468\u200d\U0001f4bb", "5\ufe0f\u20e3")
# they stay.
_GLUE_RE = re.compile("(?<=[^\\W_])[\u200d\ufe00-\ufe0f]+(?=[^\\W_])")
# Russian stress marks (acute, grave) on a Cyrillic letter: "Рома\u0301шка".
# A breve or diaeresis typed before or after the stress stays, so a
# decomposed "й"/"ё" still composes.
_STRESS_RE = re.compile("(?<=[\u0400-\u04ff])([\u0306\u0308]?)[\u0300\u0301]+")
# A digit typed as a keycap emoji: the digit, an optional variation selector
# and the combining enclosing keycap ("8\ufe0f\u20e3").
_KEYCAP = "\\d\ufe0f?\u20e3"
# Five or more keycap digits in a row spell a number rather than decoration,
# so the keycaps are folded away and the phone rules see the digits they
# hold. The separators between them are the ones a number is typed with,
# bounded and without a line break, which keeps the run linear. A shorter
# run keeps its keycaps, so an emoji-numbered list ("1\ufe0f\u20e3 Оплата")
# and a shouted year stay as written.
_KEYCAP_RUN_RE = re.compile(f"{_KEYCAP}(?:[ ().\\-]{{0,4}}{_KEYCAP}){{4,}}")
_KEYCAP_MARK_RE = re.compile("\ufe0f?\u20e3")


def plain_text(text: str) -> str:
    """The text as the rule table sees it: astral digits folded, invisible
    characters, joiners between letters and Russian stress marks dropped, a
    run of keycap digits folded to the number it spells, then canonically
    composed (NFC), so a macOS file name with a decomposed "ё" or "й" equals
    the roster term. It changes UTF-16 widths, so the scrubber applies it
    after the entity layer; the scanner applies it to every text it checks,
    and ``fold`` / the term patterns to every term, so all of them compare
    the same string."""
    if text.isascii():
        return text
    text = _GLUE_RE.sub("", _INVISIBLE_RE.sub("", normalize_astral_digits(text)))
    text = _KEYCAP_RUN_RE.sub(lambda m: _KEYCAP_MARK_RE.sub("", m.group()), text)
    return unicodedata.normalize("NFC", _STRESS_RE.sub(r"\1", text))


# A masked card followed by an unmasked expiry/CVV is a leak by definition.
_MASKED_CARD_TRAILER: re.Pattern  # defined below _CARD_TRAILER
# Our own placeholders as they appear in scrubbed text ("<otp>", "<url:host>").
_PLACEHOLDER_RE = re.compile(r"<(?P<word>[a-z0-9-]+)(?::[^<>\s]+)?>")
# The word of each placeholder the scrubber writes ("wallet" in "<wallet>"):
# a name or organisation term that equals one ("Acme Token") must not flag
# the placeholder, while a kept host ("<url:romashka.ru>") is still scanned.
_OWN_PLACEHOLDER_WORDS = frozenset(p.strip("<>") for p in (
    *FINTECH_PLACEHOLDERS.values(), *(r.placeholder for r in (*_RULES, CARD_CVV_RULE, CARD_EXPIRY_RULE)),
    PLACEHOLDER_NAME, PLACEHOLDER_ORG, PLACEHOLDER_ID, PLACEHOLDER_REDACTED, "<card>", "<domain>", "<sub>",
) if p.startswith("<"))
# A virtual id as the scrubber writes it after '@': a person ("@U04217") or
# an exported chat named by its public username ("@C01735").
_VID = r"[UC]\d+"
_VID_TAIL_RE = re.compile(r"@[UC]\d*$")
_VID_HEAD_RE = re.compile(rf"{_VID}(?![A-Za-z0-9_])")
# The scanner's view of the scrubber's own handle output: a virtual id or
# "@user" (a case ending may follow), and a virtual id inside a file name
# ("scan_@U04217.pdf") that the e-mail shape would otherwise take.
_OWN_HANDLE_RE = re.compile(rf"@(?:user|{_VID})[а-яёА-ЯЁ]{{0,3}}")
_VID_IN_FILE_NAME_RE = re.compile(rf"@{_VID}(?![\w])")
# Candidate phone runs for the known-number scan: digits with any separators
# people use, including typographic dashes.
_SCAN_PHONE_RUN = re.compile(r"\+?\d(?:[\s().\-\u2010-\u2015\u2212]*\d){6,}")
# How much of a run in front of a known number still belongs to it: a country
# code and a trunk prefix, at most ("79161112233" written as "8 916 111-22-33").
_PHONE_PREFIX_DIGITS = 3


class KnownPhones:
    """The participants' own numbers from their profiles, and where a text
    spells one of them. The scrubber replaces those spans and the leak
    scanner reports them, so the two can never disagree about a number a
    person gave Telegram.

    A number counts as stored (E.164 digits) and as its national significant
    number, so "8 999 123 45 67" and "999 123 45 67" name the same person as
    "+7 999 123 45 67". The digit strings are indexed by length: a text is
    checked in a few set lookups per digit however many numbers are known,
    where comparing each number against each run would make a verify run
    over a whole export grow with the number of participants.
    """

    def __init__(self, phones: Iterable[str]):
        known = [p for p in phones if len(p) >= 7]
        self._forms = frozenset(known) | {p[-10:] for p in known if len(p) >= 11}
        self._lengths = sorted({len(f) for f in self._forms})

    def spans(self, text: str) -> list[tuple[int, int]]:
        """The spans of ``text`` that spell a known number, whatever
        separators the author used and wherever the number sits inside a
        longer run of digits ("tx 79161112233000", "wa.me/79161112233",
        "scan_89161112233.pdf"). Each run of digits and separators is
        collapsed to its digits, the numbers are looked for inside it, and a
        hit is mapped back to text offsets; a country or trunk prefix in
        front of the hit belongs to the number, so "8 916 111-22-33" becomes
        one placeholder and not "8<phone>". Spans never overlap."""
        if not self._forms:
            return []
        spans: list[tuple[int, int]] = []
        for run in _SCAN_PHONE_RUN.finditer(text):
            at = [i for i, ch in enumerate(run.group(0)) if ch.isdigit()]
            digits = "".join(run.group(0)[i] for i in at)
            for n in self._lengths:
                for i in range(len(digits) - n + 1):
                    if digits[i:i + n] in self._forms:
                        start = 0 if i <= _PHONE_PREFIX_DIGITS else at[i]
                        spans.append((run.start() + start, run.start() + at[i + n - 1] + 1))
        spans.sort()
        merged: list[tuple[int, int]] = []
        for start, end in spans:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged


def _value_in_virtual_id(text: str, val_start: int) -> bool:
    """Whether a keyword rule's value starts inside one of our virtual ids
    after '@' ("RRN @U04217"): the whole id has the shape of an auth code,
    its digit tail the shape of a CVV, and neither is a value."""
    if _VID_TAIL_RE.search(text[:val_start]):
        return True
    return text[val_start - 1:val_start] == "@" and bool(_VID_HEAD_RE.match(text, val_start))


# "4242 4212 3456 7890 12/27 123": expiry and CVV typed right after the number,
# on the same line or the next one, with punctuation, a slash ("PAN/MM/YY/CVV"),
# a short label ("до 12/27, код 123") or a delimiter dump ("|1227|123") in
# between. A following year ("12/27/2026") marks a date, not an expiry.
_TSEP = r"(?:[ ,;|:\t()\-/]|\r?\n){1,3}"
_EXP_WORD = r"(?:(?:до|срок|exp\.?|expiry|expires|valid|thru|действительна?\s+до|годна\s+до)[ :.]{0,2})?"
_CVV_WORD = r"(?:(?:cvv2?|cvc2?|cvv/cvc|cvc/cvv|код|code|cid)[ :.]{0,2})?"
_TRAILER_SRC = (
    rf"(?P<sep1>{_TSEP}{_EXP_WORD})"
    r"(?P<exp>(?:0[1-9]|1[0-2])\s?[/.]\s?(?:20)?\d{2}(?!\d|\.\d|/(?:19|20)\d{2})"
    r"|(?<=[|;:,])(?:0[1-9]|1[0-2])2\d(?=[|;:,]\d{3,4}(?!\d))"
    # A dump writes the month and the year as two fields of their own
    # ("PAN|12|27|123", "PAN,12,2027,123"): only a CVV field behind them
    # makes the pair an expiry, so "PAN|12|27" alone stays two numbers.
    r"|(?<=[|;:,])(?:0[1-9]|1[0-2])[|;:,](?:20)?[1-9]\d(?=[|;:,]\d{3,4}(?!\d)))"
    rf"(?:(?P<sep2>{_TSEP}{_CVV_WORD})(?P<cvv>\d{{3,4}})(?!\d))?"
)
_CARD_TRAILER = re.compile(_TRAILER_SRC, re.IGNORECASE)
_MASKED_CARD_TRAILER = re.compile(MASKED_CARD + _TRAILER_SRC, re.IGNORECASE)

# Inside a link that policy keeps: phones are recognised only with a '+' or a
# query key, so order and document ids in paths are never touched.
_LINK_HEAD = re.compile(r"(?:[a-z][a-z0-9+.-]*://)?[^/?#]*", re.IGNORECASE)
_LINK_PHONE = re.compile(r"(?:\+|%2B)\d{10,15}(?!\d)|(?P<kw>[?&#](?:phone|tel|msisdn|mobile)=)%?\+?\d{10,15}(?!\d)",
                         re.IGNORECASE)
_LINK_USERINFO = re.compile(r"(?<=://)[^/?#]*@")  # "https://ivan:hunter2@acme.com": a credential
_HOST_WORDS = re.compile(r"[-.]")  # the separators that make a host a sequence of words
# The path of a kept link is route structure: order, document and commit ids
# and keyword-like segments ("/password-reset/pull/42", "/login/android_v2")
# in it are product knowledge, so only classes that are unambiguous without
# a keyword are masked there (nested links, credentials, tokens, e-mails).
# The query string and the fragment are data like message text and get the
# whole table ("?password=Qwerty123").
_LINK_PATH_RULES: tuple[_Rule, ...] = tuple(r for r in _RULES if "val" not in r.pattern.groupindex and r.name in {
    "proxy", "tg_link", "url", "bot_token", "jwt", "private_key", "credentials", "cookie", "fb_token", "known_secret",
    "ad_account", "email"})
# Wallet addresses and transaction hashes are recognised by shape alone, so
# they are masked anywhere in a kept link, host and path alike.
_LINK_CRYPTO_RULES: tuple[_Rule, ...] = tuple(r for r in FINTECH_RULES if r.name in ("wallet", "txid"))

# A browser percent-encodes whatever the user typed, so a name, a phone or a
# card inside a link arrives as "%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2" or
# "8%20916%20123%2045%2067". Such a value is read as text before the layers
# run over it. Escapes that would change the link's structure ("%2F", "%26"),
# forge one of our placeholders ("%3C") or spell something unprintable are
# left as they are, so a decoded segment is always a plain value.
_ESCAPE_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_ENCODED_PART = re.compile(r"(?<=[/?&=#;])[^/?&=#;\s]*(?:%[0-9A-Fa-f]{2}|\+)[^/?&=#;\s]*")
# Characters that carry the link's own structure or open one of our
# placeholders. Their escapes stay escaped and cut the run around them.
_LINK_STRUCTURE = "/?#&=%;+<>"
_STRUCT_ESCAPE = re.compile("(" + "|".join(f"%{ord(c):02X}" for c in _LINK_STRUCTURE) + ")", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")


def _decode_escapes(text: str) -> str:
    """``text`` with its percent escapes resolved into the characters they
    stand for, except the structural ones and any run that does not spell
    printable text (an escaped byte string, a control character)."""
    def readable(run: str) -> str:
        try:
            decoded = bytes.fromhex(run.replace("%", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return run
        return decoded if decoded.isprintable() else run

    def one(m: re.Match) -> str:
        return "".join(part if i % 2 else readable(part)
                       for i, part in enumerate(_STRUCT_ESCAPE.split(m.group(0))))
    return _ESCAPE_RUN.sub(one, text)


def _not_own_handle(accept: Optional[Callable[[re.Match], bool]]) -> Callable[[re.Match], bool]:
    """``accept`` that also leaves our own handle output ("@U04217") alone:
    verify renders a scrubbed kept link again and must get it back."""
    return lambda m: _OWN_HANDLE_RE.fullmatch(m.group(0)) is None and (accept is None or accept(m))


_LINK_QUERY_RULES: tuple[_Rule, ...] = tuple(
    replace(r, accept=_not_own_handle(r.accept)) if r.name in ("handle", "handle_spaced") else r for r in _RULES)


# --- surrogate helpers (Telegram offsets are UTF-16 code units) ------------------------

def _to_utf16_units(text: str) -> str:
    """Represent astral characters as surrogate pairs so that Python string
    indices coincide with Telegram's UTF-16 offsets."""
    out = []
    for ch in text:
        cp = ord(ch)
        if cp >= 0x10000:
            cp -= 0x10000
            out.append(chr(0xD800 + (cp >> 10)))
            out.append(chr(0xDC00 + (cp & 0x3FF)))
        else:
            out.append(ch)
    return "".join(out)


def _from_utf16_units(text: str) -> str:
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def _splits_pair(units: str, i: int) -> bool:
    return 0 < i < len(units) and "\ud800" <= units[i - 1] <= "\udbff" and "\udc00" <= units[i] <= "\udfff"


# --- vocabulary -------------------------------------------------------------------------

_WORD_RE = re.compile(r"[^\W_]{2,}", re.UNICODE)
# Shortest term the vocabulary patterns act on. A two-letter surname on its
# own collides with ordinary words ("Ли"), so people need three characters;
# a two-character organisation term is either a letter+digit title token
# ("Z9", "K7") or written into custom_terms by the operator on purpose.
PERSON_TERM_MIN_LEN = 3
ORG_TERM_MIN_LEN = 2
# Word-final letters that change under inflection: the Russian noun "Ромашка"
# (nominative) becomes "Ромашки" (genitive), so the last letter is dropped
# from the stem before the case endings are added.
_INFLECTED_ENDINGS = frozenset("аяоеиыьйуюaeiouy")
_CYRILLIC_RE = re.compile("[а-яё]")
_YO_RE = re.compile("[её]")
_CONSONANT_FINAL = re.compile("[бвгджзклмнпрстфхцчшщ]$")
# Closed inflection classes instead of open wildcards: a surname that is also
# a word ("Марк", "Лист", "Bank") does not swallow "маркет", "листинг" or
# "banking". Cyrillic and Latin (transliterated) case endings.
_ENDING = (r"(?:а|я|у|ю|е|ё|ы|и|о|ой|ою|ей|ёй|ею|ом|ем|ём|ым|им|ых|их|ах|ях|ами|ями|ыми|ими|ов|ев"
           r"|ому|ему|ого|его|ая|яя|ую|юю|ые|ие|s|es|a|i|u|y|e|oy|ey|om|ym|ykh|ami|ov|ev|ova|ovu|'s)?")
_SHORT_CONSONANT_ENDING = r"(?:а|у|ом|е|ы|ов|ым|ых|ам|ами)?"   # "Кима", "Паку", "Тена"
_SHORT_Y_ENDING = r"(?:й|я|ю|ем|е|и|ев|ям|ями)"                # "Цой", "Цоя", "Цою"
_ADJECTIVE_END = re.compile(r"(?:ий|ый|ой|ая|яя|ое|ее)$")
# Full adjective declension for an adjectival surname whose stem is too short
# for the open ending class ("Бел-ый": "Бел-ого", "Бел-ая", "Бел-ую"), one
# class per stem type so that no verb form joins in ("чист-им", "кос-им" and
# "жив-ем" stay: a hard stem takes no "-им"/"-ем"). The ending is mandatory,
# so the bare stem ("Бел", "Мал") never matches.
_ADJ_ENDINGS = {
    "hard": r"(?:ый|ой|ого|ому|ым|ом|ая|ую|ою|ые|ых|ыми|ое)",                         # Белый, Седой
    "velar": r"(?:ий|ой|ого|ому|им|ом|ая|ую|ою|ие|их|ими|ое)",                        # Дикий, Лихой
    "sibilant": r"(?:ий|ой|его|ого|ему|ому|им|ем|ом|ая|ую|ей|ою|ею|ие|их|ими|ее|ое)",  # Рыжий, Чужой
    "soft": r"(?:ий|его|ему|им|ем|яя|юю|ей|ею|ие|их|ими|ее)",                         # Синий
}
_LONG_STEM_MIN = 5  # an adjectival stem this long takes the open ending class
_FLEETING_VOWEL = ((re.compile(r"ец$"), "ц"), (re.compile(r"ець$"), "ц"), (re.compile(r"яц$"), "йц"),
                   (re.compile(r"ок$"), "к"), (re.compile(r"ёк$"), "ьк"))
# Word-final letters that are part of the nominative, not a case ending the
# stem drops: "Андрей", "Коваль", "Shevchenko" (Cyrillic "о" is an ending).
_NOMINATIVE_FINALS = "йьo"


def fold(term: str) -> str:
    """Comparison key for keep terms and names: case-, ё/е- and
    whitespace-insensitive, in the ``plain_text`` form text is matched in."""
    return " ".join(plain_text(term).lower().replace("ё", "е").split())


# Generic chat-title words in every case form ("Групп", "Технологий",
# "Сервиса", "поддержки"): Cyrillic stems with a noun ending class that has
# no surname suffix, so "Банков", "Туров" or "Тестова" in a title still name
# somebody, and an inflected form shaped like a surname ("Казина" from
# "казино") is never generic. Latin words match verbatim ("Stores" is
# listed, "Story" is a name); useful plural genitives ("клиентов") are listed.
_TITLE_NOUN_ENDING = r"(?:а|я|у|ю|е|ё|ы|и|й|ой|ей|ом|ем|ам|ям|ах|ях|ами|ями)?"
_TITLE_GENERIC_FORMS = re.compile("(?:" + "|".join(
    _YO_RE.sub("[её]", re.escape(w[:-1] if w[-1] in _INFLECTED_ENDINGS else w)) + _TITLE_NOUN_ENDING
    for w in sorted(TITLE_STOPWORDS | _TITLE_ONLY_STOPWORDS, key=lambda w: (-len(w), w))
    if len(w) >= 4 and _CYRILLIC_RE.search(w)) + ")", re.IGNORECASE)
_SURNAME_SHAPE = re.compile("(?:ов|ев|ёв|ин|ын)а?$")


def generic_title_word(token: str) -> bool:
    """Whether a word names a kind of business or a support function rather
    than an organisation or a person ("банк", "магазин", "Support"), in any
    Russian case form."""
    low = token.lower()
    if low in TITLE_STOPWORDS or low in _TITLE_ONLY_STOPWORDS:
        return True
    return (bool(_CYRILLIC_RE.search(low)) and not _SURNAME_SHAPE.search(low)
            and _TITLE_GENERIC_FORMS.fullmatch(low) is not None)


def title_tokens(title: str) -> list[str]:
    """Significant tokens of a chat title, minus generic words (Cyrillic ones
    in any case form: the distinctive part of "ООО Ромашка Групп" is
    "Ромашка"), migration markers and numbers. A two-character token counts
    only when it mixes a letter and a digit ("Z9", "K7", "4D"): plain
    two-letter words ("ИП", "QA", "по") are too common in running text to be
    scrubbed as an organisation, so such a name has to go into
    ``custom_terms``."""
    def significant(t: str) -> bool:
        if t.isdigit() or generic_title_word(t):
            return False
        return len(t) > 2 or (any(c.isdigit() for c in t) and any(c.isalpha() for c in t))
    return [t for t in _WORD_RE.findall(title) if significant(t)]


_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh", "з": "z", "и": "i",
    "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t",
    "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y",
    "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def translit(term: str) -> str:
    """Latin spelling of a Cyrillic term (the surname "Петров" becomes
    "Petrov"), so names and org names written in Latin letters (logins,
    emails, English chat) are caught as well. Terms without Cyrillic letters
    come back unchanged."""
    out = []
    for ch in term:
        low = ch.lower()
        if low in _TRANSLIT:
            latin = _TRANSLIT[low]
            out.append(latin.capitalize() if ch.isupper() else latin)
        else:
            out.append(ch)
    return "".join(out)


def _stem_part(stem: str, ending: str = _ENDING) -> str:
    """Escaped stem with ё/е folded, followed by an ending class."""
    return _YO_RE.sub("[её]", re.escape(stem.lower())) + ending


# The characters a pattern can start with. Empty means "anything": the
# pattern begins with something other than a literal, and _compile_terms
# then falls back to a plain alternation for the whole roster.
_ANY_START: frozenset[str] = frozenset()


class _Fragment(NamedTuple):
    """A pattern with the characters it can start with."""
    pattern: str
    first: frozenset[str]


def _stem_characters(stems: Iterable[str]) -> frozenset[str]:
    """The characters a ``_stem_part`` pattern of ``stems`` can start with:
    a stem is lower-cased, and a leading "ё" is folded together with "е". An
    empty stem (a term of soft signs transliterates to nothing) leaves the
    ending class at the front, which matches many letters, so the answer is
    then ``_ANY_START``."""
    characters: set[str] = set()
    for stem in stems:
        first = stem.lower()[:1]
        if not first:
            return _ANY_START
        characters.update("её" if first in "её" else first)
    return frozenset(characters)


def _adjective_ending(low: str) -> str:
    """The declension class of a short adjectival word ``low`` (lowercase)."""
    stem_end = low[-3]
    if stem_end in "кгх":
        return _ADJ_ENDINGS["velar"]
    if stem_end in "жшчщ":
        return _ADJ_ENDINGS["sibilant"]
    return _ADJ_ENDINGS["soft" if low.endswith(("ий", "яя", "ее")) else "hard"]


def _word_part(word: str, surname: bool = True) -> _Fragment:
    """Pattern for one word of a term: the stem plus Russian/Latin case
    endings, with extra stems for adjectival words ("Ковальск-ого") and
    fleeting vowels ("Кравец" -> "Кравц-а", "Кравець" -> "Кравц-я"). A word
    ending in "й", "ь" or a Latin "o" also matches itself ("Андрей",
    "Коваль", "Shevchenko": that letter is not a case ending). With
    ``surname``, an adjectival word whose stem is too short for the open
    class declines as an adjective ("Белый" -> "Бел-ого", "Бел-ая");
    organisation words leave that out, so a title word "Новая" does not
    remove "новый" and "новое". Three-letter Cyrillic surnames get explicit
    endings ("Ким-а"), everything shorter is matched verbatim."""
    low = word.lower()
    cyrillic = bool(_CYRILLIC_RE.search(low))
    if len(word) < 3:
        return _Fragment(re.escape(word), frozenset(word[:1]))
    if len(word) == 3:
        if cyrillic and _CONSONANT_FINAL.search(low):
            return _Fragment(re.escape(low) + _SHORT_CONSONANT_ENDING, _stem_characters([low]))
        if cyrillic and low.endswith("й"):
            return _Fragment(re.escape(low[:-1]) + _SHORT_Y_ENDING, _stem_characters([low]))
        return _Fragment(re.escape(word), frozenset(word[:1]))
    stems = [word[:-1] if low[-1] in _INFLECTED_ENDINGS else word]
    if low[-1] in _NOMINATIVE_FINALS:
        stems.append(word)
    declined: list[tuple[str, str]] = []   # a stem with an adjective ending of its own
    if cyrillic:
        extra = []
        if _ADJECTIVE_END.search(low):
            if len(word) - 2 >= _LONG_STEM_MIN:
                extra.append(word[:-2])
                if surname and low.endswith("ая") and low[-3] in "кгхжшчщ":
                    declined.append((word[:-2], "ий"))  # "Ковальская" -> "Ковальский"
            elif surname and len(word) - 2 >= PERSON_TERM_MIN_LEN:
                declined.append((word[:-2], _adjective_ending(low)))
        for ending, replacement in _FLEETING_VOWEL:
            found = ending.search(low)
            if found and found.start() + len(replacement) >= 4:
                extra.append(word[:found.start()] + replacement)
        # The Latin spelling of an extra stem ("Kovalsk-y") is added here
        # because the transliterated term itself is not an adjective.
        stems += extra + [translit(st) for st in extra]
    stems = list(dict.fromkeys(stems))
    parts = [_stem_part(st) for st in stems] + [_stem_part(st, e) for st, e in declined]
    body = parts[0] if len(parts) == 1 else "(?:" + "|".join(parts) + ")"
    return _Fragment(body, _stem_characters(stems + [st for st, _ in declined]))


def _term_alternatives(terms: Iterable[str], org: bool) -> list[tuple[str, _Fragment]]:
    """``(spelling, fragment)`` for every spelling of ``terms``: the term in
    ``plain_text`` form, its Latin transliteration and, for "ё", the "yo"
    spelling. Words, and the parts of a hyphenated word, are matched one by
    one, so a multi-word term ("Иван Петров", "Смирнова-Кузнецова") is found
    in every inflected form ("Смирновой-Кузнецовой"). Spellings shorter than
    ``ORG_TERM_MIN_LEN`` (organisations) or ``PERSON_TERM_MIN_LEN`` (people)
    are dropped."""
    min_len = ORG_TERM_MIN_LEN if org else PERSON_TERM_MIN_LEN
    expanded = []
    for t in terms:
        t = plain_text(t or "").strip()
        if not t:
            continue
        expanded.append(t)
        latin = translit(t)
        if latin != t:
            expanded.append(latin)
        if "ё" in t.lower():
            expanded.append(translit(t.replace("ё", "yo").replace("Ё", "Yo")))

    def word(w: str) -> _Fragment:
        pieces = [_word_part(p, surname=not org) for p in w.split("-")]
        # An empty first piece means the word began with the hyphen that
        # joins them ("-Иван"), so that hyphen is where the pattern starts.
        first = pieces[0].first if pieces[0].pattern else frozenset("-")
        return _Fragment("-".join(p.pattern for p in pieces), first)

    def term(t: str) -> tuple[str, _Fragment]:
        words = [word(w) for w in t.split()]
        first = words[0].first if words else _ANY_START
        return t, _Fragment(r"\s+".join(w.pattern for w in words), first)
    return [term(t) for t in dict.fromkeys(t for t in expanded if len(t) >= min_len)]


# The end of a term: a term that ends in a letter may run into a number
# ("petrov1990", "IMG_Petrov2.jpg", "romashka2024"), one that ends in a digit
# may not ("S3" is not in "S30").
_TERM_END = r"(?:(?<=\d)(?![^\W_])|(?<!\d)(?![^\W\d_]))"


def _case_insensitive_classes(characters: Iterable[str]) -> list[list[str]]:
    """``characters`` split into groups that fold together: two characters
    join the same group when a case-insensitive pattern of one matches the
    other ("i" with "I" and the dotless "ı", "с" with "С" and the historic
    "ᲃ"). Folding is an equivalence relation, so a character of any text
    matches the class of at most one group - which is what lets the dispatch
    below keep the alternatives in the order the flat alternation tried them
    in. Every pair is compared rather than only the first member of a group,
    so a future Unicode table that folds less tidily merges groups instead
    of splitting a class in two."""
    ordered = sorted(set(characters))
    group_of = list(range(len(ordered)))

    def root(i: int) -> int:
        while group_of[i] != i:
            group_of[i] = group_of[group_of[i]]
            i = group_of[i]
        return i
    for i, ch in enumerate(ordered):
        matcher = re.compile(re.escape(ch), re.IGNORECASE)
        for j in range(i + 1, len(ordered)):
            if matcher.fullmatch(ordered[j]):
                group_of[root(j)] = root(i)
    classes: dict[int, list[str]] = {}
    for i, ch in enumerate(ordered):
        classes.setdefault(root(i), []).append(ch)
    return list(classes.values())


def _dispatched(parts: dict[str, frozenset[str]]) -> str:
    """The alternatives of ``parts`` (each pattern with the characters it can
    start with) as one alternation that asks first which character the text
    has: "(?=[к])(?:ковальск…|кравц…)|(?=[k])(?:kovalsk…)". Only the group of
    the character at hand is entered, so the cost per position stops growing
    with the size of the roster. Inside a group the alternatives keep their
    order, and two groups never open at the same position, so the match is
    the one the flat alternation would have found."""
    classes = _case_insensitive_classes(ch for chars in parts.values() for ch in chars)
    of_class = {ch: i for i, members in enumerate(classes) for ch in members}
    groups: dict[int, list[str]] = {}
    for pattern, chars in parts.items():
        for i in sorted({of_class[ch] for ch in chars}):
            groups.setdefault(i, []).append(pattern)
    return "|".join(f"(?=[{''.join(re.escape(c) for c in classes[i])}])(?:{'|'.join(group)})"
                    for i, group in groups.items())


def _compile_terms(alternatives: Iterable[tuple[str, _Fragment]]) -> Optional[re.Pattern]:
    """One whole-word, case-insensitive pattern, longest spelling first; '_'
    and a following number count as word separators, so names inside file
    names and logins are found too. The alternatives are dispatched on their
    first character unless one of them can start with anything; a pattern
    and its first characters are built from the same stems, so two equal
    patterns always agree and the first of them may stand for both."""
    parts: dict[str, frozenset[str]] = {}   # pattern -> the characters it starts with
    for _, fragment in sorted(alternatives, key=lambda a: (-len(a[0]), a[0])):
        parts.setdefault(fragment.pattern, fragment.first)
    if not parts:
        return None
    body = _dispatched(parts) if all(parts.values()) else "|".join(parts)
    return re.compile(r"(?<![^\W_])(?:" + body + r")" + _TERM_END, re.IGNORECASE | re.UNICODE)


def _term_pattern(terms: Iterable[str], org: bool = False) -> Optional[re.Pattern]:
    """Pattern for a set of person terms (or organisation terms with
    ``org``), tolerant to Russian and Latin case endings."""
    return _compile_terms(_term_alternatives(terms, org))


def _keep_pattern(terms: Iterable[str]) -> Optional[re.Pattern]:
    """Whole-word, case-insensitive, verbatim pattern for keep terms, longest
    first ("Northwind Pay" before "Northwind")."""
    cleaned = {plain_text(t or "").strip() for t in terms} - {""}
    if not cleaned:
        return None
    alternatives = "|".join(re.escape(t) for t in sorted(cleaned, key=lambda t: (-len(t), t)))
    return re.compile(r"(?<![^\W_])(?:" + alternatives + r")(?![^\W_])", re.IGNORECASE)


def _multi_word(term: str) -> bool:
    """Whether a term spans several words ("Acme Corp", "Acme-Corp"), so a
    whole-word keep term can be a proper part of it."""
    return re.search(r"[\W_]", plain_text(term).strip()) is not None


def org_terms_from_titles(titles: Iterable[str], candidate_share: float) -> tuple[list[str], list[str]]:
    """Significant chat-title tokens, and the frequent ones among them as
    ``keep_terms`` candidates: (organisation terms, candidates).

    Every token is an organisation term - chat titles name the client - and is
    scrubbed unless the operator lists it in ``keep_terms``. A token present
    in at least ``candidate_share`` of the titles (and in at least three of
    them) is usually the product or company name that every client chat
    carries, so it is also returned as a candidate for the caller to suggest.
    It is never kept on its own: in a small export a client with a few chats
    clears any frequency threshold, and the guess would whitelist that client.
    Each title counts once, however often it repeats a token.
    """
    titles = [t for t in titles if t]
    counts: Counter[str] = Counter()
    surface: dict[str, str] = {}
    for title in titles:
        toks = title_tokens(title)
        counts.update({t.lower() for t in toks})
        for t in toks:
            surface.setdefault(t.lower(), t)
    threshold = max(3, candidate_share * len(titles))
    org = sorted(surface.values())
    candidates = sorted(surface[t] for t, c in counts.items() if c >= threshold)
    return org, candidates


def handle_like(username: str) -> bool:
    """Usernames safe to scrub even without a leading '@': long ones or ones
    with digits/underscores. Short plain words ("ivan") collide with names."""
    return len(username) >= 8 or "_" in username or any(c.isdigit() for c in username)


def _generic_handle(username: str) -> bool:
    """Whether a username spells nothing but ordinary product words
    ("payments", "sandbox_api", "webhooks"). Every '_'-separated part has to
    be one, so a client's name anywhere in the handle ("romashka_support")
    keeps it distinctive."""
    parts = [p for p in username.lower().split("_") if p]
    return bool(parts) and all(generic_title_word(p) for p in parts)


def bare_usernames(usernames: Iterable[str], chat_usernames: Container[str],
                   keep_folded: Container[str]) -> list[str]:
    """The usernames replaced, and hunted for, without a leading '@', longest
    first. Handle-like ones qualify, except a public chat's username that
    spells only product words: bare "payments" or "sandbox_api" in a support
    chat is the API term and not a reference to the chat, and scrubbing it
    would take that word out of every message of the export. Its '@' form,
    its t.me link and its keyword form ("ник: payments") are still replaced,
    as they are for a person's handle, which stays scrubbed bare whatever it
    spells."""
    return sorted((u for u in usernames if u.lower() not in keep_folded and handle_like(u)
                   and not (u in chat_usernames and _generic_handle(u))),
                  key=len, reverse=True)


def id_forms(marked_id: int) -> list[int]:
    """Number shapes under which a Telegram id may be pasted into text."""
    n = abs(marked_id)
    forms = {n}
    if marked_id < 0 and str(n).startswith("100") and len(str(n)) > 10:
        forms.add(int(str(n)[3:]))  # channel id without the -100 mark
    return sorted(forms)


def known_id_pattern(numbers: Iterable[int]) -> Optional[re.Pattern]:
    """Known ids written as numbers, for the scrubber and the scanner alike:
    never a part of a longer number or of a decimal fraction ("0.123456789",
    "123456789.5"), while a file extension or a full stop after the id does
    not hide it ("client/123456789.pdf")."""
    numbers = sorted(set(numbers), reverse=True)
    if not numbers:
        return None
    return re.compile(r"(?<![\d.])(?:" + "|".join(str(n) for n in numbers) + r")(?!\d|\.\d)")


# A product constant: ASCII capitals, digits and '_', at least one '_'.
_CONSTANT = re.compile(r"[A-Z0-9]*_[A-Z0-9_]*")
# An extension after a run makes it a file name ("PETROV_PASSPORT.pdf").
_FILE_EXT = re.compile(
    r"\.(?:pdf|jpe?g|png|heic|gif|webp|bmp|tiff?|svg|docx?|xlsx?|csv|txt|rtf|odt|ods|pptx?|zip|rar|7z|gz|tar"
    r"|json|xml|html?|ya?ml|log|mp4|mov|avi|ogg|oga|mp3|m4a|wav)(?![^\W_])", re.IGNORECASE)


def in_product_constant(m: re.Match) -> bool:
    """Whether an organisation-term hit is part of an ALL_CAPS product
    constant such as "ERR_BANK_TIMEOUT": the whole run of letters, digits
    and '_' around it is ASCII capitals, shorter than a long token, and no
    file name ("ROMASHKA_ACT.pdf"). A run glued to Cyrillic
    ("WALKER_ПАСПОРТ") is no constant, and a long identifier
    ("ROMASHKA_EXPORT_2026_03_12_FINAL_V2") is kept only because it reads as
    one, which never protects a known term inside it. Names get no such
    exemption: "PETROV_PASSPORT" is about a person."""
    text, s, e = m.string, m.start(), m.end()
    # The walk stops once the run is too long to be a constant anyway.
    first, last = max(0, s - LONG_TOKEN_MIN), min(len(text), e + LONG_TOKEN_MIN)
    while s > first and (text[s - 1].isalnum() or text[s - 1] == "_"):
        s -= 1
    while e < last and (text[e].isalnum() or text[e] == "_"):
        e += 1
    return (e - s < LONG_TOKEN_MIN and _CONSTANT.fullmatch(text, s, e) is not None
            and not _FILE_EXT.match(text, e))


@dataclass(frozen=True)
class Roster:
    """What the scrubber knows about people and organisations.

    ``by_username`` / ``by_user_id`` map to virtual ids: ``U04217`` for a
    person, ``C01735`` for an exported chat named by its public username.
    Names and org terms are plain strings that must not survive in text.
    ``keep_terms`` are never scrubbed on their own, even if they collide with
    a name or title token; a longer name or organisation term that contains
    one is still scrubbed whole. ``phones`` are the participants' own numbers
    from their profiles (E.164 digits): they must go whatever shape the
    author typed them in.
    """

    by_username: dict[str, str] = field(default_factory=dict)  # lowercase username -> vid (U##### or C#####)
    # Which of those usernames name an exported chat rather than a person:
    # only a chat's handle may spell a product word (``bare_usernames``).
    chat_usernames: frozenset[str] = frozenset()
    by_user_id: dict[int, str] = field(default_factory=dict)
    known_ids: tuple[int, ...] = ()  # marked user/chat ids that must not appear as numbers
    phones: tuple[str, ...] = ()     # digits only, as ``Known.phones``
    person_terms: tuple[str, ...] = ()
    org_terms: tuple[str, ...] = ()
    keep_terms: tuple[str, ...] = ()

    def _filtered(self, terms: Iterable[str]) -> tuple[str, ...]:
        keep = {fold(k) for k in self.keep_terms}
        return tuple(t for t in terms if fold(t) not in keep)

    def person_pattern(self) -> Optional[re.Pattern]:
        return _term_pattern(self._filtered(self.person_terms))

    def org_pattern(self) -> Optional[re.Pattern]:
        return _term_pattern(self._filtered(self.org_terms), org=True)

    def longer_term_pattern(self) -> Optional[re.Pattern]:
        """Multi-word names and organisation terms ("Олег Северов", "Acme
        Corp"), matched as the vocabulary layer matches them: the terms a
        keep term can be a proper part of."""
        return _compile_terms([
            *_term_alternatives(filter(_multi_word, self._filtered(self.person_terms)), org=False),
            *_term_alternatives(filter(_multi_word, self._filtered(self.org_terms)), org=True),
        ])

    def at_username_pattern(self) -> Optional[re.Pattern]:
        """Every known username after '@', wherever it stands ("tg@ivan_petrov")."""
        names = sorted(self.by_username, key=len, reverse=True)
        if not names:
            return None
        return re.compile(r"@(?P<u>" + "|".join(re.escape(n) for n in names) + r")" + _USERNAME_END, re.IGNORECASE)

    def bare_username_pattern(self) -> Optional[re.Pattern]:
        """Usernames written without '@' (``bare_usernames``). A preceding
        '_' is allowed (file names such as "scan_ivan_petrov.pdf"); a
        following '_' is not ("ivan_petrov_2" is another handle)."""
        names = bare_usernames(self.by_username, self.chat_usernames, {fold(k) for k in self.keep_terms})
        if not names:
            return None
        return re.compile(r"(?<![A-Za-z0-9@])(?P<u>" + "|".join(re.escape(n) for n in names) + r")" + _USERNAME_END,
                          re.IGNORECASE)

    def keyword_username_pattern(self) -> Optional[re.Pattern]:
        """Any known username, however short, right after a handle keyword
        ("мой ник в тг ivan")."""
        keep = {fold(k) for k in self.keep_terms}
        names = sorted((u for u in self.by_username if u not in keep), key=len, reverse=True)
        if not names:
            return None
        return re.compile(
            rf"(?<![\w<])(?P<kw>(?:{_HANDLE_KEYWORDS}))(?P<gap>{_HANDLE_GAP})(?P<u>"
            + "|".join(re.escape(n) for n in names) + r")" + _USERNAME_END, re.IGNORECASE)

    def id_pattern(self) -> Optional[re.Pattern]:
        return known_id_pattern(f for i in self.known_ids for f in id_forms(i) if len(str(f)) >= 6)


_span_start = itemgetter(0)


def _enclosing(span: tuple[int, int], spans: Sequence[tuple[int, int]]) -> Optional[tuple[int, int]]:
    """The entry of ``spans`` that contains ``span``, or ``None``. Every
    caller takes ``spans`` from ``finditer``, so the entries are ordered and
    never overlap: only the last one that starts at or before ``span`` can
    contain it, and the search stays a binary one however long the text is."""
    i = bisect.bisect_right(spans, span[0], key=_span_start) - 1
    return spans[i] if i >= 0 and span[1] <= spans[i][1] else None


def _strictly_inside(span: tuple[int, int], spans: Sequence[tuple[int, int]]) -> bool:
    """Whether ``span`` lies within one of ``spans`` that is longer than it."""
    outer = _enclosing(span, spans)
    return outer is not None and outer[1] - outer[0] > span[1] - span[0]


def _overlaps(span: tuple[int, int], spans: Iterable[tuple[int, int]]) -> bool:
    s, e = span
    return any(other_s < e and s < other_e for other_s, other_e in spans)


def _keep_term_hosts(text: str, keep_re: Optional[re.Pattern],
                     keep_folded: frozenset[str]) -> Callable[[re.Match], bool]:
    """Predicate over the ``BARE_DOMAIN`` matches in ``text``: whether a host
    carries nothing beyond a keep term. A keep term is a word, not a licence
    for every host that contains it ("acme.evilclient.ru"); a host stays only
    when it is the keep term itself ("northwind.app"), the keep term plus a
    public suffix ("northwind.ru", "ASP.NET") or part of a longer keep term
    in the text ("ASP.NET Core"). The scrubber and the scanner share it."""
    if keep_re is None:
        return lambda m: False
    spans: Optional[list[tuple[int, int]]] = None

    def kept(m: re.Match) -> bool:
        nonlocal spans
        host = fold(m.group(0))
        if host in keep_folded or host.rsplit(".", 1)[0] in keep_folded:
            return True
        if spans is None:
            spans = [k.span() for k in keep_re.finditer(text)]
        return _enclosing(m.span(), spans) is not None
    return kept


def _resolve(text: str, held: list[str]) -> str:
    """``text`` with its sentinels replaced by the renderings in ``held``."""
    while _SENTINEL_RE.search(text):
        text = _SENTINEL_RE.sub(lambda m: held[_decode_index(m.group(1))], text)
    # A rule that bit into a sentinel could leave a fragment behind; the raw
    # data it stood for is already replaced, so dropping the fragment is safe.
    return _PUA_RE.sub("", text)


# --- scrubber ----------------------------------------------------------------------------

# Rules whose every replaced value is counted, not just sampled: the ones
# whose vocabulary comes from the export and can hold an ordinary word the
# operator would rather keep.
_REPORTED_SURFACES = ("person", "org", "domain", "bare_username", "keyword_username")


class Scrubber:
    def __init__(self, policy: AnonPolicy, roster: Roster):
        self.policy = policy
        self.roster = roster
        self._person_re = roster.person_pattern()
        self._org_re = roster.org_pattern()
        self._bare_user_re = roster.bare_username_pattern()
        self._at_user_re = roster.at_username_pattern()
        self._kw_user_re = roster.keyword_username_pattern()
        self._id_re = roster.id_pattern()
        self._phones = KnownPhones(roster.phones)
        self._custom_res = [re.compile(p, re.IGNORECASE | re.MULTILINE | re.UNICODE) for p in policy.custom_patterns]
        self._keep_re = _keep_pattern(roster.keep_terms)
        self._longer_re = roster.longer_term_pattern() if self._keep_re is not None else None
        self._keep_folded = frozenset(fold(t) for t in roster.keep_terms)
        self._counts: Counter[str] = Counter()
        self._samples: dict[str, list[str]] = defaultdict(list)
        self._surfaces: dict[str, Counter[str]] = defaultdict(Counter)

    # Public interface -----------------------------------------------------------

    def scrub(self, text: str, entities: Iterable[Entity] = ()) -> str:
        if not text:
            return ""
        # Private-use characters in the input would collide with sentinels: swap
        # them for a same-width filler so entity offsets stay valid; full-width
        # digits must not dodge the digit rules.
        text = normalize_digits(_PUA_RE.sub(" ", text)).translate(_FULLWIDTH_PUNCT)
        sentinels: list[str] = []
        identities: dict[str, str] = {}  # digits a rule read as an identity -> its placeholder

        def protect(replacement: str, rule: str, surface: str, key: Optional[str] = None) -> str:
            self._note(rule, surface, key or surface)
            value = (key or surface).strip()
            if rule in _IDENTITY_RULES and value.isascii() and value.isdigit() and len(value) >= _IDENTITY_MIN_DIGITS:
                identities[value] = replacement
            sentinels.append(replacement)
            return f"{_S_OPEN}{_encode_index(len(sentinels) - 1)}{_S_CLOSE}"

        text = self._apply_entities(text, list(entities), protect)
        # After entities: astral digits are two UTF-16 units, and dropping
        # invisible characters or composing "е\u0308" into "ё" shifts offsets.
        text = plain_text(text)
        text = self._apply_rules(text, protect)
        text = self._repeat_identities(text, identities, protect)
        text = self._apply_known_phones(text, protect, _PHONE_RULES)
        # Bare domains before keep terms: a keep term inside a host must not
        # shield the rest of it.
        text = self._apply_domains(text, protect)
        text = self._apply_usernames(text, protect)
        # Custom patterns before keep terms: an explicit operator regex is the
        # more specific instruction, and the scanner reports its matches
        # whether or not a keep term sits inside one.
        text = self._apply_custom(text, protect)
        text = self._protect_keep_terms(text, protect)
        text = self._apply_vocabulary(text, protect)
        return _resolve(text, sentinels)

    def url_placeholder(self, url: str) -> str:
        """Placeholder for a link according to ``url_mode`` / ``allow_domains``.
        Telegram links are always hidden: they name accounts and chats. A
        link the parser rejects (a bracketed host that is not an IPv6
        literal: "http://[your-domain]/admin") is never kept."""
        url = plain_text(_PUA_RE.sub("", url))  # an entity target is not normalised like the text
        try:
            parts = urlsplit(url if "://" in url else "http://" + url)
        except ValueError:
            return PLACEHOLDER_TG if url.lower().startswith("tg:") else PLACEHOLDER_URL
        host = (parts.hostname or "").lower()
        if parts.scheme == "tg" or any(host == h or host.endswith("." + h) for h in TG_HOSTS):
            return PLACEHOLDER_TG
        allowed = self._allowed_host(host)
        if allowed is None and self.policy.url_mode != "keep":
            if self.policy.url_mode == "domain" and host and not self._host_names_somebody(host):
                return f"<url:[{host}]>" if ":" in host else f"<url:{host}>"  # an IPv6 literal keeps its brackets
            return PLACEHOLDER_URL
        kept = self._mask_inside_link(url)
        if allowed is not None and allowed != host:  # a wildcard entry hides the subdomain
            kept = re.sub(re.escape(host), lambda _: allowed, kept, count=1, flags=re.IGNORECASE)
        return kept

    def _host_names_somebody(self, host: str) -> bool:
        """Whether a host reads as a client or a person of the roster
        ("romashka.ru", "lk.romashka-shop.kz", "ivan-petrov.github.io"). Under
        ``url_mode="domain"`` the host is all that survives, so such a host
        would publish the name the organisation list exists to hide. A host
        in ``allow_domains`` is decided before this, and keep terms are
        already out of the roster patterns."""
        words = _HOST_WORDS.sub(" ", host)
        return any(rx is not None and rx.search(words) for rx in (self._org_re, self._person_re))

    def domain_placeholder(self, host: str) -> str:
        """Rendering of a bare host according to ``scrub_domains`` /
        ``allow_domains``, with the host semantics of ``url_placeholder``:
        the host itself when kept, "<sub>.example.com" under a wildcard
        entry, "<domain>" otherwise. Keep terms depend on the surrounding
        text and are the caller's business (``_keep_term_hosts``)."""
        if not self.policy.scrub_domains:
            return host
        allowed = self._allowed_host(host.lower())
        if allowed is None:
            return "<domain>"
        if allowed == host.lower():
            return host
        base_len = len(allowed) - len("<sub>.")
        return "<sub>." + host[len(host) - base_len:]  # the base as written

    def _allowed_host(self, host: str) -> Optional[str]:
        """How ``allow_domains`` renders a lower-case ``host``: the host itself
        for an exact entry or a wildcard base, "<sub>.base" for a host under
        a wildcard entry, None when no entry allows it."""
        for entry in self.policy.allow_domains:
            entry = entry.lower()
            if entry.startswith("*."):
                base = entry[2:]
                if host == base:
                    return host
                if host.endswith("." + base):
                    return "<sub>." + base
            elif host == entry:
                return host
        return None

    def _mask_inside_link(self, url: str) -> str:
        """A kept link still carries identifiers after its host, and they go
        through the same layers as message text: cards, wallets and
        transaction hashes anywhere (they need no keyword and no link
        structure), phones with a '+' or a query key, the shared rule table
        (in the path only the classes that need no keyword,
        ``_LINK_PATH_RULES``, so routes and ids survive), a participant's own
        number in the path ("wa.me/79161112233"), bare hosts (a redirect
        target), keep terms, custom patterns and the roster vocabulary. A
        query value becomes its placeholder ("?password=<password>"), a
        nested link follows the link policy, user info before the host
        becomes "<credentials>". The host itself is never touched: it is
        allowed on purpose. Every replacement is held as a sentinel until the
        end, so no layer reads another layer's placeholder as live text."""
        held: list[str] = []

        def hold(replacement: str, rule: str, surface: str, key: Optional[str] = None) -> str:
            self._note(f"url:{rule}", surface, key)
            held.append(replacement)
            return f"{_S_OPEN}{_encode_index(len(held) - 1)}{_S_CLOSE}"

        for span in reversed(find_cards(url, self.policy.card_bins)):
            url = url[:span.start] + hold(span.masked, "card", url[span.start:span.end]) + url[span.end:]
        for rule in _LINK_CRYPTO_RULES:
            url = self._substitute(rule, url, hold)
        head_end = _LINK_HEAD.match(url).end()
        head, tail = url[:head_end], url[head_end:]
        head = _LINK_USERINFO.sub(lambda m: hold(FINTECH_PLACEHOLDERS["credentials"] + "@", "credentials", m.group(0)),
                                  head, count=1)
        if not tail:
            return _resolve(head, held)
        tail = _LINK_PHONE.sub(lambda m: (m.group("kw") or "") + hold(PLACEHOLDER_PHONE, "phone", m.group(0)), tail)
        query_at = min((i for i in (tail.find("?"), tail.find("#")) if i >= 0), default=len(tail))
        path, query = tail[:query_at], tail[query_at:]
        path = self._mask_encoded(path, False, hold)
        query = self._mask_encoded(query, True, hold)
        for rule in _LINK_PATH_RULES:
            path = self._substitute(rule, path, hold)
        for rule in _LINK_QUERY_RULES:
            query = self._substitute(rule, query, hold)
        tail = self._apply_known_phones(path + query, hold)
        tail = self._apply_domains(tail, hold)
        tail = self._apply_usernames(tail, hold)
        tail = self._apply_custom(tail, hold)
        tail = self._protect_keep_terms(tail, hold)
        tail = self._apply_vocabulary(tail, hold)
        return _resolve(head + tail, held)

    def _mask_encoded(self, part: str, is_query: bool, hold) -> str:
        """Percent-encoded values in the path or the query of a kept link,
        scrubbed as the text they stand for
        ("?q=%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2" is a surname). A segment
        that carries nothing identifying is written back exactly as it
        arrived, so ordinary encoding survives
        ("/docs/%D0%BE%D0%BF%D0%BB%D0%B0%D1%82%D0%B0"); a segment that does
        is replaced by its decoded, masked text with the whitespace encoded
        again. In a query '+' stands for a space, in a path it does not."""
        def one(m: re.Match) -> str:
            segment = m.group(0)
            decoded = _decode_escapes(segment.replace("+", " ") if is_query else segment)
            if decoded == segment:
                return segment
            masked = self._mask_decoded(plain_text(decoded), is_query, hold)
            return segment if masked == decoded else _WHITESPACE_RE.sub("%20", masked)
        return _ENCODED_PART.sub(one, part)

    def _mask_decoded(self, part: str, is_query: bool, hold) -> str:
        """The layers a decoded piece of a kept link goes through: cards,
        wallets and hashes by shape, the rules of the part it came from, then
        the roster layers."""
        for span in reversed(find_cards(part, self.policy.card_bins)):
            part = part[:span.start] + hold(span.masked, "card", part[span.start:span.end]) + part[span.end:]
        for rule in (*_LINK_CRYPTO_RULES, *(_LINK_QUERY_RULES if is_query else _LINK_PATH_RULES)):
            part = self._substitute(rule, part, hold)
        part = self._apply_known_phones(part, hold)
        part = self._apply_domains(part, hold)
        part = self._apply_usernames(part, hold)
        part = self._apply_custom(part, hold)
        part = self._protect_keep_terms(part, hold)
        return self._apply_vocabulary(part, hold)

    def report(self) -> dict[str, Any]:
        """Replacement counts and sample surfaces per rule, for the operator
        to spot over-scrubbing. Contains raw tokens: keep it private."""
        return {
            "counts": dict(sorted(self._counts.items())),
            "samples": {k: v for k, v in sorted(self._samples.items())},
            # The most frequent surfaces of the vocabulary rules: a word that
            # fires hundreds of times is a homograph to put into keep_terms.
            # A public host that fires as often belongs in allow_domains, a
            # handle removed as a bare word in keep_terms if it is a product
            # term ("payments") rather than a name.
            "top_surfaces": {k: dict(self._surfaces[k].most_common(30))
                             for k in _REPORTED_SURFACES if self._surfaces[k]},
        }

    def surfaces(self, rule: str) -> dict[str, int]:
        """Every value one rule replaced, with how often, for the caller's
        private report. Raw data, as the whole report is."""
        return dict(self._surfaces[rule])

    # Internals --------------------------------------------------------------------

    def _note(self, rule: str, surface: str, key: Optional[str] = None) -> None:
        """``surface`` is the sample shown in the report (with keyword
        context), ``key`` the value counted in ``top_surfaces``."""
        self._counts[rule] += 1
        if rule in _REPORTED_SURFACES:
            self._surfaces[rule][(key or surface).lower()] += 1
        bucket = self._samples[rule]
        if len(bucket) < 12 and surface not in bucket:
            bucket.append(surface[:80])

    def _entity_replacement(self, etype: str, surface: str, entity: Entity) -> Optional[str]:
        if etype == "Mention":
            vid = self.roster.by_username.get(surface.lstrip("@").lower())
            return f"@{vid}" if vid else PLACEHOLDER_USER
        if etype == "MentionName":
            vid = self.roster.by_user_id.get(entity.user_id) if entity.user_id is not None else None
            return f"@{vid}" if vid else PLACEHOLDER_USER
        if etype == "Email":
            return PLACEHOLDER_EMAIL
        if etype == "Phone":
            return PLACEHOLDER_PHONE
        if etype == "BankCard":
            return mask_card(surface)
        if etype == "Url":
            return self.url_placeholder(surface)
        return None

    def _text_url_suffix(self, entity: Entity) -> Optional[str]:
        """For a TextUrl entity: the kept target to append after the visible
        text (which stays in place so later layers still scrub it)."""
        target = self.url_placeholder(entity.url or "")
        return f" ({target})" if target and not target.startswith("<") else None

    def _apply_entities(self, text: str, entities: list[Entity], protect) -> str:
        if not entities:
            return text
        units = _to_utf16_units(text)
        taken: list[tuple[int, int]] = []
        # Replace from the end so earlier offsets stay valid; skip entities
        # that overlap a range already replaced; snap edges that would split
        # a surrogate pair outward so no lone surrogate is produced.
        for ent in sorted(entities, key=lambda e: (e.offset, -e.length), reverse=True):
            start, end = ent.offset, min(ent.offset + ent.length, len(units))
            if start < 0 or start >= end:
                continue
            if _splits_pair(units, start):
                start -= 1
            if _splits_pair(units, end):
                end += 1
            if any(s < end and start < e for s, e in taken):
                continue
            if ent.type == "Mention" and _npm_scope(units, start, end):
                continue  # Telegram tags "@types" in "npm i @types/node" as a mention
            surface = _from_utf16_units(units[start:end])
            if ent.type == "TextUrl":
                suffix = self._text_url_suffix(ent)
                if suffix is not None:
                    units = units[:end] + protect(suffix, "entity:TextUrl", ent.url or "") + units[end:]
                continue
            replacement = self._entity_replacement(ent.type, surface.strip(), ent)
            if replacement is None:
                continue
            tail = ""
            if ent.type == "BankCard":
                # The expiry and CVV typed after a card entity follow it as
                # plain text (the trailer is ASCII, so unit offsets are safe).
                tail, end = self._card_trailer(units, end, protect)
            units = units[:start] + protect(replacement, f"entity:{ent.type}", surface) + tail + units[end:]
            taken.append((start, end))
        return _from_utf16_units(units)

    @staticmethod
    def _card_trailer(text: str, pos: int, protect) -> tuple[str, int]:
        """Expiry and CVV right after a card at ``pos``: the protected
        rendering and the position after them (``pos`` when absent)."""
        trailer = _CARD_TRAILER.match(text, pos)
        if not trailer:
            return "", pos
        out = trailer.group("sep1") + protect("<exp>", "expiry", trailer.group("exp"))
        if trailer.group("cvv"):
            out += trailer.group("sep2") + protect("<cvv>", "cvv", trailer.group("cvv"))
        return out, trailer.end()

    def _substitute(self, rule: _Rule, text: str, protect) -> str:
        def repl(m: re.Match) -> str:
            if rule.accept and not rule.accept(m):
                return m.group(0)
            if rule.name in ("handle", "handle_spaced"):
                vid = self.roster.by_username.get(m.group("u").lower())
                return protect(f"@{vid}" if vid else PLACEHOLDER_USER, rule.name, m.group(0))
            if rule.name == "url":
                return protect(self.url_placeholder(m.group(0)), rule.name, m.group(0))
            if rule.name == "kw_handle":
                vid = self.roster.by_username.get(m.group("val").lower())
                start, end = m.start("val"), m.end("val")
                return (m.string[m.start():start] + protect(f"@{vid}" if vid else PLACEHOLDER_USER, rule.name, m.group(0))
                        + m.string[end:m.end()])
            if rule.part is not None:
                # The pattern took in more than it removes (a phone shape
                # takes a whole run of numbers): everything around the part
                # stays live text, so the later layers still see an id, an
                # amount or a keyword in it.
                start, end = rule.part(m)
                return (m.string[m.start():start]
                        + protect(rule.placeholder, rule.name, m.group(0), m.string[start:end])
                        + m.string[end:m.end()])
            if "val" in rule.pattern.groupindex:
                if rule.name in ("person", "cardholder") and self._keep_re and self._keep_re.search(m.group("val")):
                    return m.group(0)  # "Best regards, Northwind Support": a keep term is not a person
                # Keyword rules replace only the value: the keyword and the
                # gap stay live text, so a name, handle, e-mail or domain in
                # the gap is still seen by the later layers, and a sentinel
                # already inside the gap resolves normally.
                start, end = m.start("val"), m.end("val")
                return (m.string[m.start():start] + protect(rule.placeholder, rule.name, m.group(0), m.group("val"))
                        + m.string[end:m.end()])
            rendered = rule.render(m) if rule.render else rule.placeholder
            return protect(rendered, rule.name, m.group(0))
        return rule.pattern.sub(repl, text)

    def _apply_rules(self, text: str, protect) -> str:
        for rule in _PRE_CARD_RULES:
            text = self._substitute(rule, text, protect)
        # Cards next: they are recognised by shape, checksum or known BIN
        # (see ``cards``), before any digit-based rule can bite into them.
        spans = find_cards(text, self.policy.card_bins)
        if spans:
            out, last = [], 0
            for span in spans:
                out.append(text[last:span.start])
                out.append(protect(span.masked, "card", text[span.start:span.end]))
                tail, last = self._card_trailer(text, span.end, protect)
                out.append(tail)
            out.append(text[last:])
            text = "".join(out)
        for rule in _RULES:
            text = self._substitute(rule, text, protect)
        if spans:
            # Next to a card in the same message, "код 123" is its CVV and
            # "до 03/30" its expiry.
            text = self._substitute(CARD_CVV_RULE, text, protect)
            text = self._substitute(CARD_EXPIRY_RULE, text, protect)
        return text

    @staticmethod
    def _repeat_identities(text: str, identities: dict[str, str], protect) -> str:
        """Every further copy of a number the message itself labelled as a
        tax id or a document gets the same placeholder. Once the author has
        named the number ("... иин 651214316007"), an order or ticket label
        in front of another copy ("обращение 651214316007 ...") no longer
        makes that copy a reference: ``not_operation_ref`` judges each
        occurrence on its own and only reads the words in front of it."""
        for value, replacement in identities.items():
            text = re.sub(rf"(?<!\d){value}(?!\d)",
                          lambda m, r=replacement: protect(r, "id_value", m.group(0)), text)
        return text

    def _apply_known_phones(self, text: str, protect, retry: tuple[_Rule, ...] = ()) -> str:
        """A participant's own number in any digit grouping the leak scanner
        can see, so the phone shapes above need not cover every spelling and
        a number the self-check hunts can never survive. It runs after the
        rule table, so a link or a card is already one replacement and this
        layer cannot cut into it, and before the domain and vocabulary
        layers, so a number is not read as a host or a chat username.

        Cutting the known number out of a run of digits can expose another
        number that the whole run had hidden ("79161112233" typed straight
        onto "89991234567"), so the ``retry`` rules run again over the rest.
        """
        spans = self._phones.spans(text)
        if not spans:
            return text
        out, last = [], 0
        for start, end in spans:
            out.append(text[last:start])
            out.append(protect(PLACEHOLDER_PHONE, "known_phone", text[start:end]))
            last = end
        out.append(text[last:])
        text = "".join(out)
        for rule in retry:
            text = self._substitute(rule, text, protect)
        return text

    def _apply_domains(self, text: str, protect) -> str:
        """Bare hosts as ``domain_placeholder`` renders them; a host that is
        only a keep term stays for the keep-term layer."""
        if not self.policy.scrub_domains:
            return text
        keep_host = _keep_term_hosts(text, self._keep_re, self._keep_folded)

        def one(m: re.Match) -> str:
            host = m.group(0)
            rendered = host if keep_host(m) else self.domain_placeholder(host)
            return host if rendered == host else protect(rendered, "domain", host)
        return BARE_DOMAIN.sub(one, text)

    def _protect_keep_terms(self, text: str, protect) -> str:
        """Keep terms become sentinels so no later layer can touch them,
        except where a keep term is a proper part of a longer known name or
        organisation ("Acme" inside the custom term "Acme Corp", "мороз"
        inside the full name "Анна Мороз"): the longer term is the more
        specific instruction and the scanner hunts for it whole, so the
        vocabulary layer must see it whole. A keep term that equals a whole
        term never reaches those patterns (``Roster._filtered``). The
        operator's ``custom_patterns`` are the other exception: they run one
        layer earlier, so a keep term inside such a match is already gone."""
        if self._keep_re is None:
            return text
        longer: Optional[list[tuple[int, int]]] = None  # spans of multi-word terms, found on first demand

        def keep(m: re.Match) -> str:
            nonlocal longer
            if self._longer_re is not None:
                if longer is None:
                    longer = [x.span() for x in self._longer_re.finditer(text) if not in_product_constant(x)]
                if _strictly_inside(m.span(), longer):
                    return m.group(0)
            return protect(m.group(0), "keep", m.group(0))
        return self._keep_re.sub(keep, text)

    def _apply_custom(self, text: str, protect) -> str:
        """The operator's own regexes, each match replaced whole. A zero-width
        match is left alone: the configuration rejects a pattern that can match
        the empty string, but a policy assembled in code may still carry one,
        and replacing nothing would shred the message into placeholders."""
        for rx in self._custom_res:
            text = rx.sub(lambda m: protect(PLACEHOLDER_REDACTED, "custom", m.group(0)) if m.group(0) else "", text)
        return text

    def _apply_usernames(self, text: str, protect) -> str:
        """Known usernames after '@' anywhere, after a handle keyword, and
        bare where ``bare_usernames`` allows it. They run before keep terms:
        a keep term inside a username ("northwind_ivan") must not shield the rest of it,
        while a username that equals a keep term stays bare."""
        def vid(m: re.Match) -> str:
            return "@" + self.roster.by_username[m.group("u").lower()]
        if self._at_user_re is not None:
            text = self._at_user_re.sub(lambda m: protect(vid(m), "known_at", m.group(0)), text)
        if self._kw_user_re is not None:
            text = self._kw_user_re.sub(
                lambda m: m.group("kw") + m.group("gap")
                + protect(vid(m), "keyword_username", m.group(0), m.group("u").lower()), text)
        if self._bare_user_re is not None:
            text = self._bare_user_re.sub(
                lambda m: protect(vid(m), "bare_username", m.group(0), m.group("u").lower()), text)
        return text

    def _apply_vocabulary(self, text: str, protect) -> str:
        """Known numeric ids, organisation terms (except inside a product
        constant) and person terms."""
        if self._id_re is not None:
            text = self._id_re.sub(lambda m: protect(PLACEHOLDER_ID, "known_id", m.group(0)), text)
        if self._org_re is not None:
            text = self._org_re.sub(
                lambda m: m.group(0) if in_product_constant(m) else protect(PLACEHOLDER_ORG, "org", m.group(0)), text)
        if self._person_re is not None:
            text = self._person_re.sub(lambda m: protect(PLACEHOLDER_NAME, "person", m.group(0)), text)
        return text


# --- leak scanner ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Leak:
    kind: str      # "user_id", "username", "phone", "name", "title", or a regex rule name
    match: str
    location: str = ""


@dataclass(frozen=True)
class Known:
    """Raw identifiers that must never appear in the anonymized output."""

    user_ids: frozenset[int] = frozenset()
    chat_ids: frozenset[int] = frozenset()
    usernames: frozenset[str] = frozenset()   # lowercase, without '@'
    chat_usernames: frozenset[str] = frozenset()  # those of them that name an exported chat
    phones: frozenset[str] = frozenset()      # digits only
    names: frozenset[str] = frozenset()       # full names and last names
    titles: frozenset[str] = frozenset()      # chat titles / org terms
    keep_terms: frozenset[str] = frozenset()
    card_bins: frozenset[str] = frozenset()   # cards with these BINs must be masked


class LeakScanner:
    """Detects identifying data. Regex classes are the scrubber's own table,
    so the scanner is exactly as strict as the scrubber is thorough."""

    # Ids shorter than this collide with ordinary numbers too often to scan for.
    MIN_ID_DIGITS = 6

    def __init__(self, known: Known, regex_rules: bool = True, url_allowed: Optional[Callable[[str], bool]] = None,
                 domain_allowed: Optional[Callable[[str], bool]] = None, custom_patterns: Iterable[str] = ()):
        """``url_allowed`` / ``domain_allowed`` say which links and bare
        domains the policy keeps; ``custom_patterns`` are the operator's
        extra regexes, reported as kind "custom"."""
        self.known = known
        self.regex_rules = regex_rules
        self.url_allowed = url_allowed
        self.domain_allowed = domain_allowed
        self._custom_res = [re.compile(p, re.IGNORECASE | re.MULTILINE | re.UNICODE) for p in custom_patterns]
        keep = {fold(k) for k in known.keep_terms}
        self._id_re = known_id_pattern(f for i in (*known.user_ids, *known.chat_ids) for f in id_forms(i)
                                       if len(str(f)) >= self.MIN_ID_DIGITS)
        # The three username shapes the scrubber replaces - after '@'
        # anywhere, bare handle-like ones, and any one after a handle keyword
        # - taken from a roster of the known usernames, so the scanner hunts
        # for exactly what the scrubber would have removed.
        users = Roster(by_username=dict.fromkeys(sorted({u.lower() for u in known.usernames if u}), ""),
                       chat_usernames=frozenset(u.lower() for u in known.chat_usernames),
                       keep_terms=tuple(known.keep_terms))
        self._username_res = [rx for rx in (users.at_username_pattern(), users.bare_username_pattern(),
                                            users.keyword_username_pattern()) if rx is not None]
        self._phones = KnownPhones(known.phones)
        self._card_bins = tuple(known.card_bins)
        self._keep_re = _keep_pattern(known.keep_terms)
        self._keep_folded = frozenset(keep)
        self._name_re = _term_pattern(n for n in known.names if fold(n) not in keep)
        self._title_re = _term_pattern((t for t in known.titles if fold(t) not in keep), org=True)

    def scan(self, text: str, location: str = "") -> list[Leak]:
        if not text:
            return []
        text = plain_text(normalize_digits(text).translate(_FULLWIDTH_PUNCT))
        unique: dict[str, Leak] = {}
        for leak in self._scan(text, location):
            unique.setdefault(leak.match.lower(), leak)
        return list(unique.values())

    def _scan(self, text: str, location: str) -> list[Leak]:
        leaks: list[Leak] = []
        # Scanned text contains resolved placeholders ("<passport>"); a rule
        # must not fire on the word inside one, and a keyword rule's value
        # slot may legitimately hold one ("password: <url>").
        # Only our own renderings are opaque. A typed autolink is not one of
        # them: "<mailto:ivan@example.com>", "<https://evil.example.com/x>"
        # and "<tel:+79161112233>" carry live values that must be reported,
        # while "<url:shop.example.com>" is the scrubber's own kept host.
        found = [p for p in _PLACEHOLDER_RE.finditer(text) if p.group("word") in _OWN_PLACEHOLDER_WORDS]
        placeholders = [p.span() for p in found if p.group("word") == "url" or ":" not in p.group(0)]
        # The card layer's own output: its six visible BIN digits are not a
        # value a keyword rule may claim ("код: 424242**********" is a masked
        # card, not a one-time code).
        masked_cards = masked_card_spans(text)
        own_ends = {p.end() for p in found}
        # Everything the scrubber itself wrote, word by word: the word inside a
        # placeholder, the handle it renders ("@user", "@U04217") and a masked
        # card. A vocabulary term or an operator pattern that spells one of
        # these describes our output, not a value the message still carries.
        own_spans = sorted([*(p.span("word") for p in found),
                            *(h.span() for h in _OWN_HANDLE_RE.finditer(text)), *masked_cards])

        def inside_placeholder(pos: int) -> bool:
            outer = _enclosing((pos, pos), placeholders)
            return outer is not None and outer[0] < pos < outer[1]

        def own_rendering(m: re.Match) -> bool:
            return _enclosing(m.span(), own_spans) is not None
        if self._id_re:
            leaks += [Leak("user_id", m.group(0), location) for m in self._id_re.finditer(text)]
        for rx in self._username_res:
            leaks += [Leak("username", m.group(0), location) for m in rx.finditer(text)]
        leaks += [Leak("phone", text[s:e], location) for s, e in self._phones.spans(text)]
        for span in find_cards(text, self._card_bins):
            leaks.append(Leak("card", text[span.start:span.end], location))
        for m in _MASKED_CARD_TRAILER.finditer(text):
            leaks.append(Leak("cvv" if m.group("cvv") else "expiry", m.group(0), location))
        if self._name_re:
            # A name inside a longer keep term ("Белый" in the kept "Белый
            # список") is the scrubber's deliberate choice. A title word
            # there is still reported: the product name itself belongs in
            # keep_terms.
            kept = [k.span() for k in self._keep_re.finditer(text)] if self._keep_re else []
            leaks += [Leak("name", m.group(0), location) for m in self._name_re.finditer(text)
                      if not own_rendering(m) and not _strictly_inside(m.span(), kept)]
        if self._title_re:
            leaks += [Leak("title", m.group(0), location) for m in self._title_re.finditer(text)
                      if not own_rendering(m) and not in_product_constant(m)]
        if self.regex_rules:
            keep_host = _keep_term_hosts(text, self._keep_re, self._keep_folded)
            for m in BARE_DOMAIN.finditer(text):
                if inside_placeholder(m.start()) or keep_host(m):
                    continue
                if not (self.domain_allowed and self.domain_allowed(m.group(0))):
                    leaks.append(Leak("domain", m.group(0), location))
            for rx in self._custom_res:
                leaks += [Leak("custom", m.group(0), location) for m in rx.finditer(text)
                          if m.group(0) and not inside_placeholder(m.start()) and not own_rendering(m)]
            for rule in _RULES:
                for m in rule.pattern.finditer(text):
                    if rule.accept and not rule.accept(m):
                        continue
                    if inside_placeholder(m.start()):
                        continue
                    if "val" in rule.pattern.groupindex:
                        val_start = m.start("val")
                        if (_PLACEHOLDER_RE.match(m.group("val")) or inside_placeholder(val_start)
                                or _value_in_virtual_id(text, val_start)
                                or _overlaps((val_start, m.end("val")), masked_cards)):
                            continue
                        if rule.name in ("person", "cardholder") and self._keep_re and self._keep_re.search(m.group("val")):
                            continue  # a keep term ("Northwind Support") is not a person
                    hit = m.group(0)
                    if rule.render is not None and rule.render(m) == hit:
                        continue  # already masked ("c_user=<cookie>")
                    if rule.name in ("handle", "handle_spaced") and (
                            _OWN_HANDLE_RE.fullmatch(hit) or m.start() in own_ends):
                        continue  # our own placeholders; a kept host after "https://<credentials>"
                    if rule.name == "email" and _VID_IN_FILE_NAME_RE.search(hit):
                        continue  # "scan_@U04217.pdf": a file name around a virtual id
                    if rule.name == "url":
                        # The scrubber reads a link's percent-encoded values
                        # as text, so the scanner reports what they spell.
                        decoded = _decode_escapes(hit)
                        if decoded != hit:
                            leaks += [x for x in self._scan(decoded, location) if x.kind != "url"]
                        if self.url_allowed and self.url_allowed(hit):
                            continue
                    if rule.name == "td_header" and _OWN_HANDLE_RE.fullmatch(m.group("who")):
                        continue  # "@user, [...]": the handle rule masked the pasted name first
                    leaks.append(Leak(rule.name, hit, location))
        return leaks
