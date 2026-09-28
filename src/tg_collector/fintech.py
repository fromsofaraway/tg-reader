"""Extended rules for financial and identity data found in support chats.

Everything clients commonly paste into a support chat beyond the generic
identifiers handled in ``scrub``:

* card companions: CVV, expiry, cardholder name (also surname + initials),
  3-D Secure / SMS codes, PIN, backup codes
* credential dumps ("login:pass:2fa:mail"), "user:pass" after a login flag
  or word ("curl -u", "логин") and for default accounts ("root:..."),
  passwords (also "-p" on a command line), 2FA secrets (also in groups of
  four), API keys with well-known prefixes (also the dotted SendGrid and
  Discord shapes), PEM private key blocks, HTTP Basic credentials,
  ``.env``-style assignments, cookies and access tokens, proxy strings
* crypto: seed phrases (BIP39), transaction hashes and wallet addresses (USDT
  TRC20/ERC20, BTC, LTC, TON, DOGE, XRP, Solana), exchange memos and UIDs
* identity documents of the CIS: KZ IIN/BIN, UA RNOKPP, BY personal number,
  UZ PINFL, KG PIN, passports and driver licences by keyword, dates of birth,
  residential addresses, postcodes
* people named next to a keyword: self-introductions, contact persons,
  signatures, sole proprietors, role words followed by a surname, initials
* ad-platform identifiers (Facebook act_/BM/pixel, Google Ads, TikTok),
  messenger ids by keyword, bank routing/sort codes and account numbers,
  payment-network references (RRN/ARN/auth codes), user-agent strings

Rules are keyword-gated wherever a bare pattern would also match product
vocabulary (amounts, decline codes, order numbers, country names), so the
knowledge base keeps *what* was discussed while the values disappear.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Callable

from .bip39 import WORDS as BIP39_WORDS, trie_regex
from .rules import (
    GROUP_SEP, HANDLE_START, MASKED_CARD, NO_PUA, NUMBER_END, NUMBER_START, USERNAME, Rule, element_rule,
    holds_replacement, keyword_rule, reads_as_identifier, value_group,
)

# --- placeholders ---------------------------------------------------------------------

P = {
    "cvv": "<cvv>", "exp": "<exp>", "holder": "<cardholder>", "otp": "<otp>", "pin": "<pin>",
    "credentials": "<credentials>", "password": "<password>", "2fa": "<2fa-secret>", "secret": "<token>",
    "cookie": "<cookie>", "token": "<token>", "private_key": "<private-key>", "proxy": "<proxy>", "seed": "<seed-phrase>",
    "txid": "<txid>", "wallet": "<wallet>", "id": "<id>",
    "iin": "<iin>", "company": "<company-id>", "rnokpp": "<rnokpp>", "personal": "<personal-id>",
    "tax": "<tax-id>", "snils": "<snils>", "passport": "<passport>", "licence": "<driver-licence>", "dob": "<dob>",
    "address": "<address>", "postcode": "<postcode>", "ad": "<ad-account>", "txn": "<txn-ref>", "ua": "<user-agent>",
    "name": "<name>", "bank_code": "<bank-code>", "account": "<account>",
    # The handle layer renders a login as a virtual id or "@user".
    "user": "@user",
}

# --- checksums ------------------------------------------------------------------------------

def kz_id_ok(d: str) -> bool:
    """Kazakhstan IIN (persons) and BIN (companies): 12 digits, mod-11 check."""
    if len(d) != 12 or not d.isdigit():
        return False
    s = sum(int(d[i]) * (i + 1) for i in range(11)) % 11
    if s == 10:
        w2 = [3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2]
        s = sum(int(d[i]) * w2[i] for i in range(11)) % 11
        if s == 10:
            return False
    return s == int(d[11])


def ua_rnokpp_ok(d: str) -> bool:
    """Ukraine RNOKPP (tax number of a person): 10 digits."""
    if len(d) != 10 or not d.isdigit():
        return False
    w = [-1, 5, 7, 9, 4, 6, 10, 5, 7]
    return (sum(int(d[i]) * w[i] for i in range(9)) % 11) % 10 == int(d[9])


def _kz_person(d: str) -> bool:
    """IIN starts with a birth date (YYMMDD) and a century/sex digit 1-6."""
    return d[2:4] in {f"{m:02d}" for m in range(1, 13)} and 1 <= int(d[4:6]) <= 31 and d[6] in "123456"


# --- accept callbacks --------------------------------------------------------------------------

_ERROR_CONTEXT = re.compile(r"(?:ошиб|причин|отказ|error|reason|declin|response|resp|mcc|мсс|http|status|статус)\w*\W*$",
                            re.IGNORECASE)
_ERROR_WORD = re.compile(r"ошиб|причин|отказ|error|reason|declin|response|status|статус|mcc|мсс", re.IGNORECASE)


def not_error_code(m: re.Match) -> bool:
    """A number after "code" is an outcome ("error code 4001", "decline code
    05"), not a secret, when an error word precedes it."""
    before = m.string[max(0, m.start() - 24):m.start()]
    inside = m.group("kw") + m.group("gap")
    return not _ERROR_CONTEXT.search(before) and not _ERROR_WORD.search(inside)


# Order, ticket, transaction and payment numbers are product knowledge, yet
# one random 10-digit number in eleven passes the RNOKPP check, and as many
# pass the INN, OGRN or IIN check. The checksum-only rules therefore spare a
# number written right after such a label: only punctuation, "№"/"#", "id",
# "no."/"номер" or one line break in between ("заказ №3184713454", "Номер
# заказа:\n3184713454", "order_id=7700000425"). The label list is closed on
# purpose: "заказчик" (the customer), a bare "платёж"/"оплата"/"перевод"/
# "чек" and a bare "id" introduce requisites as often as references ("ИНН
# заказчика: ...", "реквизиты для оплаты: ...", "national ID: ..."). An
# earlier replacement between the label and the number ends the label, so
# the scrubber (sentinels) and the leak scanner (placeholders) agree.
_OPERATION_GAP = rf"[^\w\n<{NO_PUA}]"
# Masculine nouns that decline alike, so one ending class serves all three.
_MASCULINE_ENDING = r"(?:а|у|ом|е|ы|ов|ам|ами|ах)?"
_OPERATION_NOUN = (
    rf"(?:заказ|тикет|инвойс){_MASCULINE_ENDING}"
    r"|транзакци(?:я|и|ю|ей|й|ям|ями|ях)|обращени(?:е|я|ю|ем|и|й|ям|ями|ях)|заяв(?:к(?:а|и|у|ой|е|ам|ами|ах)|ок)"
    r"|orders?|tickets?|transactions?|txns?|invoices?"
    rf"|(?:номер|id|№){_OPERATION_GAP}{{0,3}}(?:платежа|операции|оплаты)|payment[ _\-]?id")
_OPERATION_LABEL = re.compile(
    rf"(?<![\w<@\-])(?:{_OPERATION_NOUN})"
    rf"(?:(?:{_OPERATION_GAP}|_){{0,3}}(?:id|no\.?|nr\.?|number|(?:под[ \t]+)?номер(?:ом)?))?"
    rf"(?:{_OPERATION_GAP}|_){{0,4}}(?:\n{_OPERATION_GAP}{{0,4}})?\Z", re.IGNORECASE)
# A plural label carries over the whole list it introduces: in "заказы:
# 3184713454, 7700000425, 7700000016" every number is a reference, not only
# the first, and one of them passing a tax-id checksum by chance must not
# turn it into <tax-id>. The list is the numbers seen so far, each closed by
# ',', ';' or '/'; anything else between the label and the number (a word, a
# line break) ends it, so "заказы: 12345, ИНН 7700000425" is a tax id again.
_OPERATION_PLURAL = (
    r"(?:заказ|тикет|инвойс)(?:ы|ов|ам|ами|ах)"
    r"|транзакци(?:и|й|ям|ями|ях)|обращени(?:я|й|ям|ями|ях)|заяв(?:ки|ок|кам|ками|ках)"
    r"|orders|tickets|transactions|txns|invoices")
_OPERATION_LIST = re.compile(
    rf"(?<![\w<\-])(?:{_OPERATION_PLURAL})[^\w\n<]{{0,4}}"
    rf"(?:\d{{5,20}}[ \t]*[,;/][ \t]*)+\Z", re.IGNORECASE)
# How far back a list label may stand from the number it introduces.
_OPERATION_LIST_REACH = 160
# ...unless the number belongs to someone: a tax-id, requisite or
# counterparty word shortly before it keeps the checksum in charge ("ИНН по
# заказу: 7700000425", "реквизиты заказчика, заявка 020531600149").
_NUMBER_OWNER = re.compile(
    r"(?<![\w<\-])(?:ИНН|ИИН|БИН|ЖСН|КПП|УНП|ИПН|ІПН|ОГРН(?:ИП)?|РНОКПП|РНУКПН|ЄДРПОУ|ЕГРПОУ|ЕДРПОУ|ПИНФЛ|ПІНФЛ|СНИЛС"
    r"|inn|iin|tin|tax|налог\w*|податк\w*|реквизит\w*|реквізит\w*|плательщик\w*|платник\w*|получател\w*"
    r"|отримувач\w*|отправител\w*|відправник\w*|контрагент\w*|заказчик\w*|замовник\w*|payer|payee|beneficiar\w*"
    r"|паспорт\w*|passport|national|(?:личн|персональн|personal)\w*[ \t]+(?:номер|код|идентификац|number|id)\w*)"
    r"(?![\w])", re.IGNORECASE)
# The same word right behind the number instead of in front of it ("заявка
# 651214316007 (иин)", "7700000425 - ИНН"), which only a bracket or a dash
# makes unambiguous: after a comma or a space the word introduces the next
# number instead ("заказ 7700000425, ИНН плательщика 7701234567").
_NUMBER_OWNER_AFTER = re.compile(r"[ \t]*[(\[\-—–][ \t]*(?:ИИН|ИНН|БИН|ЖСН|ИПН|IIN|INN|BIN)(?![\w])",
                                 re.IGNORECASE)


def not_operation_ref(m: re.Match) -> bool:
    """Accept check for the bare checksum rules (INN, OGRN, KZ IIN/BIN, UA
    RNOKPP): False when the matched number is an order, ticket, transaction
    or payment reference, by its own label (``_OPERATION_LABEL``) or as one
    item of a labelled list (``_OPERATION_LIST``), and no tax-id or
    requisites word precedes it (``_NUMBER_OWNER``) or stands right behind it
    in brackets or after a dash (``_NUMBER_OWNER_AFTER``)."""
    start = m.start()
    if not (_OPERATION_LABEL.search(m.string, max(0, start - 40), start)
            or _OPERATION_LIST.search(m.string, max(0, start - _OPERATION_LIST_REACH), start)):
        return True
    return (_NUMBER_OWNER.search(m.string, max(0, start - 60), start) is not None
            or _NUMBER_OWNER_AFTER.match(m.string, m.end()) is not None)


_OTHER_NUMBER = re.compile(r"заказ|order|ticket|тикет|invoice|инвойс|сч[её]т|сумм|amount|верси|version|build|сборк|лимит|limit"
                           r"|балан|balance|(?<![\w])id(?![\w])|account|аккаунт", re.IGNORECASE)

# Only a bare "код"/"code" can name a reference; "код подтверждения", "otp"
# and "3ds код" always introduce a one-time code.
_BARE_CODE = re.compile(r"код(?:а|ы|ов|ом|у|е)?|codes?", re.IGNORECASE)
# Right before a bare "код": a kind word ("ответный код 4001" = response
# code, "promo code", "merchant code") or a decline with a preposition
# ("отклонена с кодом 4001", "отказ по коду 4001"). Nouns only: "ошиблась с
# кодом, правильный 482913" (made a mistake with the code) is a one-time code.
_REFERENCE_BEFORE = re.compile(
    r"(?<![\w])(?:(?:ответн|промо|promo|coupon|discount|merchant|terminal|category|currency|country|result|area"
    r"|мсс|mcc|тсп)\w{0,2}"
    r"[^\w\n]{0,3}|(?:ошибк|ошибок|отказ|отклон|declin|reject)\w*[^\S\n]+(?:с|со|по|под|with|by)[^\S\n]+)$",
    re.IGNORECASE)
# A kind word in the genitive right after a bare "код" names what the number
# identifies, not a one-time code: "код ответа" (response code), "код
# категории" (MCC), "код товара" (product code), "Код ТСП" (merchant code).
# "операции", "подтверждения" and "активации" are deliberately absent: they
# label the bank's own one-time codes.
_CODE_KIND = (r"[^\S\n]*[-–—]?[^\S\n]*(?:ответ(?:а|ов)|результат(?:а|ов)|возврат(?:а|ов)|категори[ийя]"
              r"|терминал(?:а|ов)|магазин(?:а|ов)|мерчант(?:а|ов)|валют(?:ы)?|стран(?:ы)?|город(?:а|ов)"
              r"|регион(?:а|ов)|товар(?:а|ов)|купон(?:а|ов)|акци[ий]|продукт(?:а|ов)|тариф(?:а|ов)|услуг(?:и)?"
              r"|партн[её]р(?:а|ов)|филиал(?:а|ов)|точки|кассы|скидки|бонус(?:а|ов)|тсп|мсс|mcc)(?![\w])")
# A rejected match still consumes its text, so a check on the text before
# the keyword applies only when the gap is one phrase: in "Код ответа не
# пришёл, код 482913" the second "код" must be reached.
_GAP_BREAK = re.compile(r"[,.;!?]|(?<![\w])(?:код|code)", re.IGNORECASE)
# Decline and response codes are short; SMS codes are mostly six digits.
_REFERENCE_MAX_DIGITS = 5
# "код 4001 означает недостаточно средств" (code 4001 means insufficient
# funds): a code that the text goes on to explain is a glossary entry, also
# as a short list ("коды 4001 и 4002 означают отказ"). "это" (is), "значит"
# (means) and "=" count only before an outcome word ("код 5003 = таймаут",
# "код 6001 это отказ"): around an arriving one-time code they are fillers
# ("пришёл код 4829 это он?"). Every separator run matches one way only, so
# a failing tail cannot backtrack.
_CODE_LIST = r"(?:[ \t]*(?:[,;/][ \t]*)?(?:(?:и|или|and|or)[ \t]+)?\d{2,5}(?!\d))*"
_OUTCOME = r"(?:отказ|отклон|недостат|ошибк|таймаут|timeout|insufficient|declin|do not honou?r|error)"
_EXPLAINED = re.compile(
    rf"{_CODE_LIST}[ \t]*(?:(?:[-—–:][ \t]*)?(?:означа|обознача|расшифровыва|means(?![\w])|stands for|indicates)"
    rf"|(?:[-—–:=][ \t]*)?(?:это|значит)[ \t]+{_OUTCOME}|=[ \t]*{_OUTCOME})", re.IGNORECASE)


# A glossary entry of a decline code: the line starts with the code (often
# behind a list marker or a table pipe) and goes on to name the reason. Such
# a line explains what a code means, so the number is product knowledge, not
# an arriving one-time code. A ':' right after the keyword ("Код: 4821 —
# недостаточно средств") is a label, so the number is the value of that
# label and stays an OTP.
_DECLINE_REASON = (r"(?:карт[аы][^\S\n]+)?заблокирован\w*|утерян\w*|украден\w*|недостаточно[^\S\n]+средств"
                   r"|превышен\w*[^\S\n]+(?:лимит\w*[^\S\n]+(?:по[^\S\n]+карт\w*|на[^\S\n]+(?:снятие|списание)"
                   r"|операц\w*|сумм\w*|снят\w*|списан\w*)|сумм\w*|остат\w*)|отказ\w*[^\S\n]+(?:эмитент\w*|банк\w*"
                   r"|эквайер\w*|в[^\S\n]+обслуживании)|неверн\w*[^\S\n]+(?:cvv|cvc|pin|пин\w*|срок\w*)"
                   r"|ист[её]к\w*[^\S\n]+срок|insufficient|do[^\S\n]+not[^\S\n]+hono]?u?r|(?:restricted|stolen|lost)"
                   r"[^\S\n]+card|card[^\S\n]+(?:blocked|restricted|lost|stolen)|таймаут|timeout")
_ENTRY_MARK = r"(?:\*\*|`|__)?"
_ENTRY_START = re.compile(rf"(?:^|\n)[ \t]*(?:[-*\u2022|>][ \t]*|\d{{1,2}}[.)][ \t]*)?{_ENTRY_MARK}[ \t]*$")
_DECLINE_ENTRY = re.compile(
    rf"{_CODE_LIST}[ \t]*{_ENTRY_MARK}[ \t]*[-\u2014\u2013:=(|\t\n][ \t]*{_ENTRY_MARK}[ \t]*(?:{_DECLINE_REASON})",
    re.IGNORECASE)
# "падает с кодом 5003", "вылетает с кодом 4001": the code names the failure.
_CRASH_BEFORE = re.compile(r"(?<![\w])(?:пада|упал|вылета|отвалива|заверша|крашит|ошиба)\w*[^\S\n]+со?[^\S\n]*$",
                           re.IGNORECASE)


# A glossary of codes lists one code per line ("- 4001 — неверный CVV\n-
# 4002 — неверный PIN"). Without this check the keyword that ends one entry
# takes the code that opens the next one. Both lines must look the same: the
# same list marker, codes of the same shape, and separators that start with
# the same character.
_ENTRY_HEAD = re.compile(r"[ \t]*(?P<mark>[-*\u2022|]|\d{1,2}[.)])?[ \t]*(?P<code>[A-Za-z]{0,4}\d{3,6})"
                         r"(?P<sep>[ \t]*(?:[\u2014\u2013|]|-[ \t]|:[ \t]))")


def _line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def _list_entry(m: re.Match) -> bool:
    """The keyword ends one entry of a code list and the value opens the
    next one, so the value is that entry's code, not the keyword's."""
    gap = m.group("gap")
    if "\n" not in gap or ":" in gap or "=" in gap:
        return False
    head = _ENTRY_HEAD.match(m.string, _line_start(m.string, m.start()))
    entry = _ENTRY_HEAD.match(m.string, _line_start(m.string, m.start("val")))
    if not head or not entry or entry.end("code") != m.end("val"):
        return False
    return (head.group("mark") == entry.group("mark")
            and len(head.group("code")) == len(entry.group("code"))
            and head.group("code").rstrip("0123456789") == entry.group("code").rstrip("0123456789")
            and head.group("sep").strip()[:1] == entry.group("sep").strip()[:1])


def _decline_entry(m: re.Match) -> bool:
    """The number is a decline code explained on its own line."""
    return (":" not in m.group("gap")
            and bool(_ENTRY_START.search(m.string, max(0, m.start() - 40), m.start()))
            and bool(_DECLINE_ENTRY.match(m.string, m.end(), m.end() + 120)))


def _otp_context_ok(m: re.Match) -> bool:
    """An OTP keyword must not reach across another label ("codes expired,
    заказ 12345678") nor follow an error word. A bare "код"/"code" also names
    references (the Russian code kinds, "код ответа", are excluded by the
    keyword itself): after a kind word or a decline ("ответный код 4001",
    "отказ по коду 4001"), and, for a short number, when the text goes on to
    explain it ("код 4001 означает ...") or it is a numeric JSON field
    ('"code": 4001'). These checks are OTP-only: the backup-code and card-CVV
    rules keep the plain ``not_error_code`` gate."""
    gap = m.group("gap")
    if not not_error_code(m) or _OTHER_NUMBER.search(gap) or _list_entry(m):
        return False
    if not _BARE_CODE.fullmatch(m.group("kw")):
        return True
    if _REFERENCE_BEFORE.search(m.string, max(0, m.start() - 24), m.start()) and not _GAP_BREAK.search(gap):
        return False
    if len(value_group(m)) > _REFERENCE_MAX_DIGITS:
        return True
    if _CRASH_BEFORE.search(m.string, max(0, m.start() - 40), m.start()) and not _GAP_BREAK.search(gap):
        return False
    json_number = m.string[max(0, m.start() - 1):m.start()] in ('"', "'") and not gap.endswith(('"', "'"))
    return not json_number and not _decline_entry(m) and not _EXPLAINED.match(m.string, m.end(), m.end() + 80)


# The gap of a card-companion rule ("cvv", "exp", "pin") that ends in an
# error word or, after a clause break, in another number label holds an
# error code or an order number, not the companion: "cvv mismatch, error
# 4001", "пин ошибка E1234", "cvv верный, заказ 4821". Labels start a word
# ("насчёт" is no "счёт", "border" no "order"); error nouns only ("cvv
# ошиблась, верный 456" is still a CVV), "заказчик" (customer) is no order,
# and a number label needs the break ("cvv к счёту 123" is a CVV). Anchored
# at the gap end, a rejected match never hides a later companion value: the
# gap has no digits, so a keyword inside it would take the same number.
_LABEL_TAIL = (r"\w*(?:[^\S\n]+(?:банка|эмитента|эквайера|оплаты|платежа|транзакции|bank|issuer))?"
               r"(?:[^\w\n]+(?:код\w*|code|номер|no))?[^\w\n]*(?-i:E|ERR)?$")
_COMPANION_STOP = re.compile(
    rf"(?<![\w])(?!ошиб(?!к|ок))(?:{_ERROR_WORD.pattern}){_LABEL_TAIL}"
    rf"|[,.;!?)—–][^\n]*?(?<![\w])(?!заказчи)(?:{_OTHER_NUMBER.pattern}){_LABEL_TAIL}", re.IGNORECASE)


def _companion_value_ok(m: re.Match) -> bool:
    return not _COMPANION_STOP.search(m.group("gap")) and not _list_entry(m)


def _has_digit(m: re.Match) -> bool:
    return any(c.isdigit() for c in value_group(m))


# One identifier written as keyword and value with nothing in between
# ("PASSWORD_MIN_LENGTH=8", "password_reset_flow_v2", "tokens_rotation_plan_v2.docx"):
# words of one case, numbers and version tags joined by '_', '.' or '-', or
# one camelCase word. A lower-case name needs three pieces, because two
# ("password_hunter") are as often a keyword and a password glued together;
# an ALL_CAPS constant is product knowledge from the first separator on.
_GLUED_NAME = re.compile(
    r"[A-Z]{1,24}(?:[_.\-](?:[A-Z]{1,24}|\d{1,8}|V\d{1,3}))+"
    r"|[a-z]{1,24}(?:[_.\-](?:[a-z]{1,24}|\d{1,8}|v\d{1,3})){2,}"
    r"|[a-z]{1,24}(?:[A-Z][a-z]{1,24})+")
# What may follow the '=' or ':' of such a name and still leave it a
# setting: nothing, a small number, a plain word, or an earlier replacement.
_NAME_REST = re.compile(r"\d{1,3}|[a-z]{1,24}|[A-Z]{1,24}")


def _glued_name(m: re.Match) -> bool:
    """The keyword and the value are one identifier, with no separator
    between them: a constant, a setting or a file name rather than a secret
    ("ошибка PASSWORD_EXPIRED", "password_min_length: 8",
    "tokenization_v2_rollout_plan")."""
    if m.group("gap"):
        return False
    name, separator, rest = (m.group("kw") + value_group(m)).partition("=")
    if not separator:
        name, _, rest = name.partition(":")
    return bool(_GLUED_NAME.fullmatch(name)) and (
        not rest or bool(_NAME_REST.fullmatch(rest)) or holds_replacement(rest))


def _api_key_ok(m: re.Match) -> bool:
    """A token has letters and digits. A keyword and value glued into one
    identifier are a constant or a file name ("TOKEN_INVALID_SIGNATURE_2026",
    "tokens_rotation_plan_v2.docx"). A REST path is documentation, unless
    a long number sits anywhere in it: three or more segments right after
    the keyword ("token /api/v2/auth/refresh.json", "токен: /oauth/v2/x1")
    or the rest of a path the keyword is a segment of
    ("/api/v2/oauth/token/refresh/2026-03-12"). A random token rarely holds
    two slashes and plain pieces only."""
    v = value_group(m)
    if not (any(c.isdigit() for c in v) and any(c.isalpha() for c in v)) or _glued_name(m):
        return False
    in_path = v.count("/") >= 2 or ("/" in v and m.string[m.start() - 1:m.start()] == "/")
    return not (in_path and reads_as_identifier(v, path_numbers_visible=False))


def _has_digit_and_letter(m: re.Match) -> bool:
    v = m.group(0)
    return any(c.isdigit() for c in v) and any(c.isalpha() for c in v)


# Punctuation that is ordinary inside shell words and identifiers ("app_db",
# "backup.tar", "prod-1", "/var/log"): it does not make a value a secret.
_SHELL_WORD = "_.-/"


def _mixed_case(v: str) -> bool:
    return v != v.lower() and v != v.upper()


def _secret_like(v: str, ordinary: str = "") -> bool:
    """A plain word is prose; a secret has a digit, a symbol or mixed case.
    ``ordinary`` lists punctuation that does not count as a symbol."""
    return any(c.isdigit() for c in v) or any(not c.isalnum() and c not in ordinary for c in v) or _mixed_case(v)


def _pem_marker(m: re.Match) -> bool:
    """The value slot holds the BEGIN line of a PEM block, which the
    private_key rule owns (a keyword rule meets it on the scanner's view of
    scrubbed text, or on a paste cut before its END line)."""
    return (m.group("gap") + value_group(m)).endswith("-----BEGIN")


# A Telegram username after '@' (also our "@U04217"), in the shape the handle
# rule removes: that rule takes it later. Glued to a Latin word
# ("password@Qwerty123") it is no handle and stays a password.
_AT_HANDLE = re.compile(HANDLE_START + USERNAME)


# Words of validation and error messages ("This field is required.", Russian
# "Не менее 8 символов" = "at least 8 characters") and of empty settings
# ("not set", Russian "не задан"). Russian entries are stems, English ones
# whole words.
_MESSAGE_WORD = re.compile(
    r"(?<![^\W\d_])(?:(?:ошиб|неверн|неправильн|некорректн|недопустим|обязательн|должн|символ|менее|минимум|подход"
    r"|совпада|пуст|коротк|слаб|ист[её]к|заполн|введите|укажите|задан|указан|отсутств)"
    r"|(?:error|invalid|incorrect|wrong|required|must|should|characters?|least|match(?:es)?|empty|blank|short|weak"
    r"|expired|field|not|none|null|unset|missing|undefined)(?![^\W\d_]))",
    re.IGNORECASE)
# A value that is itself an error, outcome or state word, not a password:
# "пароль:\nошибка 4012", "пароль: неверный" (wrong), "Пароль Устарел"
# (outdated), "password: expired", and the 3-D Secure product term ("did
# not pass 3ds-check"). A closed list matched against the whole value; the
# Russian stems take Cyrillic inflection tails only, so a digit or a symbol
# makes the value a password again ("неверный1", "Забыл12").
_PASSWORD_PROSE = re.compile(
    r"ошибк[аиуеой]?|ошибок|отказ[аеуы]?|статус[аеу]?"
    r"|(?:не)?(?:верн|правильн|валидн|корректн)[а-яё]{0,3}|(?:не)?вер(?:ен|на|но|ны)|ошибочн[а-яё]{0,3}"
    r"|ист[её]к[а-яё]{0,3}|просрочен[а-яё]{0,2}|сброшен[а-яё]{0,2}|сбросил[аи]?|измен[её]н[а-яё]{0,2}"
    r"|сменил[аи]?|смен[её]н[а-яё]{0,2}|обновл[её]н[а-яё]{0,2}|устарел[а-яё]{0,2}|забыл[а-яё]{0,2}"
    r"|утерян[а-яё]{0,2}|потерян[а-яё]{0,2}|принят[а-яё]{0,2}|заблокирован[а-яё]{0,2}"
    r"|подходит|подош[её]л|подошл[аи]|сработал[а-яё]{0,2}|работает|отклон[её]н[а-яё]{0,2}"
    r"|нужен|нужна|нужно|требуется|отсутствует|любой|прош[её]л|прошл[аи]"
    r"|(?:пуст|стар|нов|временн|одноразов)(?:ый|ой|ая|ое|ые)|прежн(?:ий|яя|ее|ие)"
    r"|errors?|status|declined?|incorrect|wrong|invalid|expired|reset|changed|updated|unknown|forgot(?:ten)?"
    r"|correct|valid|accepted|rejected|missing|required|needed|empty|blank|same|temporary|unchanged|mismatch"
    r"|failed|works|working|okay|3-?d-?s(?:ecure)?(?:-[a-z]+)?"
    r"|скрыт[а-яё]{0,3}|удал[её]н[а-яё]{0,2}|удалил[аи]?|null|none|nil|true|false|undefined", re.IGNORECASE)


# A quoted value that describes where the secret comes from instead of
# spelling it out ('"secret_key": "выдаётся менеджером"', 'SECRET_KEY="см.
# README"', 'api_key: "храним в Vault"'), or a template placed there by a
# config generator ("${API_TOKEN}", "{{ secret }}"). Anchored at the start of
# the value: a description opens with its verb or pointer, while a secret
# with a lead-in word is still a secret ('"ключ из кабинета: Xy7Pq2Lm"').
# Word forms are spelled out rather than stemmed, so "хранитель" (keeper) is
# no "хранится" (is kept).
_VALUE_DESCRIPTION = re.compile(
    r"(?:см\.?|смотри|see[ \t]+(?:docs?|readme|below|above|the)"
    r"|выда[её]тся|выдают|выдаём|выдаем|генерируется|генерируются|созда[её]тся|зада[её]тся|бер[её]тся"
    r"|хранится|хранятся|храним(?:ся)?|храню|приходит|прид[её]т|придут|высыла(?:ется|ем|ют)"
    r"|указан(?:о|а|ы)?|укажите|возьмите|получите|запросите|ротаци(?:я|и|ю|ей)"
    r"|только|по[ \t]+запросу|будет[ \t]+в|тестов(?:ый|ая|ое)[ \t]+(?:ключ|токен|пароль|секрет)"
    r"|не[ \t]+(?:использу\w+|нужен|нужна|нужно|требуется|задан\w*|указан\w*)"
    r"|(?:из|в)[ \t]+(?:лк|личн\w+[ \t]+кабинет\w*|кабинет\w*|письм\w+|vault|\.env|почт\w+)"
    r"|(?:ваш|ваша|ваше|your)[ \t]+(?:api[ \t]+)?(?:ключ|пароль|токен|секрет|key|password|token|secret))"
    r"(?![^\W\d_])|\$\{|\{\{|<", re.IGNORECASE)
_WORD = re.compile(r"[^\W_]+")


def _holds_secret_word(v: str) -> bool:
    """A word of four or more characters with both a letter and a digit, or
    with a capital inside it: the value spells a secret out after all
    ('"ваш ключ AbCd 1234"'), whatever it says around it."""
    return any(len(w) >= 4 and ((any(c.isdigit() for c in w) and any(c.isalpha() for c in w))
                                or (any(c.isupper() for c in w[1:]) and any(c.islower() for c in w)))
               for w in _WORD.findall(v))


def _quoted_text_ok(v: str) -> bool:
    """Whether a value of several words is a passphrase rather than prose.
    Only a quoted slot (``_quoted_value``) yields one, so a value without
    spaces is nothing to judge and passes. Prose here is a validation or
    error message, or a note about where the secret is kept with no word in
    it that spells one out."""
    if not any(c.isspace() for c in v):
        return True
    if _MESSAGE_WORD.search(v):
        return False
    return not (_VALUE_DESCRIPTION.match(v) and not _holds_secret_word(v))


# More text after a word on its line: after a multi-word label that ends its
# line ("Пароль от ЛК:\nверсия 2.3.1") a letters-only word that starts a
# sentence is not the password; a lone one is.
_LINE_GOES_ON = re.compile(r"[ \t]+[^\s]")
# A length policy instead of a password ("пароль 8-64 символа", "пароль:
# минимум 8 символов", '"password_policy": "min 8 chars"'). The number is
# short and the unit word follows it after a blank, so "пароль: 12345678
# символов" stays a password.
_LENGTH_SPEC = re.compile(
    r"(?:(?:минимум|максимум|min|max|от|до|не[ \t]+(?:менее|более|короче|длиннее))[ \t]+)?"
    r"\d{1,3}(?:[ \t]*[-–—][ \t]*\d{1,3}|\+)?[ \t]+"
    r"(?:символ|знак|цифр|букв|character|char|digit|letter|symbol)", re.IGNORECASE)
# Words that say where the password comes from or what it must look like
# instead of being one ("пароль: придёт отдельным письмом", "пароль: только
# латиница"). Spelled out per form: "хранитель" is no "хранится".
_PASSWORD_INSTRUCTION = re.compile(
    r"прид[её]т|придут|приходит|приходят|отправ(?:им|ил[аи]?|лю|ляется|ляем|ится|ят|лен[ао]?)"
    r"|генерир(?:уется|уются|уем|ую)|зада[её]тся|задают|бер[её]тся|хранится|хранятся|храним(?:ся)?"
    r"|латиниц(?:а|ы|у|ей)|регистр|чувствителен|чувствительн(?:ый|ая|ое)|сброс(?:ится|им|ите)"
    r"|высыла(?:ется|ем|ют)|выда[её]тся|выдают|указыва(?:ется|ют)|минимум|максимум|только",
    re.IGNORECASE)
# The rest of the sentence after the value, bounded so that a keyword
# repeated over a long text costs the same per match.
_SENTENCE_TAIL = re.compile(r"[^.!?;\n]{0,120}")
_DIGIT_WORD = re.compile(r"[^\W_]*\d")
# How long a number must be to read as the operation's own number.
_OPERATION_NUMBER_DIGITS = 6


def _instruction_value(m: re.Match) -> bool:
    """The value is an instruction word and the sentence goes on without
    naming a password ("пароль: придёт отдельным письмом"). A lone
    instruction word is still the value ("пароль: придёт"), and so is a real
    password behind one ("пароль: только Qwerty123")."""
    if not _PASSWORD_INSTRUCTION.fullmatch(value_group(m)):
        return False
    rest = _SENTENCE_TAIL.match(m.string, m.end("val")).group()
    return bool(rest.strip()) and not _DIGIT_WORD.search(rest)


def _operation_number(m: re.Match) -> bool:
    """The value is the number of the operation the label names, not a
    password ("пароль к заказу 90829441 не нужен"): no ':' or '=' introduces
    it, and the sentence goes on past it."""
    v = value_group(m)
    return (v.isdigit() and len(v) >= _OPERATION_NUMBER_DIGITS
            and not any(ch in m.group("gap") for ch in ":=")
            and _OPERATION_LABEL.search(m.group("gap")) is not None
            and _LINE_GOES_ON.match(m.string, m.end("val")) is not None)


def _looks_like_password(m: re.Match) -> bool:
    """Reject plain words after a password keyword (Russian "пароль
    неверный" = "password is wrong"): a real password has a digit, a symbol,
    mixed case, or follows ':'/'='. A value that already holds a replacement,
    a handle ("с паролем @oleg_support"), a label that talks about an error,
    an error or outcome word as the value ("пароль: неверный") and a
    letters-only word that starts a sentence on the line after a label are
    not passwords either. Neither is the prose that answers what the password
    must look like, where it comes from or which operation it belongs to."""
    v, gap = value_group(m), m.group("gap")
    if holds_replacement(v) or _pem_marker(m) or _ERROR_WORD.search(gap) or _list_entry(m):
        return False
    if _PASSWORD_PROSE.fullmatch(v) or not _quoted_text_ok(v):
        return False
    if (_glued_name(m) or _LENGTH_SPEC.match(m.string, m.start("val"))
            or _instruction_value(m) or _operation_number(m)):
        return False
    if (v.isalpha() and "\n" in gap and any(c.isalpha() for c in gap)
            and _LINE_GOES_ON.match(m.string, m.end("val"))):
        return False
    if gap.endswith("@") and _AT_HANDLE.fullmatch(m.string, m.start("val") - 1, m.end("val")):
        return False
    if any(ch in gap for ch in ":="):
        return True
    return _secret_like(v, " ")


# The whole value is a template a config generator fills in: "API_TOKEN=${API_TOKEN}".
_TEMPLATE_VALUE = re.compile(r"\$\{[^{}]*\}|\{\{[^{}]*\}\}|%\([^()]*\)s|%[sd]")
# An element carrying no value: a flag, an empty or masked setting, a
# template, or a placeholder an earlier layer already wrote.
_EMPTY_VALUE = re.compile(rf"true|false|null|none|nil|undefined|n/?a|[-–—]+|\?+|\*+|x{{3,}}|@(?:user|[UC]\d+)"
                          rf"|{_TEMPLATE_VALUE.pattern}", re.IGNORECASE)


def _element_value_ok(m: re.Match) -> bool:
    """"<ExpirePassword>true</ExpirePassword>" and "<ApiKey>${API_KEY}</ApiKey>"
    state a setting, not a secret."""
    v = value_group(m)
    return not (holds_replacement(v) or _EMPTY_VALUE.fullmatch(v))


def _env_value_ok(m: re.Match) -> bool:
    """The name must look like an environment variable (upper case or with
    '_': "bypass:" is prose) and the value like a secret ("ERROR_TOKEN=INVALID"
    is prose), with the same heuristic as ``_looks_like_password``. A quoted
    value with spaces after such a name is a passphrase unless it reads as a
    message or as a note about where the secret is kept."""
    kw, v = m.group("kw"), value_group(m)
    if not ("_" in kw or kw.isupper()) or _pem_marker(m) or holds_replacement(v):
        return False
    if _TEMPLATE_VALUE.fullmatch(v):
        return False
    if any(c.isspace() for c in v):
        return _quoted_text_ok(v)
    return _secret_like(v)


def _unquote(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


# A command that takes a login, earlier on the same line as a "-p" flag.
_LOGIN_COMMAND = re.compile(
    r"(?<![\w-])(?:-u|--user(?:name)?|login|mysql\w*|mariadb\w*|psql|mongo\w*|redis-cli|sqlplus|smbclient|sshpass|ftp)"
    r"(?![\w-])[^\n]*$", re.IGNORECASE)
# Commands whose "-p" names a project, a profile, a path or a git ref, never
# a password ("docker compose -p Northwind2 up", "git log -p HEAD~3", "mkdir
# -p app/logs"). The command must own the flag: only ordinary argument
# characters may stand between them, so a second command after ';', '&&',
# '|' or a comma, or after a Russian word, is judged on its own ("git pull;
# mysql -u root -pS3cret99"). "docker run" and "docker exec" hand the line
# to another program, which may well take a password, so they end the run.
# The list is short on purpose: a command listed here in front of a real
# password would leak it, while an unlisted one only over-scrubs.
_CLI_ARGUMENT = r"[^;&|()`,\nА-Яа-яЁё]"
_NO_PASSWORD_COMMAND = re.compile(
    rf"(?<![\w.-])(?:(?:git|gh|mkdir|cp|ls|helm|kubectl|npm|npx|yarn|pnpm|k6|ansible[\w-]*|terraform|gradle|mvn"
    rf"|tsc|pytest)(?![\w-]){_CLI_ARGUMENT}*"
    rf"|(?:docker(?:-compose|[ \t]+compose)|podman-compose)(?![\w-])"
    rf"(?:(?!(?<![\w-])(?:run|exec)(?![\w-])){_CLI_ARGUMENT})*)\Z", re.IGNORECASE)
# How far back the command that owns a "-p" flag may stand.
_CLI_COMMAND_REACH = 160


def _cli_password_ok(m: re.Match) -> bool:
    """A value after "-p" is never another flag, a path or a port (it needs
    a letter), and never the next line (a trailing "-p" prompts for the
    password). A command that has no password to give ends it there. A
    strong value, a digit plus mixed case or a real symbol, counts anywhere;
    a weaker one only when spaced from the flag on a command line that logs
    in ("mysql -u root -p secret99"): elsewhere "-p" is a port, a profile or
    a flag ("cp -p file1 file2", "-print0")."""
    v = _unquote(value_group(m))
    if not v or v[0] in "-/.~<" or not any(c.isalpha() for c in v) or "\n" in m.group("gap"):
        return False
    command = _NO_PASSWORD_COMMAND.search(m.string, max(0, m.start() - _CLI_COMMAND_REACH), m.start())
    if command and not _LOGIN_COMMAND.search(command.group()):
        return False
    if any(c.isdigit() for c in v) and (_mixed_case(v) or any(not c.isalnum() and c not in _SHELL_WORD for c in v)):
        return True
    return (bool(m.group("gap")) and _secret_like(v, _SHELL_WORD)
            and bool(_LOGIN_COMMAND.search(m.string, max(0, m.start() - _CLI_COMMAND_REACH), m.start())))


_VERSION_TAG = re.compile(r"\d+(?:\.\d+)*(?:-[a-z0-9.]+)?", re.IGNORECASE)
# Keywords that introduce a login only in prose: the same words name an
# access level, a permission or a product ("уровень доступа — role:Admin",
# "аккаунт: iOS:17.4", "доступы: grant_type:client_credentials"). "логин",
# "creds" and the CLI flags always introduce credentials and stay out.
_PROSE_LOGIN_WORD = re.compile(r"доступ|акк|уч[её]тк", re.IGNORECASE)


def _version_part(part: str) -> bool:
    """"v2", "17.4", "2.1-beta": a version tag, never half of a credential.
    An all-digit run is no version here: "admin:123456" is a password."""
    return not part.isdigit() and bool(_VERSION_TAG.fullmatch(part.lstrip("vV")))


def _password_part(pw: str) -> bool:
    """The second half of a "user:pass" pair after a prose keyword. A real
    password carries a digit, a capital inside the word or a symbol that is
    no part of an ordinary shell word; a role, a scope and a permission read
    as plain words ("payments:write_all", "role:Admin", "scope:payments.write")."""
    return (any(c.isdigit() for c in pw)
            or any(not c.isalnum() and c not in _SHELL_WORD for c in pw)
            or (any(c.isupper() for c in pw[1:]) and any(c.islower() for c in pw)))


def _user_pass_ok(m: re.Match) -> bool:
    """"user:pass" after a login flag or word. A dotted user with a numeric
    password is a host and port ("доступ: db.acme.com:5432"). After a CLI
    flag a user with a letter is enough ("curl -u admin:secretpass"); a
    numeric user ("docker run -u 1000:1000" is uid:gid) or a prose word
    before the pair ("доступ: read:write") needs a password part that
    looks like one. After a prose keyword neither half may be a version tag
    ("учётка v2:beta1") and the password part must be a strong one, because
    the same shape spells out permissions and roles there."""
    user, _, password = _unquote(value_group(m)).partition(":")
    if "." in user and password.isdigit():
        return False
    named = any(c.isalpha() for c in user)
    if m.group("kw").startswith("-"):
        return named or (any(c.isalpha() for c in password) and _secret_like(password, _SHELL_WORD))
    if _PROSE_LOGIN_WORD.match(m.group("kw")):
        return (named and password.isascii() and not _version_part(user)
                and not _version_part(password) and _password_part(password))
    return named and password.isascii() and _secret_like(password)


def _default_account_ok(m: re.Match) -> bool:
    """"admin:S3cretPass" with no keyword at all: the password part needs a
    letter and a digit or a real symbol. Mixed case alone is prose here
    ("Test:Passed"), and a version tag is a product ("postgres:16-alpine")."""
    pw = m.group(0).split(":", 1)[1]
    return (any(c.isalpha() for c in pw) and not _VERSION_TAG.fullmatch(pw)
            and (any(c.isdigit() for c in pw) or any(not c.isalnum() and c not in "_.-" for c in pw)))


def _basic_auth_ok(m: re.Match) -> bool:
    """HTTP Basic credentials are base64 of "user:password": the value must
    decode to printable text with a colon, so "basic settings" stays. Right
    after an Authorization header any long value with a letter and a digit
    counts."""
    v = value_group(m)
    body = v.rstrip("=")
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), altchars=b"-_" if "-" in v or "_" in v else None)
    except (binascii.Error, ValueError):
        raw = b""
    if b":" in raw and all(0x20 <= b < 0x7F for b in raw):
        return True
    return ("authorization" in m.group("kw").lower() and len(v) >= 16
            and any(c.isdigit() for c in v) and any(c.isalpha() for c in v))


_B32 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def _base32_secret(m: re.Match) -> bool:
    """Single-case base32 with at least one digit (prose is all letters); a
    grouped key has no all-digit group (amounts, tickets, card fragments are
    digit groups)."""
    groups = re.split(r"[ \-]", value_group(m))
    v = "".join(groups)
    return ((v.isupper() or v.islower()) and set(v.upper()) <= _B32
            and any(c in "234567" for c in v) and not any(g.isdigit() for g in groups))


def _kz_id(m: re.Match) -> bool:
    return kz_id_ok(m.group(0)) and not_operation_ref(m)


def _kz_render(m: re.Match) -> str:
    return P["iin"] if _kz_person(m.group(0)) else P["company"]


def _ua_id(m: re.Match) -> bool:
    return ua_rnokpp_ok(m.group(0)) and not_operation_ref(m)


def _digit_count(low: int, high: int):
    def accept(m: re.Match) -> bool:
        return low <= len(re.sub(r"\D", "", value_group(m))) <= high
    return accept


_EXCHANGE_ACCOUNT = r"(?:pay[^\w\n<]{0,2})?(?:uid|id|user[^\w\n<]{0,2}id|айди|юид|аккаунт\w*|акк\w*|account)"
_EXCHANGE_ACCOUNT_RE = re.compile(_EXCHANGE_ACCOUNT, re.IGNORECASE)


def _exchange_uid_ok(m: re.Match) -> bool:
    """Bare "binance 1234567" (no id/uid/акк word) must be 7+ digits, so
    amounts and years next to an exchange name ("bybit 1000 usdt") survive."""
    return bool(_EXCHANGE_ACCOUNT_RE.search(m.group("kw"))) or len(value_group(m)) >= 7


# --- rule fragments -------------------------------------------------------------------------------

_B58 = r"[1-9A-HJ-NP-Za-km-z]"
# A user-friendly TON address is 48 base64url characters; the first two
# encode its flags and workchain.
_TON_PREFIX = r"(?-i:EQ|UQ|Ef|Uf|kQ|0Q|kf|0f)"
# After a coin or wallet keyword, an address of a chain without a dedicated
# rule (Solana, Stellar, Cosmos, Cardano, Monero, ...) is letters and digits;
# Nano-style addresses start with "nano_". Only TON's base64url has "-" and
# "_" inside, and a TON address glued to a word or cut short (which the
# dedicated rule misses) is still taken whole. Anywhere else a dash or an
# underscore ends the value, so an order reference or a constant after the
# keyword ("usdt: INV-20260312-000123-ABCD", "USDT_TRC20_WITHDRAWAL_DISABLED")
# stays product knowledge, while an address glued to a suffix is still
# removed ("sol <wallet>-mainnet").
_FALLBACK_WALLET = (rf"{_TON_PREFIX}[A-Za-z0-9_\-]{{23,93}}|(?:nano|xrb|ban)_[A-Za-z0-9]{{20,90}}"
                    r"|[A-Za-z0-9]{25,95}")
# A short keyword is a whole word: "pin" is not "ping", "др" (birthday) is
# not "другая", "индекс" is not "индексация". A Latin keyword is ended only
# by a Latin letter and a Cyrillic one only by a Cyrillic letter, so a glued
# value or a glued word of the other script still follows it ("PIN1234",
# "pin_code", "pinкод"); Russian case forms are spelled out per keyword.
_LATIN_END = r"(?![A-Za-z])"
_CYRILLIC_END = r"(?![А-Яа-яЁё])"
# A card expiry: "MM/YY", "MM.YY", "MM-YY", "MM YY", "MMYY" or "MM/20YY".
# Not part of something longer: a third part after the same separator is a
# full date ("срок до 12.03.2026"), a two-digit year below 13 is a day and
# month ("срок оплаты 10.02"; card expiries in Telegram history start in
# 2013), and a time unit after a dotted, dashed or spaced pair is a duration
# ("срок 10-14 дней", "12 24 часа"). A slash is the expiry separator, so
# "срок 12/27 года" stays an expiry.
_TIME_UNIT = (r"(?:дн(?:я|ей|и)?|день|час(?:а|ов)?|ч|мин(?:ут[аы]?)?|сек(?:унд[аы]?)?|мес(?:яц(?:а|ев)?)?"
              r"|недел(?:ь|я|ю|и|ей)|нед|сут(?:ки|ок)|раб(?:очих|очий|очие)?|год(?:а|у)?|лет|г"
              r"|days?|hours?|min(?:ute)?s?|months?|weeks?|years?)(?![^\W\d_])")


def _expiry_value(separator: str) -> str:
    """A card expiry: a month, ``separator``, a two- or four-digit year. A
    further digit, the same separator once more (a date: "12.03.2026") or,
    after a separator that is not a slash, a time unit ("срок 10-14 дней")
    ends the match."""
    return (rf"(?:0[1-9]|1[0-2])\s?{separator}\s?(?:20)?(?:1[3-9]|[2-9]\d)"
            rf"(?![\d/]|(?P=sep)\s?\d|(?(slash)(?!)|\s?{_TIME_UNIT}))")


_EXPIRY_VALUE = _expiry_value(r"(?:(?P<slash>/)|(?P<sep>[.\-]))?")
# The same value where the only label is a bare "до" (see ``CARD_EXPIRY_RULE``):
# the separator is then mandatory and never a dot, because "до 10.50" is an
# amount, "до 1250" a limit and "до 10 30" a time.
_CARD_EXPIRY_VALUE = _expiry_value(r"(?:(?P<slash>/)|(?P<sep>-))")
_NAME = r"(?-i:(?:[A-ZА-ЯЁ][a-zа-яё'\-]+|[A-ZА-ЯЁ]{2,}))"
_INIT = r"(?-i:[A-ZА-ЯЁ]\.(?:\s?[A-ZА-ЯЁ]\.)?)"   # "И.", "И.И.", "И. И."
_IP = r"(?:\d{1,3}\.){3}\d{1,3}"

# People next to a keyword. One capitalised word (never a legal form or an
# acronym), initials with a mandatory dot, words never joined across a line
# so a job title under a signature stays.
_LEGAL = r"(?!(?:ООО|ОАО|АО|ПАО|ЗАО|ТОО|ИП|ФОП|LLC|LTD|INC|GMBH|API|URL|SMS|OTP|PIN|CVV|BIN|IBAN)(?![a-zа-яё]))"
_W = rf"(?-i:{_LEGAL}(?:[A-ZА-ЯЁ][a-zа-яё'\-]+|[A-ZА-ЯЁ]{{2,}}))"
_INI = r"(?-i:[A-ZА-ЯЁ]\.(?:[^\S\n]?[A-ZА-ЯЁ]\.)?)"
_SP = r"[^\S\n]+"
_FULL = rf"{_W}(?:{_SP}{_W}){{1,2}}(?:{_SP}{_INI})?|{_W}{_SP}{_INI}|{_INI}{_SP}{_W}"
_SURNAME_SUFFIX = (r"(?-i:(?:ов|ев|ёв|ин|ын|ский|цкий|ская|цкая|ова|ева|ёва|ина|ына|ко|ук|юк|ич|дзе|швили|ян|улы|кызы"
                   r"|ov|ev|in|sky|ski|ova|eva|ina|ko|uk|ich))")
# Card networks, tiers, wallets and banks, and the words of a decline
# message ("Cardholder Name Mismatch"): after a holder word they name a
# product, not a person ("для держателей Visa Gold", "держатель карты Kaspi
# Gold"). The cardholder gap steps over them and over "карты", so a person
# named after the product is still found ("держатель карты Visa Gold Иван
# Сидоров"). Closed list on purpose: an unlisted product name belongs in
# ``keep_terms``. Latin "Mir" is a given name, so only the capitals "MIR"
# count; the tail keeps "Мира" and "Goldman" out.
_CARD_PRODUCT = (r"(?:visa|master ?card|maestro|мир|(?-i:MIR)|union ?pay|amex|american express|discover|jcb|diners"
                 r"|apple pay|google pay|samsung pay|pay|gold|platinum|infinite|signature|world|elite|classic|standard"
                 r"|electron|premium|business|debit|credit|virtual|plan|black|блэк|travel"
                 r"|(?:премиальн|классическ|золот|платинов|дебетов|кредитн|виртуальн|зарплатн)(?:ая|ой|ую)"
                 r"|kaspi|каспи|halyk|халык|jusan|tinkoff|тинькофф|сбер\w*|sber\w*|альфа|alfa|втб|vtb|freedom|revolut"
                 r"|банк\w*|bank\w*|name|mismatch|verification|format|invalid)(?![a-zа-яё])")
_CARD_WORD = r"карт\w*|cards?(?![\w])"
_CARD_WORD_RE = re.compile(rf"(?<![\w])(?:{_CARD_WORD})", re.IGNORECASE)
_CARD_PRODUCT_RE = re.compile(rf"(?<![\w])(?:{_CARD_WORD}|{_CARD_PRODUCT})", re.IGNORECASE)
_SURNAME_WORD = re.compile(rf"[^\W\d_]{{2}}{_SURNAME_SUFFIX}(?![^\W\d_])")   # on lower-cased text
# Names typed in lower case, as chats are written ("меня зовут иван смирнов",
# "фио: смирнов алексей викторович"). Capitalisation is the signal everywhere
# else, so these need a word shaped like a patronymic or - after a
# self-introduction, where the next words are the name for sure - like a
# surname. Only high-precision endings count: "-ов" also ends a plural
# genitive ("фио клиентов не отображается"), and "-овне"/"-овной" ordinary
# adjectives ("на уровне", "основной"). Two or three words, the first one
# only if a marked word follows, plus a surname after a patronymic
# ("алексей викторович смирнов").
_LOW_WORD = r"(?-i:[а-яё]{2,}(?:-[а-яё]{2,})?)"
_LOW_PATR = (r"(?-i:(?:[а-яё]{2,}(?:ович|евич)|(?:иль|кузьм|лук|фом|никит|савв)ич)(?:а|у|ем|е)?"
             r"|[а-яё]{2,}(?:овна|евна))")
_LOW_SURNAME = r"(?-i:[а-яё]{2,}(?:ов|ев|ёв|ова|ева|ёва|ский|ская|цкий|цкая|енко))"
_LOW_NAME = rf"(?:{_LOW_WORD}{_SP}){{0,2}}(?:{_LOW_PATR})(?:{_SP}{_LOW_SURNAME})?(?![^\W\d_])"
# After a self-introduction a surname may stand for the patronymic, but then
# it must come first or second, so that a sentence that merely goes on
# ("меня зовут для рассылки заказов") is no name.
_LOW_INTRO_NAME = (rf"(?:(?:{_LOW_WORD}{_SP}){{0,2}}(?:{_LOW_PATR})|(?:{_LOW_WORD}{_SP})?(?:{_LOW_SURNAME}))"
                   rf"(?:{_SP}{_LOW_SURNAME})?(?![^\W\d_])")
_INIT_RE = re.compile(_INIT)


# A plural holder word addresses a group of clients, so after "карт" the
# value names a card product ("держатели карт Райффайзен Премиум"), unless
# it carries a surname ending or an initial.
_PLURAL_HOLDER = re.compile(r"(?:держател|владельц)(?:и|ей|ям|ями|ях|ы|ев|ам|ами|ах)", re.IGNORECASE)


def _cardholder_ok(m: re.Match) -> bool:
    """A value made only of card and product words is a product ("Visa
    Gold", "Золотой Карты"). After "карты" in the gap a value that mixes a
    product word with other words ("держатели карт Acme Credit"), or that
    follows a plural holder word, names a person only with a surname ending
    or an initial ("держатель карты Мир Асланов", "Иван Банков")."""
    v, gap = value_group(m), m.group("gap")
    person = _CARD_PRODUCT_RE.sub(" ", v)
    if not any(c.isalpha() for c in person):
        return False
    if _CARD_WORD_RE.search(gap) and (person != v or _PLURAL_HOLDER.match(m.group("kw"))):
        return bool(_SURNAME_WORD.search(v.lower()) or _INIT_RE.search(v))
    return True


# A document series in front of its number ("MP1234567", "АБ 123456", "мк
# 123456"). It never starts inside a word, so a keyword cannot lend it its
# own tail ("правами 123456"), though a file name may glue it with '_'
# ("паспорт_AB1234567"). Written apart from the number it is never a short
# lower-case prose word ("права на 1234567", "заявка id 1234567",
# "паспорт по 1234567"); "no" is none: "passport no 1234567" is a number.
_PROSE_SERIES = (r"(?-i:(?:по|на|от|до|за|из|с|со|в|во|к|ко|у|о|об|и|а|но|да|не|ни|то|же|ли|бы|для|про|при|без|под"
                 r"|над|все|всё|вот|это|как|так|уже|еще|ещё|или|чем|где|кто|что|раз|шт|руб|тг|мин|час|id|tx|ок|ok"
                 r"|to|of|in|on|at|is|by|or|and|for|the|via|per))")
# The label between a document series and its number ("серия 4509 номер
# 123456", "Серия: 4509\nНомер паспорта: 123456"): the document word after
# "номер" and a colon are optional, so the label reads the same whether it
# repeats the document or not.
_DOC_NO = r"(?:№|#|no\.?|номер(?:[ \t]+(?:паспорта|документа|удостоверения))?)[ \t]*:?[ \t]?"


def _series(lo: int, hi: int, sep: str = r"[ \t]") -> str:
    """Regex fragment for ``lo``-``hi`` series letters, glued to the number
    or followed by ``sep``."""
    return rf"(?<![^\W_])(?:(?!{_PROSE_SERIES}{sep})[A-ZА-Я]{{{lo},{hi}}}{sep}|[A-ZА-Я]{{{lo},{hi}}})"


# Well-known secret prefixes (AWS, Stripe, webhooks, Google, Twilio, Shopify,
# GitLab, Hugging Face, Slack, SendGrid, Discord). Case-sensitive on purpose.
# The dotted SendGrid and Discord keys are spelled out: a '.' in the generic
# base64 rule would swallow long dotted file names and hosts.
_KNOWN_SECRET = (
    r"(?<![\w])(?:AKIA[0-9A-Z]{16}|[srp]k_(?:live|test)_[A-Za-z0-9]{24,}|whsec_[A-Za-z0-9]{32,}"
    r"|AIza[0-9A-Za-z_-]{35}|SK[0-9a-f]{32}|shp(?:at|ss|ca)_[0-9a-f]{32}|glpat-[A-Za-z0-9_-]{20}|hf_[A-Za-z0-9]{30,}"
    r"|xox[abp]-[A-Za-z0-9-]{10,}|SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,}"
    r"|[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,})(?![\w])"
)
# A browser user-agent is a chain of product tokens ("Chrome/120.0.0.0",
# "Telegram-Android/10.5.2"), comments in parentheses, in-app extensions in
# brackets ("[FB_IAB/FB4A;FBAV/440.0.0.0.0;]"), up to three bare words before
# a product ("Mobile Safari/537.36", "Pinterest for iOS/12.4.1"), IE's "like
# Gecko", and in-app suffixes that write the version after a space
# ("Instagram 310.0.0.34.111 Android (33/13; 420dpi; ...)"). Matching that
# grammar instead of the rest of the line keeps what follows the user-agent
# in a pasted log line (error codes, statuses, timings, a Russian sentence)
# as live text for the later layers. A product name starts with a letter (a
# date is not a product), a version cannot end in a sentence period, and a
# comment after the first one is Latin only ("(ошибка 4001)" is a remark,
# not part of the user-agent).
_UA_WORD = r"[A-Za-z][A-Za-z0-9_\-]*"
_UA_PRODUCT = r"[A-Za-z][A-Za-z0-9_.\-]*/[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*"
_UA_COMMENT = r"\([^)\nА-Яа-яЁё]*\)|\[[^\]\nА-Яа-яЁё]*\]"
_UA_APP = rf"{_UA_WORD}[ \t]+\d+(?:\.\d+)+(?:[ \t]+{_UA_WORD})?(?=[ \t]+\()"
_UA_TOKEN = rf"{_UA_PRODUCT}|like Gecko|{_UA_APP}|{_UA_WORD}(?=(?:[ \t]+{_UA_WORD}){{0,2}}[ \t]+{_UA_PRODUCT})"
_USER_AGENT = re.compile(rf"Mozilla/5\.0 \([^)\n]*\)(?:[ \t]*(?:{_UA_COMMENT})|[ \t]+(?:{_UA_TOKEN}))*")

# PEM private keys: the key material between the armour lines becomes one
# placeholder and the BEGIN/END lines stay ("the client pasted an RSA key").
# Separators are real line breaks or the literal "\n" of a JSON string or an
# .env value and are copied from the input. They are possessive and the body
# may not end inside one, so a marker followed by thousands of blank lines
# and no END line is scanned once instead of backtracking the run against
# the lazy body. Certificates and public keys are public material and stay.
_PEM_MARK = r"[A-Z0-9 ]{0,24}PRIVATE KEY(?: BLOCK)?-----"
_PEM_SEP = r"(?:\s|\\[rn])*+"
_PEM_BLOCK = re.compile(
    rf"(?P<head>-----BEGIN {_PEM_MARK})(?P<sep1>{_PEM_SEP})(?P<body>[\s\S]{{1,20000}}?(?<!\s)(?<!\\[rn]))"
    rf"(?P<sep2>{_PEM_SEP})(?P<foot>-----END {_PEM_MARK})")
_PEM_NOISE = re.compile(r"<[a-z0-9-]+>|\s|\\[rn]")


def _pem_body_ok(m: re.Match) -> bool:
    """An empty template, or a body that already is our placeholder, stays."""
    return bool(_PEM_NOISE.sub("", m.group("body")))


def _pem_render(m: re.Match) -> str:
    return m.group("head") + m.group("sep1") + P["private_key"] + m.group("sep2") + m.group("foot")


# Quote pairs a value may be wrapped in: (opening quote, closing quotes).
_QUOTE_PAIRS = (('"', '"'), ("'", "'"), ("«", "»"), ("“", "”“"), ("„", "“”"), ("`", "`"))


def _quoted_value(min_len: int, max_len: int, quotes: tuple[tuple[str, str], ...] = _QUOTE_PAIRS,
                  gate: Callable[[str], str] = lambda body: "") -> str:
    """Regex fragment for the whole text between a pair of quotes, spaces
    included, when the opening quote is the last character of the gap
    ('"Qwerty 123"', «Мой пароль 2024»). The quotes stay outside the value,
    so the rendering keeps them. The text starts and ends with a visible
    character, never with a separator (':', '=', ',', ';'), and is closed by
    its own quote on the same line.

    ``gate(body)`` returns a zero-width fragment checked at the start of the
    text, before it is consumed. It differs per quote pair, so it is given
    ``body``: the character class of one character of the text, which stops
    at that pair's own closing quote."""
    parts = []
    for opening, closing in quotes:
        body = f"[^{re.escape(closing)}\\n]"
        parts.append(rf"(?<={re.escape(opening)}){gate(body)}"
                     rf"(?=[^\s{re.escape(closing)}:=,;]){body}{{{min_len},{max_len}}}(?<!\s)(?=[{re.escape(closing)}])")
    return "|".join(parts)


# ".env" lines: an identifier that ends in a secret word, then '=' or ':'.
# A '#' glued to the value is part of it ("PASSWORD=Summer#2024"): dotenv
# starts a comment only after whitespace.
# The identifier is taken greedily and bounded, and the secret word is
# checked with fixed-width lookbehinds, so long "a-b-c" runs stay linear.
# The same name as a JSON, YAML, Python or PHP key ('"db_password": "x"',
# "'api_secret' => 'x'") keeps its closing quote in the gap; a quoted value
# is taken whole, spaces included.
_ENV_SUFFIXES = ("PASSWORD", "PASSWD", "PASS", "PWD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "PRIVATE_KEY", "SECRET_KEY",
                 "ACCESS_KEY", "CLIENT_SECRET", "AUTH_KEY", "SIGNING_KEY", "ENCRYPTION_KEY", "MASTER_KEY", "DSN")
_ENV_NAME = (r"[A-Za-z][A-Za-z0-9_.-]{0,63}(?:" + "|".join(f"(?<={s})" for s in _ENV_SUFFIXES) + ")")
_STRAIGHT_QUOTES = (('"', '"'), ("'", "'"))
_ENV_SECRET = re.compile(
    rf"(?<![\w])(?:export[ \t]+)?(?P<kw>{_ENV_NAME})(?P<gap>[\"']?[ \t]*(?:=>|[=:])[ \t]*[\"']?)"
    rf"(?P<val>{_quoted_value(6, 64, _STRAIGHT_QUOTES)}|[^\s\"';,]{{6,}})",
    re.IGNORECASE)
_PREP = r"(?:от|для|к|на|from|for|to|of|the)"
# "пароль от личного кабинета: X": a 1-3 word label on the keyword's line
# that ends in ':' or '=' (the value may start the next line), or a
# preposition and one word; multi-word labels without a colon stay out (that
# heuristic over-scrubs versions and error codes). A ':' right after the
# keyword ends the label. The label also ends before a word that belongs to
# the next field, so in "пароль Qwerty123 логин: ivan" the password is the
# value: a login, e-mail or phone field ("логин:", "почта:") follows only the
# first label word or a leading conjunction ("пароль и почта:"), and no
# field name at all follows a word that reads as a value (four or more
# characters with a digit or a symbol; brand names such as "AnyDesk" are
# label words). A password keyword is never a label word: it starts the next
# field ("пароль Qwerty123 новый пароль: Qwerty456" has two values).
# Colloquial spellings ("pw", "пасворд", "пороль") and the instrumental
# "паролем" count; the genitive "пароля" does not ("сброс пароля: ошибка"
# = "password reset: error" is prose).
# A bank's "кодовое слово" (code word) identifies the caller by phone and is
# as secret as a password; so are its "контрольное" and "секретное" variants.
_PASSWORD_WORDS = (r"(?:кодов|контрольн|секретн)\w*[ \t]+слов\w*"
                   r"|пароль|пароли|паролем|пороль|password|passwd|passphrase|пасс-?фраза|пас{1,2}ворд|pass(?![\w])"
                   r"|pwd|pw(?![\w])|пасс(?![\w])")
_LABEL_WORD = rf"(?!(?:{_PASSWORD_WORDS})(?![^\W\d_]))[^\s:=,;<]{{1,24}}"
_VALUE_WORD = r"(?=[^\s:=,;<]{4})(?=[^\s:=,;<]{0,23}[\d!#$%^&*+?~@])"
_LOGIN_FIELD = (r"(?:логин|login|username|юзернейм|почта|e-?mail|емейл|имейл|мейл|мыло|телефон|phone|ник|nick(?:name)?)"
                r"[ \t]*[:=]")
_OTHER_FIELD = (r"(?:user|юзер|пользователь|host|хост|server|сервер|site|сайт|url|port|порт|domain|домен|id|uid"
                r"|key|ключ|code|код|pin|пин|token|токен|2fa|2фа)[ \t]*[:=]")
_CONJUNCTION = r"(?:и|или|and|or|&|/)"
_LABEL_NEXT_WORD = (rf"(?!{_VALUE_WORD}{_LABEL_WORD}[ \t]+(?:{_LOGIN_FIELD}|{_OTHER_FIELD}))"
                    rf"{_LABEL_WORD}[ \t]+(?!{_LOGIN_FIELD})")
# Up to three label words, or four and five ("пароль для входа в личный
# кабинет:", "пароль от личного кабинета на сайте:") when the value after the
# colon reads as one: four words of prose reach far enough to end on a colon
# of their own ("пароль от кабинета не работает в логах: AUTH_FAILED_4012"),
# so there the value may be neither an ALL_CAPS constant nor a message word.
_LONG_LABEL_VALUE = (rf"(?=[^\w\n<]{{0,4}}(?!(?-i:[A-Z0-9_]{{4,}})(?![^\W_]))"
                     rf"(?!{_MESSAGE_WORD.pattern}){_VALUE_WORD})")
_PASSWORD_LABEL = (rf"[^\w\n<:=]{{0,3}}(?:{_PREP}[ \t]+){{0,2}}(?:{_CONJUNCTION}[ \t]+)?"
                   rf"(?:(?:{_LABEL_NEXT_WORD}){{0,2}}{_LABEL_WORD}[ \t]*[:=]"
                   rf"|(?:{_LABEL_NEXT_WORD}){{3,4}}{_LABEL_WORD}[ \t]*[:=]{_LONG_LABEL_VALUE})")
# A state word before the value ("пароль: новый Qwerty123" = new, "password:
# temporary Hunter22") belongs to the gap when the next word reads as a value
# and has a letter; otherwise the state word is the value and is rejected as
# prose ("пароль: новый пароль", "пароль: неверный").
_PASSWORD_STATE = (r"(?:(?:не)?(?:верн|правильн)|нов|стар|прежн|текущ|временн|одноразов)(?:ый|ий|ой|ая|яя|ое|ее)"
                   r"|new|old|current|temporary|wrong|correct")
# Filler between the keyword and a password written without a colon
# ("пароль был Qwerty123", "пароль у него hunter22", "my password is
# hunter2"). The words are closed lists of forms, so the prose they also
# start stays prose: the value still has to look like a password ("пароль
# был изменён", "password is required").
_PASSWORD_FILLER = (r"(?:(?:был[аио]?|будет|теперь|сейчас|тот же|такой|вот|у (?:него|неё|нее|меня|клиента)"
                    r"|(?:сменил|поменял|изменил)[аи]? на|is|was|now)[ \t]+)?")
_PASSWORD_GAP = (rf"(?:{_PASSWORD_LABEL}[^\w\n<]{{0,4}}(?:\n[^\w\n<]{{0,4}})?"
                 rf"|(?:[^\w\n<:=]{{0,3}}{_PREP}[ \t]+[^\s:=]{{1,24}})?[^\w\n<]{{0,5}}{_PASSWORD_FILLER})"   # ' => "' is five
                 rf"(?:(?:{_PASSWORD_STATE})[ \t]+{_VALUE_WORD}(?=[^\s:=,;<]{{0,63}}[^\W\d_]))?")
# A password is one bare token. The quotes and brackets around it belong to
# the text ('{"password": "hunter2"}' keeps its JSON shape), and so does the
# sentence punctuation after it. A quoted passphrase is taken whole when the
# quote opens right after ':' or '=' ('password: "correct horse battery"',
# '"password": "..."') or the text has a digit, a symbol or an inner capital
# («Мой пароль 2024»), unless the quoted text reads as a validation or error
# message ('password: "hunter2 is wrong"'); then only the first token is the
# value, as for unquoted text.
_STRONG_CHAR = r"(?:\d|_|[^\w\s.,!?;:()\"'«»“”„`\-]|(?-i:[a-zа-яё][A-ZА-ЯЁ]))"
_OPENS_AFTER_ASSIGNMENT = r"(?<=[:=>].)|(?<=[:=>][ \t].)"   # the quote follows ":", "=" or "=>"
_PASSWORD_VALUE = (_quoted_value(4, 64,
                                 gate=lambda body: rf"(?!{body}{{0,63}}?{_MESSAGE_WORD.pattern})"
                                                   rf"(?:{_OPENS_AFTER_ASSIGNMENT}|(?={body}{{0,63}}?{_STRONG_CHAR}))")
                   # A closing tag ends the value: in an XML payload the text
                   # of the element is the password ("<Description>Password
                   # is invalid</Description>" keeps its markup).
                   + r"|(?![\"'«“„`])(?:(?!</)[^\s,;]){4,64}(?<![.!?:)\]}\"'»”’`])")
# "-p" on a command line: a bare value (bounded, so an over-long one is left
# to the generic secret rules whole) or a quoted one with spaces inside.
_CLI_VALUE = r"\"[^\"\n]{4,64}\"|'[^'\n]{4,64}'|[^\s<\"']{4,64}(?![^\s<\"'])"
# "user:pass" with one colon, bare or quoted (spaces allowed in the password).
# Never '@' (an e-mail follows, left to the e-mail rule whole) nor '<' (the
# scanner must not read our own placeholders as a password).
_USER_PASS = r"[^\s:@/<\"']{2,64}:[^\s:@/<\"']{4,64}"
# Sentence punctuation after the pair belongs to the text, as it does after
# a password ("акк: ivan:Qwerty123, пароль сменю", "доступ: role:viewer;").
_USER_PASS_VALUE = (rf"\"{_USER_PASS}[^\"\n]*\"|'{_USER_PASS}[^'\n]*'"
                    rf"|{_USER_PASS}(?<![,;.!?)\]}}])(?![\w:@])")
# Default and service accounts: "root:toor1234" is a credential even without
# a keyword or a second colon. "login" and "user" are labels, not accounts.
_DEFAULT_ACCOUNTS = r"admin|administrator|root|deploy|guest|demo|test|superuser|sa|postgres|mysql|ftp|sftp|ssh"
_BACKUP_CODE = r"(?:[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|\d{4}[ \u00a0]\d{4}|\d{6,8})(?!\d)"
_SEED_WORD = trie_regex(BIP39_WORDS)
# Spaces, commas, newlines, optional "1." numbering. A digit or a letter
# always follows a separator, never another blank, so the runs are taken
# possessively and the rule stays linear on a word of the list in front of a
# long run of empty lines ("access" and 4000 of them).
_SEED_SEP = r"(?:[ \t,;]++|[^\S\n]*+\n\s*+)(?:\d{1,2}[.)]\s*+)?"
_EXCHANGE = (r"binance|bybit|okx|okex|kucoin|bitget|mexc|htx|huobi|gate\.io|bingx|coinex|whitebit|kraken|bitfinex"
             r"|бинанс\w*|байбит\w*|окх|кукоин\w*|битгет\w*|мекс\w*|хуоби")
_MONTH = r"(?:янв|фев|мар|апр|ма[йя]|июн|июл|авг|сен|окт|ноя|дек|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-zа-я]*"
_DOB_VALUE = (rf"\d{{1,2}}[./-]\d{{1,2}}[./-](?:19|20)\d{{2}}(?![\d])|(?:19|20)\d{{2}}-\d{{2}}-\d{{2}}(?![\d])"
              rf"|\d{{1,2}}\s+{_MONTH}\s+(?:19|20)\d{{2}}(?![\d])")
# Street-shaped addresses: an optional city, a street keyword, a number, and
# an optional building/flat. "пр." and "пер." are also chat shorthand for
# "прочее" (other) and "перевод" (transfer). "пр." counts only before a
# capitalised name ("и пр. лимит 100" is safe). "пер." counts unless a
# transfer follows: an amount, a lower-case preposition or particle, or a
# word about money or its recipient ("пер. 1500 руб", "пер. на карту 1500",
# "пер. средств", "пер. клиенту 500"). Any other name is a lane, typed in
# lower case too ("пер. кривоколенный 5"), and so are an ordinal ("пер. 1-й
# Колобовский 5") and a short number before a capitalised word ("пер. 8
# Марта 5").
_TRANSFER_AFTER_PER = (r"\s*(?:\d(?!\d?-?(?:[йяе]|ый|ий|ой|ая|ое)(?![а-яё])|\d?[ \t]+(?-i:[А-ЯЁ]))"
                       r"|(?-i:на|от|с|со|по|за|в|во|до|из|к|ко|без|для|через|между|не)\s"
                       r"|(?-i:средств[а-яё]*|денег|деньги|клиент[а-яё]*|отклон[а-яё]*)(?![а-яё]))")
_STREET = (r"(?:ул\.|улица|вул\.|вулиця|просп\.|проспект|пр-т|пр\.(?=\s*(?-i:[А-ЯЁ]))"
           rf"|пер\.(?!{_TRANSFER_AFTER_PER})|переулок|бульвар|б-р|шоссе|наб\.|набережная|мкр\.|микрорайон|көш\.|көшесі)")
_STREET_EN = r"(?:st|street|ave|avenue|rd|road|blvd|dr|drive|ln|lane|way|ct|court|pl|place)"
# An English street name has no lower-case function word: a run with one
# before "way", "dr", "st", "ct" or "pl" is a sentence ("2 cards by the
# way", "5 minutes to get there dr"). Only the lower-case spelling is a
# function word, so "5 The Drive" is still an address.
_EN_STOPWORD = (r"(?-i:(?:the|a|an|to|on|in|by|of|at|for|from|with|this|that|these|those|there|here|out|up|no|my"
                r"|your|our|their|its|his|her|and|or|per|via|is|are|was|were|be|get|got|hit|all|any|each|every"
                r"|same|either|other|another|some|more|less|than|into|onto|over|under|about|after|before)"
                r"(?![A-Za-z0-9.'\-]))")
_EN_STREET_WORD = rf"(?!{_EN_STOPWORD})[A-Za-z0-9.'\-]+"
_CITY = r"(?:(?:г\.|город|с\.|пос\.|п\.)\s*[^\n,;]{2,30}?,\s*)?"
# Between the street keyword and the house number stands the street name: up
# to 40 characters on one line, with an optional comma. The blanks around it
# are taken possessively, which keeps the rule linear on a street keyword in
# front of a long run of spaces or newlines. The name may also start inside
# that run and is then shorter than two characters of its own: the two
# lookbehind branches read one character after a blank ("мкр. 5, д. 12",
# where "5" alone is too short) and a name of blanks only ("ул.  , 5"), and
# the lookahead branch reads a name of blanks whose run ends in a newline
# ("мкр.  \n5"), asking for the two adjacent blanks such a name needs.
_STREET_NAME = (r"(?:\s*+(?:[^\n,;]{2,40}?|(?<=[^\S\n])[^\n,;]|(?<=[^\S\n]{2})),?"
                r"|(?=\s*?[^\S\n]{2}))\s*+")
# A building or flat number never starts with a blank, and neither does its
# keyword, so these runs are possessive as well.
_BLD = r"(?:\s*+[,/]?\s*+(?:к\.|корп\.?|корпус|стр\.?|строение|под\.?|подъезд)\s*+\d+)?"
_FLAT = r"(?:\s*+[,/]?\s*+(?:кв\.?|квартира|оф\.?|офис|apt\.?|office)\s*+\d+)?"
# A house number starts a digit run and never sits inside one of our
# virtual ids ("ул. 1 @U04217" in the scanner's view).
_HOUSE_NUMBER_START = r"(?<!\d)(?<!@[UC])"

# The value of an address keyword runs to the end of the line, so a gate
# tells an address from a sentence about addresses ("прописка не нужна",
# "billing address must match the card ending 4242"). Text that later
# layers replace, or that already is a replacement, counts as one neutral
# word ("_"): e-mail addresses, handles (also our "@U04217"), links, masked
# cards, placeholders and the scrubber's sentinels. The scrubber sees the
# raw text and the scanner the replacements, and both must reach the same
# verdict.
_ADDRESS_NOISE = re.compile(
    rf"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|{HANDLE_START}{USERNAME}|[a-z][a-z0-9+.-]*://\S+"
    rf"|{MASKED_CARD}|<[^<>\s]{{1,80}}>|[{NO_PUA}]+", re.IGNORECASE)
# Words that name a place even without a house number ("с. Каскелен, ул.
# Абылай хана", "село Каскелен"), and on top of them the words and glued
# shapes of a house, building or flat ("кв5", "12к2", "10а кв 3").
_PLACE_WORD = (rf"{_STREET}|(?:г|с|пос)\.|(?:село|пос[её]лок|аул|мкр)(?![\w])"
               r"|город(?=[ \t]+(?-i:[А-ЯЁ]))")
_PLACE_TOKEN = re.compile(rf"(?<![\w.])(?:{_PLACE_WORD})", re.IGNORECASE)
_ADDRESS_TOKEN = re.compile(
    rf"(?<![\w.])(?:{_PLACE_WORD}|(?:д|кв|корп|стр|под|оф|apt|{_STREET_EN})\."
    rf"|(?:город|дом|кв|квартира|корпус|строение|подъезд|офис|suite|unit|house|zip|индекс|{_STREET_EN})(?![\w]))"
    r"|(?<![\w])(?:кв|д|дом|корп|к|стр|с|лит)\.?\d|\d(?:кв|корп|к|стр|с|лит)\.?\d", re.IGNORECASE)
# A value that opens with one of these words is a sentence unless it shows
# an address signal ("и адрес проживания отличаются, ошибка KYC_07"). Other
# single letters ("а/я 15", "в г. Алматы") are no such words: addresses
# start with them.
_ADDRESS_PROSE = re.compile(
    r"(?:и|не|ни|нет|нужн\w*|надо|можно|нельзя|должн\w*|обязательн\w*|требу\w*|необходим\w*|подтвер\w*|укаж\w*"
    r"|указ\w*|уточн\w*|измен\w*|меня\w*|поменя\w*|смен\w*|совпада\w*|провер\w*|заполн\w*|отлича\w*|для|есть"
    r"|был\w*|будет|это|как\w*|что|если|или|тоже|также"
    r"|is|isn't|are|aren't|was|were|must|should|can|cannot|can't|does|doesn't|do|don't|not|will|won't|has|have"
    r"|fails?|failed|mismatch\w*|required|optional|needs?|for|field)(?![\w'])", re.IGNORECASE)
# A part of the value that ends in a house number ("абая 10", "абая 17 а,",
# "кенесары 40/2") unless the word before the number names another kind of
# number ("code 51", "лимита 500", "попытки 3", "до 15").
_HOUSE_NUMBER_END = re.compile(r"(?<![\w.:])[1-9]\d{0,2}(?:[ \t]?[а-яёa-z])?(?![\w])(?=\s*(?:[,/;]|$))",
                               re.IGNORECASE)
_WORD_BEFORE = re.compile(r"([^\W\d_]+)[^\w\n]*$")
_NOT_HOUSE_WORD = re.compile(
    r"код\w*|code\w*|до|от|за|на|в|во|из|по|с|со|к|у|около|более|менее|больше|меньше|свыше|максимум|минимум"
    r"|попыт\w*|раз|шт|штук\w*|пункт\w*|п|шаг\w*|этап\w*|карт(?:а|ы|у|е|ой|ам|ами|ах)?"
    r"|above|below|over|under|max|min|for|of|to|by|is|are|in|at|step|item|attempts?|cards?|times?", re.IGNORECASE)


def _address_text(m: re.Match) -> str:
    return _ADDRESS_NOISE.sub(" _ ", value_group(m)).strip()


def _ends_in_house_number(v: str) -> bool:
    for m in _HOUSE_NUMBER_END.finditer(v):
        before = _WORD_BEFORE.search(v, 0, m.start())
        word = before.group(1) if before else ""
        if not (_OTHER_NUMBER.search(word) or _ERROR_WORD.search(word) or _NOT_HOUSE_WORD.fullmatch(word)):
            return True
    return False


# A number that only counts something ("2 страница паспорта", "1-3 дня",
# "до 255 символов", "step 2 of 4") is no house number, so a value whose
# every digit belongs to such a count is prose about addresses, not an
# address. "стр." and "п." are deliberately absent: they also abbreviate
# "строение" and "посёлок".
_COUNTING_WORD = (r"страниц\w*|разворот\w*|пункт\w*|раздел\w*|пол[еяю]|шаг\w*|step|page|символ\w*|знак\w*"
                  r"|characters?|chars?|дн(?:я|ей|и)|день|days?|час(?:а|ов|ы)?|hours?|минут\w*|рабоч\w*|of|из")
_COUNT = r"\d{1,3}(?:[-\u2013\u2014.]\d{1,3})?"
_COUNTED_NUMBER = re.compile(rf"(?<![\w])(?:{_COUNTING_WORD})[^\w\n]{{0,3}}{_COUNT}(?![\w])"
                             rf"|(?<![\w]){_COUNT}[^\w\n]{{0,3}}(?:{_COUNTING_WORD})(?![\w])", re.IGNORECASE)


def _counts_only(v: str) -> bool:
    """Every digit of the value belongs to a counted quantity."""
    return not any(c.isdigit() for c in _COUNTED_NUMBER.sub(" ", v))


def _looks_like_address(m: re.Match) -> bool:
    """The text after a strong address keyword ("прописка", "адрес
    доставки") is an address unless it plainly is a sentence. Failing
    towards removal: without a digit it needs a place word; with a digit it
    is an address unless it opens with a prose word ("не", "можно",
    "must") and shows no street, house or flat word and no part that ends
    in a house number."""
    v = _address_text(m)
    if not any(c.isalpha() for c in v):
        return False
    if not any(c.isdigit() for c in v):
        return bool(_PLACE_TOKEN.search(v))
    if _counts_only(v) and not _ADDRESS_TOKEN.search(v):
        return False
    if not _ADDRESS_PROSE.match(v):
        return True
    return bool(_ADDRESS_TOKEN.search(v)) or _ends_in_house_number(v)


def _looks_like_street_address(m: re.Match) -> bool:
    """The value after a bare "адрес:" is an address when it has a digit
    and a letter of its own ("адрес: почему не проходит?" and "email
    адрес: a@b.com" stay for the later layers)."""
    v = _address_text(m)
    return (any(c.isdigit() for c in v) and any(c.isalpha() for c in v)
            and not (_counts_only(v) and not _ADDRESS_TOKEN.search(v)))


# The strong address keywords. Their value never runs into a second address
# that is labelled ("адрес регистрации: ...", "адрес: ...") or introduced by
# "по адресу": a rejected sentence before it would hide it. The value does
# not end in a space or a separator, so the text between two addresses
# stays.
_ADDRESS_KEYWORDS = (r"прописк\w*|адрес(?: (?:проживания|регистрации|доставки|прописки|фактический|billing))"
                     r"|по адресу|мой адрес"
                     r"|домашний адрес|billing address|shipping address|проживаю по адресу|зарегистрирован\w* по адресу")
_NEXT_ADDRESS = (rf"(?<![\w<])(?:(?:{_ADDRESS_KEYWORDS}|адрес)[^\w\n<]{{0,2}}[:=\-—]"
                 r"|(?:проживаю|зарегистрирован\w*) по адресу)")
_ADDRESS_VALUE = rf"(?:(?!{_NEXT_ADDRESS})[^\n]){{6,120}}(?<![\s,;])"

# Integrations paste XML and SOAP requests, where the tag names the kind of
# value ("<Password>Qwerty123</Password>", "<soap:Body><Login>...</Login>").
# The keyword rules cannot read those: their value slot would start at the
# tag's own '>' and run into the closing tag. One rule per kind, applied
# before the keyword rules, so the element is settled before they see it.
ELEMENT_RULES: tuple[Rule, ...] = (
    element_rule("password", r"password|passwd|passphrase|pwd|pass", P["password"], _element_value_ok),
    element_rule("cvv", r"cvv2?|cvc2?", P["cvv"], _element_value_ok),
    element_rule("pin", r"pin|pin[_-]?code", P["pin"], _element_value_ok),
    element_rule("otp", r"otp|otp[_-]?code|sms[_-]?code", P["otp"], _element_value_ok),
    element_rule("api_key", r"token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|api[_-]?key"
                            r"|access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?key", P["secret"],
                 _element_value_ok),
    element_rule("kw_handle", r"login|user[_-]?name", P["user"], _element_value_ok),
)
# Proxy strings go before the generic URL rule ("socks5://user:pass@host" is a
# credential, not just a link) and before the IP rule.
PROXY_RULES: tuple[Rule, ...] = (
    Rule("proxy", re.compile(r"(?<![\w])(?:socks[45]?h?|https?)://[^\s@/]+:[^\s@/]+@[^\s/]+", re.IGNORECASE), P["proxy"]),
    Rule("proxy", re.compile(rf"(?<![\w.]){_IP}:\d{{2,5}}:[^\s:@]+:[^\s:@]+(?![\w])"), P["proxy"]),
    Rule("proxy", re.compile(rf"(?<![\w.@/])[^\s:@/]{{1,64}}:[^\s:@/]{{1,64}}@{_IP}:\d{{2,5}}(?![\w])"), P["proxy"]),
    Rule("proxy", re.compile(r"(?<![\w.@/])[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,6}:\d{2,5}:[^\s:@]{1,64}:[^\s:@]{1,64}(?![\w])",
                             re.IGNORECASE), P["proxy"]),
)

FINTECH_RULES: tuple[Rule, ...] = (
    # --- credentials and secrets (before email/url/ip rules) ---
    # A PEM block first: its lines would otherwise be taken one by one, and
    # "PRIVATE_KEY=-----BEGIN ..." by the .env rule.
    Rule("private_key", _PEM_BLOCK, P["private_key"], _pem_body_ok, _pem_render),
    Rule("credentials", re.compile(
        r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}:[^\s:]{4,}(?::[^\s:]+){0,4}"), P["credentials"]),
    Rule("credentials", re.compile(
        r"(?<![\w@./:])[\w.\-]{4,32}:[^\s:@/]{6,}(?::[^\s:/]+){1,3}(?![\w:])"), P["credentials"], _has_digit_and_letter),
    # One colon only: "curl -u admin:S3cretPass", "логин: ivan_petrov:S3cretPass"
    # (keywords are whole words: "логин:пароль" is a format description), and
    # bare "root:toor1234" for well-known account names.
    keyword_rule("credentials",
                 # "доступно"/"доступен" (available) is no login word.
                 r"(?:-u|--user(?:name)?|--login)(?![\w-])|логин\w*|login\w*|акк\w*|учетк\w*|учётк\w*|доступ(?!н)\w*"
                 r"|creds?(?![\w])|credentials|данные для входа",
                 _USER_PASS_VALUE, P["credentials"], gap=r"[ \t]*=?[^\w\n<\"']{0,4}", accept=_user_pass_ok),
    Rule("credentials", re.compile(
        rf"(?<![\w@./:\-])(?:{_DEFAULT_ACCOUNTS})\d{{0,3}}:[^\s:@/<\"']{{6,}}(?![\w:@])", re.IGNORECASE),
        P["credentials"], _default_account_ok),
    # Session cookies of ad platforms, Google, PHP/ASP/Node apps, TikTok. Case-sensitive so
    # lowercase product keys ("sid=", "wd=") are unaffected.
    Rule("cookie", re.compile(
        r"(?<![\w])(c_user|xs|datr|fr|sb|presence|wd|spin|sessionid|session_id|auth_token|csrftoken|li_at|JSESSIONID"
        r"|SID|HSID|SSID|APISID|SAPISID|LSID|OSID|SIDCC|__Secure-(?:[13]P(?:SID|APISID|SIDTS|SIDCC)|OSID)|__Host-[13]PLSID"
        r"|PHPSESSID|ASP\.NET_SessionId|connect\.sid|remember_token|remember_me"
        r"|ct0|sid_tt|sid_guard|uid_tt|ssid_ucp_v1|sessionid_ss)"
        r"=([^;\s\"']{3,})"), P["cookie"], None, lambda m: f"{m.group(1)}={P['cookie']}"),
    Rule("fb_token", re.compile(r"(?<![\w])EAA[A-Za-z0-9]{20,}(?![\w])"), P["token"]),
    Rule("known_secret", re.compile(_KNOWN_SECRET), P["token"]),
    Rule("env_secret", _ENV_SECRET, P["secret"], _env_value_ok),
    keyword_rule("password", _PASSWORD_WORDS, _PASSWORD_VALUE, P["password"], gap=_PASSWORD_GAP,
                 accept=_looks_like_password),
    # "mysql -pS3cretPass", "sshpass -p S3cretPass"; case-sensitive ("-P 3306"
    # is a port) and never inside "--password" / "--port". A '>' in front ends
    # a placeholder the scrubber wrote, and the word glued to it is part of a
    # package name, not a flag ("<org>-pay==4.1.0" from "romashka-pay==4.1.0").
    keyword_rule("password", r"(?<![->])-p", _CLI_VALUE, P["password"], gap=r"[ \t]*",
                 accept=_cli_password_ok, flags=0),
    keyword_rule("2fa_secret",
                 r"2fa|2фа|two[- ]factor|totp|аутентификатор\w*|authenticator|секрет\w*|secret|seed|ключ",
                 r"(?-i:(?:[A-Z2-7]{4}[ \-]?){4,16}|(?:[a-z2-7]{4}[ \-]?){4,16})(?<![ \-])(?![A-Za-z0-9])", P["2fa"],
                 gap=r"[^\w\n<]{0,20}(?:[^\s<]{1,20}\s+){0,3}?(?:(?:код|ключ|key|secret)[^\w\n<]{0,6})?",
                 accept=_base32_secret),
    keyword_rule("basic_auth",
                 r"(?:proxy-)?authorization[^\w\n<]{0,3}basic|basic(?:[ \-]auth(?:orization|entication)?)?",
                 r"[A-Za-z0-9+/_-]{8,}={0,2}(?![\w+/=])", P["token"], gap=r"[^\w\n<]{0,4}", accept=_basic_auth_ok),
    # A bare "ключ" (key) is not a keyword here: in integration support it
    # names a JSON field ("ключ payment_status_code_01").
    keyword_rule("api_key",
                 r"api[_ -]?key|apikey|api[_ -]?secret|secret[_ -]?key|access[_ -]?token|auth[_ -]?token|refresh[_ -]?token"
                 r"|bearer|token|токен(?:[_ -]доступа)?|ключ api|api ключ|client[_ -]?secret|(?:api|апи)[_ -]?ключ|ключ[_ -]?api"
                 r"|секретн\w*[_ -]ключ|ключ доступа|access key(?: id)?|секретн\w* токен",
                 r"[A-Za-z0-9_\-./+=]{16,}", P["secret"], gap=r"[^\w\n<]{0,6}", accept=_api_key_ok),
    # An activation key written in groups ("VK7JG-NPHTM-C97JM-9MPGT-3V66T").
    # Only after a licence keyword: the same shape spells out error and
    # order references ("ACT-4001-DECLINED-CARD"), so a bare group run stays.
    # A bare "ключ:" is out of the keywords, it names JSON fields.
    keyword_rule("licence_key",
                 r"лицензи\w*(?: ключ)?|ключ\w* (?:активации|продукта|лицензии)|licen[cs]e(?:[_ -]?key)?"
                 r"|activation[_ -]?key|product[_ -]?key|serial(?:[_ -]?(?:number|key))?|серийн\w* (?:номер|ключ)",
                 r"(?<![\w-])[A-Z0-9]{4,8}(?:-[A-Z0-9]{4,8}){3,}(?![\w-])", P["token"],
                 gap=r"[^\w\n<]{0,8}", accept=_has_digit_and_letter, flags=re.IGNORECASE | re.MULTILINE),
    # --- crypto (before the generic hex/base64 secret rules) ---
    # An address or a hash keeps its shape when a label is glued to it with an
    # underscore ("usdt_TJRab...", "кошелек_0x..."), so only a letter or a
    # digit in front cancels these rules.
    Rule("seed_phrase", re.compile(
        rf"(?<![A-Za-z])(?:\d{{1,2}}[.)]\s*)?{_SEED_WORD}(?:{_SEED_SEP}{_SEED_WORD}){{11,}}(?![A-Za-z])",
        re.IGNORECASE), P["seed"]),
    Rule("txid", re.compile(r"(?<![^\W_])(?:0x)?[0-9a-fA-F]{64}(?![\w])"), P["txid"]),
    Rule("txid", re.compile(rf"(?<![^\W_]){_B58}{{86,88}}(?![\w])"), P["txid"]),
    Rule("wallet", re.compile(rf"(?<![^\W_])T{_B58}{{33}}(?![\w])"), P["wallet"]),                       # TRON
    Rule("wallet", re.compile(r"(?<![^\W_])0x[0-9a-fA-F]{40}(?![\w])"), P["wallet"]),                    # EVM
    Rule("wallet", re.compile(r"(?<![^\W_])(?:bc1|ltc1|tb1)[ac-hj-np-z02-9]{25,62}(?![\w])", re.IGNORECASE), P["wallet"]),
    Rule("wallet", re.compile(rf"(?<![^\W_])[13]{_B58}{{25,34}}(?![\w])"), P["wallet"], _has_digit_and_letter),  # BTC legacy
    Rule("wallet", re.compile(rf"(?<![^\W_])[LM]{_B58}{{26,33}}(?![\w])"), P["wallet"], _has_digit_and_letter),  # LTC legacy
    Rule("wallet", re.compile(rf"(?<![^\W_])D[5-9A-HJ-NP-U]{_B58}{{32}}(?![\w])"), P["wallet"]),         # DOGE
    Rule("wallet", re.compile(rf"(?<![^\W_])r{_B58}{{24,34}}(?![\w])"), P["wallet"], _has_digit_and_letter),     # XRP
    Rule("wallet", re.compile(rf"(?<![^\W_]){_TON_PREFIX}[A-Za-z0-9_-]{{46}}(?![\w])"), P["wallet"]),  # TON
    keyword_rule("wallet",
                 r"sol|solana|кошел(?:[ёе]к|ьк)[а-яё]{0,3}|wallet|адрес(?:\s+для)?\s+(?:пополнения|перевода|вывода|депозита)|deposit address"
                 r"|usdt|usdc|trc-?20|erc-?20|bep-?20|ton|btc|eth",
                 _FALLBACK_WALLET, P["wallet"], gap=r"[^\w\n<]{0,12}(?:адрес|address)?[^\w\n<]{0,6}",
                 accept=lambda m: _has_digit(m) and any(c.isalpha() for c in value_group(m))),
    keyword_rule("memo",
                 r"memo|мемо|destination tag|тег назначения|dest tag|payid|pay id|binance id|binance uid|бинанс id|uid",
                 r"[A-Za-z0-9\-]{4,32}", P["id"], gap=r"[^\w\n<]{0,6}", accept=_has_digit),
    keyword_rule("exchange_uid",
                 rf"(?:{_EXCHANGE})(?:[^\w\n<]{{0,3}}{_EXCHANGE_ACCOUNT})?"                          # "Bybit ID 123", "KuCoin: 123"
                 rf"|{_EXCHANGE_ACCOUNT}[^\w\n<]{{1,3}}(?:(?:на|в|on|in|at|from)[^\w\n<]{{1,3}})?(?:{_EXCHANGE})",  # "ID на бинансе 123"
                 r"\d{5,20}(?![\w])", P["id"], gap=r"[^\w\n<]{0,6}", accept=_exchange_uid_ok),
    # Messenger ids by keyword; a bare "id" stays (order and merchant ids are product vocabulary).
    keyword_rule("tg_id",
                 r"(?:telegram|телеграм\w*|телега|tg|тг|user|юзер|мой|my|его|её|ее|их|наш|ваш|your|chat|чат|peer|icq|аськ\w*)"
                 r"[ _-]?(?:id|айди|айдишник\w*)|(?:user|chat|peer|from|sender)_?id|айди|icq",
                 r"\d{6,13}(?![\d])", P["id"], gap=r"[^\w\n<]{0,6}(?:№|#|no\.?)?[^\w\n<]{0,3}"),
    # --- card companions (card numbers themselves are handled in ``cards``) ---
    # The value is never the first octet of an IP address ("cvv 203.0.113.3").
    keyword_rule("cvv",
                 rf"cvv2?|cvc2?|(?:cid|csc){_LATIN_END}|(?:цвв|свв|цвц){_CYRILLIC_END}|код безопасности"
                 r"|код (?:с обратной стороны|на обратной стороне|на обороте|сзади)|три цифры(?: сзади| на обороте)?|3 цифры",
                 r"\d{3,4}(?!\d|\.\d)", P["cvv"], gap=r"[^\d\n<]{0,20}", accept=_companion_value_ok),
    # "срока действия карты 12/27": singular case forms of "срок" only; the
    # plural "сроки" (deadlines) is no expiry label.
    keyword_rule("expiry",
                 rf"exp(?:ir(?:y|es?|ed|ing|ation)|\.)?(?:[ ._-]?date)?{_LATIN_END}"
                 rf"|срок(?:а|у|ом|е)?{_CYRILLIC_END}(?: действия| карты)?|действ\w* до|годн\w* до|валидн\w* до"
                 r"|valid thru|дата истеч\w*|дата окончания",
                 _EXPIRY_VALUE, P["exp"], gap=r"[^\d\n<]{0,12}", accept=_companion_value_ok),
    keyword_rule("cardholder",
                 r"cardholder(?: name)?|holder|name on card|имя на карте|держател\w*|владел\w* карт\w*|фио|на имя",
                 rf"(?!карт|card)(?:{_NAME}(?:\s+(?:{_NAME}|{_INIT})){{1,2}}|{_INIT}\s+{_NAME})", P["holder"],
                 gap=rf"[^\w\n<]{{0,4}}(?:(?:{_CARD_WORD}|{_CARD_PRODUCT})[^\w\n<]{{0,4}}){{0,4}}", accept=_cardholder_ok),
    # People by keyword, in three tiers of confidence.
    Rule("person", re.compile(rf"(?<![\w.]){_W}{_SP}{_INI}(?![\w])|(?<![\w.]){_INI}{_SP}{_W}(?![\w])"), P["name"]),
    keyword_rule("person",
                 r"меня зовут|его зовут|её зовут|ее зовут|my name is|контактное лицо|контакт\.? лицо"
                 r"|с уважением|best regards|kind regards|regards|sincerely|from:|от:|кому:|to:|cc:",
                 # The name always starts with a capital letter, never with a
                 # blank, so the runs of the gap are taken possessively and
                 # the rule stays linear on a keyword in front of a long run
                 # of spaces ("best regards" and 4000 of them).
                 _FULL, P["name"], gap=r"[,:;\-–—]?[^\S\n]*+\n?[^\S\n]*+"),
    keyword_rule("person", r"ИП|ФОП|ФЛП", _FULL, P["name"], gap=r"[^\S\n]+", flags=0),
    keyword_rule("person", rf"(?:меня|его|её|ее) зовут{_CYRILLIC_END}", _LOW_INTRO_NAME, P["name"],
                 gap=r"[,:;\-–—]?[^\S\n]*"),
    keyword_rule("person", rf"фио{_CYRILLIC_END}|контакт(?:ное|\.?) лицо|получател\w*|плательщик\w*", _LOW_NAME,
                 P["name"], gap=r"[,:;\-–—]?[^\S\n]*"),
    keyword_rule("person",
                 r"ген(?:еральный)?\.?[^\S\n]?директор|директор|руководитель|бухгалтер|главбух|учредитель|владелец"
                 r"|представитель|менеджер|сотрудник|получател\w*|плательщик\w*",
                 rf"(?=(?:{_W}{_SP})*{_W}{_SURNAME_SUFFIX}(?![a-zа-яё])){_FULL}", P["name"],
                 gap=r"[^\w\n<]{0,3}(?:компании|организации|фирмы)?[^\w\n<]{0,3}"),
    # Ad-platform ids before bank details: "ad account N" is not a bank account.
    Rule("ad_account", re.compile(r"(?<![\w])act_\d{6,}(?![\w])"), "act_" + P["id"]),
    keyword_rule("ad_account",
                 r"бм|bm|business manager|пиксель|pixel|page id|кабинет|ad account|рекламн\w* (?:аккаунт|кабинет)|advertiser(?: id)?"
                 r"|bc id|tiktok|тикток|google ads|гугл адс|customer id|cid",
                 r"\d{3}-\d{3}-\d{4}(?![\d])|\d{9,20}(?![\d])", P["ad"], gap=r"[^\w\n<]{0,8}(?:id[^\w\n<]{0,3})?"),
    # Bank details before the OTP rule: "sort code 040004" is a bank code, not a one-time code.
    keyword_rule("bank_code",
                 r"routing(?: number| no\.?| num| #)?|aba(?: number| routing)?|sort ?code|bsb(?: number)?"
                 r"|transit (?:number|no\.?|#)|institution (?:number|no\.?|#)",
                 r"\d{2,3}(?:[ \-]?\d{2,3}){1,3}(?!\d)", P["bank_code"],
                 gap=r"[^\w\n<]{0,6}(?:№|#|no\.?|number|num)?[^\w\n<]{0,4}", accept=_digit_count(5, 9)),
    keyword_rule("bank_account",
                 r"account(?: number| no\.?| num| #)?|acct(?:\.| number| no\.?)?|acc\.? ?(?:no\.?|number)|a/c|номер сч[её]та"
                 r"|сч[её]т получателя|расч[её]тн\w* сч[её]т|р/с|clabe|iban/account",
                 r"\d{7,20}(?!\d)|\d{4}(?: \d{4}){1,4}(?!\d)", P["account"],
                 gap=r"[^\w\n<]{0,6}(?:№|#|no\.?)?[^\w\n<]{0,4}", accept=_digit_count(7, 20)),
    # Lists of backup codes go before the OTP rule, which would take only the first one.
    keyword_rule("backup_codes",
                 r"backup codes?|recovery codes?|резервн\w* код\w*|запасн\w* код\w*|коды? восстановления|бэкап[- ]?код\w*",
                 rf"{_BACKUP_CODE}(?:[ \t,;\n]{{1,3}}{_BACKUP_CODE}){{0,15}}", P["otp"],
                 gap=r"[^\w<-]{0,12}", accept=not_error_code),
    # "код"/"code" only as whole words (with Russian case endings): "кодировка 1234" is prose.
    # A code kind in the genitive right after "код" ("код ответа" = response
    # code, "код категории" = MCC) makes it a reference; checked here, not in
    # ``accept``, so a later "код" in the same sentence is still reached.
    keyword_rule("otp",
                 r"код(?:а|ы|ов|ом|у|е)?(?: подтверждения| из смс| из sms)?(?![\w])"
                 rf"(?!{_CODE_KIND})"
                 r"|codes?(?![\w])|otp|passcode|пасс-?код|одноразовый пароль|one[- ]time password|3-?ds(?: код| code)?"
                 # "пароль из смс", "пин из sms" name the same one-time code,
                 # and a confirmation key names it in JSON and query strings.
                 r"|(?:пароль|пин|код)[ \t]+(?:из|с|в)[ \t]+(?:смс|sms)|кодик[^\W\d_]*"
                 r"|(?<![A-Za-z])(?:sms|otp|verification|verify|confirm(?:ation)?|auth)[_-]?code",
                 r"\d{4,8}(?!\d)", P["otp"], gap=r"[^\d\n<]{0,30}", accept=_otp_context_ok),
    keyword_rule("pin", rf"(?:pins?|pin-?codes?){_LATIN_END}|пин(?:-?код)?(?:а|у|ом|е|ы|ов|ам|ами|ах)?{_CYRILLIC_END}",
                 r"\d{4,6}(?!\d)", P["pin"], gap=r"[^\d\n<]{0,10}", accept=_companion_value_ok),
    # --- identity documents ---
    # A '+' in front means a phone in international format, never a tax id.
    Rule("kz_id", re.compile(r"(?<![\w+])\d{12}(?![\w])"), P["iin"], _kz_id, _kz_render),
    Rule("ua_rnokpp", re.compile(r"(?<![\w+])\d{10}(?![\w])"), P["rnokpp"], _ua_id),
    Rule("by_id", re.compile(r"(?<![A-Z0-9])[1-6]\d{6}[ABCEHKM]\d{3}(?:PB|BA|BI)\d(?![A-Z0-9])"), P["personal"]),
    Rule("kg_pin", re.compile(
        r"(?<![\w])[12](?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])(?:19[2-9]\d|20[012]\d)\d{5}(?![\w])"), P["personal"]),
    # A group separator may be the line break the client's app wrapped the
    # number at ("СНИЛС 112-233\n445 95"): without it the number stays in
    # clear on both lines.
    keyword_rule("snils", r"снилс|snils",
                 rf"\d{{3}}{GROUP_SEP}\d{{3}}{GROUP_SEP}\d{{3}}{GROUP_SEP}\d{{2}}{NUMBER_END}(?![./:\-]\d)",
                 P["snils"], gap=r"[^\w\n<]{0,6}(?:№|#|no\.?)?[^\w\n<]{0,3}", in_identifier=True),
    keyword_rule("tax_id",
                 r"ИИН|ЖСН|IIN|ИНН|ИПН|ІПН|РНОКПП|РНУКПН|ПИНФЛ|ПІНФЛ|PINFL|JShShIR|ЄДРПОУ|ЕГРПОУ|ЕДРПОУ|УНП"
                 r"|номер налогоплательщика|tax id|tin|личный номер|персональный номер|pesel|cnp|codice fiscale",
                 rf"[A-Z]{{0,2}}(?:\d{{8,16}}|\d{{2,6}}(?:[ \-]\d{{2,6}}){{1,5}}){NUMBER_END}(?![./:\-]\d)", P["tax"],
                 gap=r"[^\w\n<]{0,6}(?:№|#|no\.?)?[^\w\n<]{0,3}", accept=_digit_count(8, 16), in_identifier=True),
    # A Russian passport is a four-digit series and a six-digit number, and
    # clients paste the two on separate lines as often as on one ("Серия
    # 4509\nНомер 123456"). Across the line break the number label is
    # mandatory: without it the next line's number is any number ("Серия
    # 2024\n123456 заказов").
    keyword_rule("passport",
                 # Letters only after a stem: a file name glues the number to
                 # the keyword with '_' ("паспорт_4509123456"), and "\\w*"
                 # would read that number as part of the word.
                 r"паспорт[^\W\d_]*|passport|удостоверени[^\W\d_]*|уд\.?[ \t]?л(?:ичн[^\W\d_]*)?\.?|удв"
                 r"|id[- ]?card|загран[^\W\d_]*|серия и номер|серия"
                 r"|свидетельств[^\W\d_]* о рождении",
                 rf"(?:{_series(1, 3)})?\d{{2}}[ \t_]?\d{{2}}"
                 rf"(?:[ \t,_]{{0,2}}(?:{_DOC_NO})?|[ \t,;]*\n[ \t]*{_DOC_NO})\d{{6}}{NUMBER_END}"
                 rf"|{_series(1, 2)}(?:{_DOC_NO})?\d{{6,8}}{NUMBER_END}|\d{{2}}[ \t]?\d{{7}}{NUMBER_END}"
                 rf"|\d{{9,10}}{NUMBER_END}",
                 P["passport"], gap=r"(?:[^\d\n<]{0,24}[^\w\n<])?", in_identifier=True),
    # "права" is also access rights: an id word is never a licence series
    # ("права админа, ID 1234567", "права в БМ 1234567").
    keyword_rule("driver_licence",
                 rf"в/у|ву{_CYRILLIC_END}|вод\.?[ \t]?уд[^\W\d_]*\.?|водительск\w*(?: \w+)?|driver'?s? licen[cs]e|права",
                 rf"\d{{2}}\s?[А-ЯA-Z0-9]{{2}}\s?\d{{6}}(?![\w])"
                 rf"|(?!(?-i:ID|BM|БМ|TG|ТГ)\s?\d){_series(2, 3, r'\s')}\d{{6,7}}(?![\w])", P["licence"],
                 gap=r"(?:[^\d\n<]{0,19}[^\w\n<])?"),
    keyword_rule("dob",
                 rf"др(?:а|у|ом|е)?{_CYRILLIC_END}|д\.р\.|д/р|дат\w* рожд\w*\.?|день рождения(?![^\S\n]+компании)"
                 r"|родил\w*|born|dob|date of birth|birth ?date|birthday",
                 _DOB_VALUE, P["dob"], gap=r"[^\d\n<]{0,12}"),
    # "01.01.1990 г.р.": the keyword follows the value.
    Rule("dob", re.compile(
        rf"(?<![\d.])(?:{_DOB_VALUE}|(?:19|20)\d{{2}}(?![\d]))"
        r"(?=\s*(?:г\.\s?р(?:\.|(?=[\s,;]|$))|года?\s+рожд\w*|г\.\s?рожд\w*))", re.IGNORECASE | re.UNICODE), P["dob"]),
    keyword_rule("address", _ADDRESS_KEYWORDS, _ADDRESS_VALUE, P["address"], gap=r"[^\w\n<]{0,4}",
                 accept=_looks_like_address),
    Rule("address", re.compile(
        rf"(?<![\w]){_CITY}{_STREET}{_STREET_NAME}(?:(?:д\.|дом|house|№)\s*+)?"
        rf"{_HOUSE_NUMBER_START}\d{{1,4}}[а-яa-z]?{_BLD}{_BLD}{_FLAT}", re.IGNORECASE), P["address"]),
    Rule("address", re.compile(
        rf"(?<![\w])\d{{1,6}}\s+{_EN_STREET_WORD}(?:\s+{_EN_STREET_WORD}){{0,4}}\s+{_STREET_EN}\.?"
        r"(?:\s+(?:N|S|E|W|NE|NW|SE|SW))?(?:\s*,?\s*(?:apt|suite|ste|unit|#)\s*\w+)?(?![\w])", re.IGNORECASE), P["address"]),
    # Bare "адрес:" with a separator; the letter+digit gate keeps "адрес: почему не проходит?" intact.
    keyword_rule("address", r"адрес", r"[^\n]{6,120}", P["address"], gap=r"[^\w\n<]{0,2}[:=\-—][^\w\n<]{0,3}",
                 accept=_looks_like_street_address),
    keyword_rule("postcode",
                 rf"(?:почтовый индекс|индекс(?:а|ом|у|е)?){_CYRILLIC_END}|zip(?:[ -]?code)?{_LATIN_END}|postcode|postal code",
                 r"\d{5,6}(?!\d)", P["postcode"], gap=r"[^\d\n<]{0,6}"),
    # --- payment references ---
    Rule("txn_ref", re.compile(r"(?<![\w])[27]\d{22}(?![\w])"), P["txn"]),                              # ARN
    keyword_rule("txn_ref",
                 r"rrn|arn|stan|auth(?:orization)? code|approval code|код авторизации|номер транзакции|transaction id"
                 r"|txn id|trace id|receipt(?: id| number)?|invoice|инвойс",
                 r"[A-Za-z0-9\-]{6,32}(?![\w])", P["txn"], gap=r"[^\w\n<]{0,8}(?:№|#|no\.?)?[^\w\n<]{0,3}", accept=_has_digit),
    Rule("user_agent", _USER_AGENT, P["ua"]),
    keyword_rule("device_id", r"imei|iccid|sim(?:[- ]?card)?|серийн\w* номер|serial(?: number)?|s/n",
                 r"[A-Z0-9]{8,20}(?![\w])", "<device-id>", gap=r"[^\w\n<]{0,8}", accept=_has_digit),
)

# A three-digit "код", and an expiry after a bare "до", belong to a card only
# in a message that also carries a card number; the scrubber applies both
# after the table when it masked one ("карта 5105 1051 0510 5100, CVV 737,
# до 03/30").
CARD_CVV_RULE = keyword_rule("cvv", r"код|code", r"\d{3}(?!\d)", P["cvv"], gap=r"[^\d\n<]{0,6}", accept=not_error_code)
CARD_EXPIRY_RULE = keyword_rule("expiry", r"до|by|valid(?: thru)?", _CARD_EXPIRY_VALUE, P["exp"],
                                gap=r"[^\d\n<]{0,6}", accept=_companion_value_ok)

# Public-suffix-ish list for bare domains written without a scheme ("acme.ru").
DOMAIN_TLDS = (
    "ru com net org io app store site online shop xyz top club pro info kz ua by uz kg me co biz link dev ai su "
    "рф cc tv vip life world space fun live click one cloud digital agency team money cash finance bank card cards "
    "pay ge am md tj tm lt lv ee pl de fr it es nl uk us ca in br tr ae il"
).split()
_DOMAIN_LABELS = r"(?:[a-z0-9а-яё](?:[a-z0-9а-яё\-]{0,61}[a-z0-9а-яё])?\.)+"
# Suffixes that are also English words or payment products: "Yandex.Money",
# "App.Store", "Apple.Pay" and a sentence glued to the next one ("Done.It")
# are prose, so such a suffix makes a host only in lower case ("acme.store")
# or in a fully shouted host ("ACME.STORE"). Country and generic suffixes
# match in any case: Russians write "Ромашка.РФ", "Acme.Ru".
_WORD_TLDS = frozenset(
    "money pay cash card cards bank finance store app it in me us am one team live life fun click".split())
_ANY_CASE_TLD = "(?:" + "|".join(t for t in DOMAIN_TLDS if t not in _WORD_TLDS) + ")"
_WORD_TLD = "(?:" + "|".join(t for t in DOMAIN_TLDS if t in _WORD_TLDS) + ")"
_UPPER_LABELS = r"(?:[A-Z0-9А-ЯЁ](?:[A-Z0-9А-ЯЁ\-]{0,61}[A-Z0-9А-ЯЁ])?\.)+"
# A host ends at anything but a label character; a dot ends it only when no
# label follows, so "наш сайт romashka.ru." is still a host.
_HOST_END = r"(?![\w\-]|\.[\w\-])"
# Well-known documentation files are not hosts, although ".md" is Moldova.
_DOC_FILE = (r"(?:readme|changelog|changes|contributing|license|licence|security|install|upgrading|migration|faq"
             r"|todo|authors|history|roadmap)\.md")
# A host written without a scheme ("acme.ru"); the scrubber and the leak
# scanner share it.
BARE_DOMAIN = re.compile(
    rf"(?<![\w@/.\-])(?!{_DOC_FILE}{_HOST_END})"
    rf"(?:{_DOMAIN_LABELS}(?:{_ANY_CASE_TLD}|(?-i:{_WORD_TLD}))"
    rf"|(?-i:{_UPPER_LABELS}{_WORD_TLD.upper()})){_HOST_END}",
    re.IGNORECASE)
