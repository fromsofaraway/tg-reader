"""Operation references are product knowledge, identifiers of people are not.

* An order, ticket, transaction, invoice or payment number written right
  after its label stays, also when it happens to pass an INN, OGRN, KZ IIN
  or UA RNOKPP checksum; a bare checksum-valid number, a number after a
  requisites or counterparty word ("ИНН заказчика: ...", "реквизиты для
  оплаты: ...") and a number whose label is not adjacent are still tax ids.
* An order reference or an ALL_CAPS constant after a coin keyword ("usdt:
  INV-20260312-000123-ABCD") is no wallet; a TON address glued to a word or
  cut short, and any other address followed by a dashed suffix, still is.
* A user-agent ends with its last token: the error code, status or Russian
  sentence after it stays, and an access-log timestamp or a clock with
  milliseconds is no IPv6 address.

Every scrubbed case is also flagged by the leak scanner on the raw text and
passes it on the output; every kept case stays byte-identical and the
scanner is silent on it."""

import random

import pytest

from conftest import assert_fast, check
from tg_collector.cards import luhn_ok
from tg_collector.config import AnonPolicy
from tg_collector.fintech import kz_id_ok, ua_rnokpp_ok
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber, _inn_ok, _ogrn_ok

BINS = ("424242", "400000", "510510")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS, keep_terms=("Northwind",)),
                    Roster(keep_terms=("Northwind",))).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS), keep_terms=frozenset({"Northwind"})))


def kept(scrub, scanner, text):
    check(scrub, scanner, text, text)


# --- checksum-valid order and transaction numbers -------------------------------------------------

@pytest.mark.parametrize("text", [
    # RNOKPP-valid (3184713454), INN-valid (7700000425, 770000000082, 9876543210),
    # OGRN-valid (1027700000041), OGRNIP-valid (391315064287204), IIN-valid (020531600149).
    "заказ 3184713454",
    "заказ №3184713454 не прошёл",
    "Заказ № 3184713454 не прошёл",
    "ЗАКАЗ 3184713454",
    "по заказу 3184713454 не пришли деньги",
    "Номер заказа: 7700000425",
    "Номер заказа:\n3184713454",
    "номер заказа\n3184713454",
    "заказ под номером 3184713454",
    "заказ номер 3184713454",
    "ЗАКАЗА 770000000082",
    "заказ 770000000082",
    "заказ 020531600149",
    "заказ 391315064287204",
    "Анна, заказ 9876543210 не прошёл",
    "в личном кабинете заказ 3184713454 висит",
    "транзакция 3184713454 отклонена",
    "транзакция 1027700000041",
    "Олег, по транзакции 1027700000041 списали",
    "ID транзакции 1027700000041",
    "BIN 424242, транзакция 3184713454 отклонена",
    "тикет 3184713454",
    "тикет 020531600149",
    "по тикету №7700000425 нет ответа",
    "заявка 3184713454",
    "по заявке 7700000425 ответа нет",
    "обращение 3184713454 закрыто",
    "по обращению №770000000082 нет ответа",
    "ID платежа: 7700000425",
    "номер платежа 3184713454",
    "№ платежа 3184713454",
    "номер операции 7700000425",
    "id оплаты 3184713454",
    "order #3184713454",
    "order number 7700000425",
    "Refund for order 9876543210 is stuck",
    "order_id=7700000425",
    "order_id=3184713454 лимит=1000",
    "ticket: 3184713454",
    "payment id 3184713454",
    "PaymentId 7700000425",
    "txn 1027700000041",
    "заказ 3184713454:paid",
])
def test_labelled_operation_numbers_stay(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected,kind", [
    # A bare checksum-valid number is still a tax id.
    ("просто 3184713454", "просто <rnokpp>", "ua_rnokpp"),
    ("и 770000000082", "и <inn>", "inn"),
    ("вот 020531600149", "вот <iin>", "kz_id"),
    ("просто 7700000425", "просто <inn>", "inn"),
    ("просто 1027700000041", "просто <ogrn>", "ogrn"),
    # Requisites and counterparty words are no operation labels.
    ("ИНН заказчика: 7700000425", "ИНН заказчика: <inn>", "inn"),
    ("ИНН Заказчика 770000000082", "ИНН Заказчика <inn>", "inn"),
    ("ИНН заказчика 7700000425", "ИНН заказчика <inn>", "inn"),
    ("Заказчик: 7700000425", "Заказчик: <inn>", "inn"),
    ("заказчика 7700000425", "заказчика <inn>", "inn"),
    ("реквизиты заказчика: 7700000425", "реквизиты заказчика: <inn>", "inn"),
    ("ОГРНИП заказчика 391315064287204", "ОГРНИП заказчика <ogrn>", "ogrn"),
    ("ИНН получателя платежа: 770000000082", "ИНН получателя платежа: <inn>", "inn"),
    ("ИНН получателя платежа: 7700000425", "ИНН получателя платежа: <inn>", "inn"),
    ("получатель платежа: 7700000425", "получатель платежа: <inn>", "inn"),
    ("ИИН для вывода: 020531600149", "ИИН для вывода: <iin>", "kz_id"),
    ("ИНН для оплаты: 7700000425", "ИНН для оплаты: <inn>", "inn"),
    ("реквизиты для оплаты: 7700000425", "реквизиты для оплаты: <inn>", "inn"),
    ("Реквизиты для оплаты:\n770000000082", "Реквизиты для оплаты:\n<inn>", "inn"),
    ("Реквизиты для перевода:\n7700000425", "Реквизиты для перевода:\n<inn>", "inn"),
    ("Реквизиты для платежа: 7700000425", "Реквизиты для платежа: <inn>", "inn"),
    ("РНОКПП для оплаты: 3184713454", "РНОКПП для оплаты: <rnokpp>", "ua_rnokpp"),
    ("ИИН для перевода: 020531600149", "ИИН для перевода: <iin>", "kz_id"),
    ("ИИН отправителя перевода: 020531600149", "ИИН отправителя перевода: <iin>", "kz_id"),
    ("ИНН в чеке: 7700000425", "ИНН в чеке: <inn>", "inn"),
    # A tax or requisite word shortly before an operation label keeps the checksum in charge.
    ("ИНН по заказу: 7700000425", "ИНН по заказу: <inn>", "inn"),
    ("инн по заказу: 7700000425", "инн по заказу: <inn>", "inn"),
    ("иин по заявке 020531600149", "иин по заявке <iin>", "kz_id"),
    ("реквизиты плательщика, заявка 020531600149", "реквизиты плательщика, заявка <iin>", "kz_id"),
    # A bare "id", "платёж", "оплата", "перевод", "операция" or "чек" is no operation label.
    ("id 3184713454", "id <rnokpp>", "ua_rnokpp"),
    ("ID: 020531600149", "ID: <iin>", "kz_id"),
    ("national ID: 3184713454", "national ID: <rnokpp>", "ua_rnokpp"),
    ("Personal ID: 020531600149", "Personal ID: <iin>", "kz_id"),
    ("платёж 3184713454 завис", "платёж <rnokpp> завис", "ua_rnokpp"),
    ("оплата 3184713454", "оплата <rnokpp>", "ua_rnokpp"),
    ("предоплата 3184713454", "предоплата <rnokpp>", "ua_rnokpp"),
    ("перевод 7700000425", "перевод <inn>", "inn"),
    ("операция 3184713454", "операция <rnokpp>", "ua_rnokpp"),
    ("чек №3184713454", "чек №<rnokpp>", "ua_rnokpp"),
    # The label must be adjacent: a word or a blank line in between ends it.
    ("заказ от 7700000425", "заказ от <inn>", "inn"),
    ("заказ\n\n3184713454", "заказ\n\n<rnokpp>", "ua_rnokpp"),
    ("заказ 3184713454 и 7700000425", "заказ 3184713454 и <inn>", "inn"),
    ("заказ 7700000425, ИНН 770000000082", "заказ 7700000425, ИНН <tax-id>", "tax_id"),
    ("заказ 123, ИНН 7700000425", "заказ 123, ИНН <tax-id>", "tax_id"),
    ("заказ 12, ИИН 020531600149", "заказ 12, ИИН <iin>", "tax_id"),
    ("ИНН 7700000425 и 770000000082", "ИНН <tax-id> и <inn>", "inn"),
    ("ИНН/КПП 7700000425/770701001", "ИНН/КПП <inn>/770701001", "inn"),
    # A label is a whole word.
    ("paid 3184713454", "paid <rnokpp>", "ua_rnokpp"),
    ("Kazakhstan 3184713454", "Kazakhstan <rnokpp>", "ua_rnokpp"),
    # An earlier replacement between the label and the number ends the label,
    # in the scrubber (a sentinel) and in the scanner (a placeholder) alike.
    ("заказ @oleg_support 7700000425", "заказ @user <inn>", "inn"),
    ("заказ oleg@example.com 7700000425", "заказ <email> <inn>", "inn"),
    # Payment references keep their own keyword rule.
    ("invoice 3184713454", "invoice <txn-ref>", "txn_ref"),
    ("инвойс 770000000082", "инвойс <txn-ref>", "txn_ref"),
    ("transaction id 3184713454", "transaction id <txn-ref>", "txn_ref"),
    # Earlier keyword rules, cards and national phone shapes are unaffected.
    ("user id 3184713454", "user id <id>", "tg_id"),
    ("bybit uid 3184713454", "bybit uid <id>", None),
    ("заказ 380501234567", "заказ <phone>", "phone"),
    ("order 79991234567", "order <phone>", "phone"),
    ("заказ 6011111111111117", "заказ 601111**********", "card"),
    ("транзакция 4242424242424242", "транзакция 424242**********", "card"),
])
def test_tax_ids_near_operation_words_are_still_scrubbed(scrub, scanner, text, expected, kind):
    check(scrub, scanner, text, expected, kind)


def _checksum_ids(length, accept, count=40):
    rng = random.Random(length)
    found = []
    while len(found) < count:
        v = rng.choice("123456789") + "".join(rng.choice("0123456789") for _ in range(length - 1))
        if v[:3] in ("380", "375", "998", "996", "995", "374", "992", "993") or luhn_ok(v):
            continue  # national phone shapes and card-shaped runs are other rules
        if accept(v):
            found.append(v)
    return found


@pytest.mark.parametrize("length,accept", [
    (10, lambda v: ua_rnokpp_ok(v) or _inn_ok(v)),
    (12, lambda v: kz_id_ok(v) or _inn_ok(v)),
    (13, _ogrn_ok),
    (15, _ogrn_ok),
])
def test_random_checksum_valid_ids_follow_their_label(scrub, scanner, length, accept):
    for v in _checksum_ids(length, accept):
        for label in ("заказ ", "транзакция №", "Номер заказа: ", "order #"):
            kept(scrub, scanner, label + v)
        out = scrub("просто " + v)
        assert out != "просто " + v and out.startswith("просто <"), (v, out)
        assert scanner.scan("просто " + v) and not scanner.scan(out)


def test_placeholders_after_operation_labels_are_not_flagged(scanner):
    for text in ("заказ <rnokpp>", "транзакция <ogrn>", "Номер заказа: <inn>",
                 "order #<iin>", "заказ <company-id>"):
        assert not scanner.scan(text), text


def test_operation_label_check_is_linear(scrub):
    for text in ("заказ 3184713454 " * 250, "заказ " + "№" * 4000 + " 3184713454",
                 "order" + "_" * 4000 + "3184713454", "ИНН по заказу: 7700000425 " * 160, "заказа " * 600):
        assert_fast(lambda: scrub(text), label=text[:40])


# --- one label carries a whole list of references -------------------------------------------------

@pytest.mark.parametrize("text", [
    # every number of a labelled list is a reference, not only the first
    "заказы: 7700000425, 7700000023, 7700000016",
    "заказы: 3184713454, 7700000425",
    "заказы: 3184713454; 7700000425 / 7700000023",
    "заказы 3184713454, 7700000425",
    "тикеты 123456, 7700000425",
    "тикеты: 12345, 7700000425",
    "по заказам 248965822333597, 851912492530126",
    "транзакции: 12345, 1027700000041",
    "заявки: 12345, 020531600149",
    "обращения: 12345, 3184713454",
    "инвойсы: 12345, 770000000082",
    "orders: 12345, 7700000425",
    "tickets 123456, 3184713454",
    "заказы: 12345, 67890, 7700000425",
])
def test_every_number_of_a_labelled_list_is_a_reference(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected,kind", [
    # a tax-id or requisites word inside the list keeps the checksum in charge
    ("заказы: 12345, ИНН 7700000425", "заказы: 12345, ИНН <tax-id>", "tax_id"),
    ("заказы: 3184713454, ИНН 7700000425", "заказы: 3184713454, ИНН <tax-id>", "tax_id"),
    ("заказы: 3184713454, реквизиты 7700000425", "заказы: 3184713454, реквизиты <inn>", "inn"),
    ("заказы: 12345, 7700000425 и мой ИНН 7700000023",
     "заказы: 12345, 7700000425 и мой ИНН <tax-id>", "tax_id"),
    # a word or a line break after the last comma ends the list
    ("заказы: 12345, вот 7700000425", "заказы: 12345, вот <inn>", "inn"),
    ("заказы: 12345,\n7700000425", "заказы: 12345,\n<inn>", "inn"),
    ("заказы 12345 7700000425", "заказы 12345 <inn>", "inn"),
    # a singular label reaches only its own number
    ("заказ 3184713454 и 7700000425", "заказ 3184713454 и <inn>", "inn"),
    # phones, cards and the keyword rules are unaffected
    ("заказы: 3184713454, 7700000425, телефон 79161234567",
     "заказы: 3184713454, 7700000425, телефон <phone>", "phone"),
    ("заказы: 12345, 79161234567", "заказы: 12345, <phone>", "phone"),
    ("заказы: 12345, 6011111111111117", "заказы: 12345, 601111**********", "card"),
])
def test_a_list_label_does_not_shield_a_tax_id(scrub, scanner, text, expected, kind):
    check(scrub, scanner, text, expected, kind)


def test_the_list_label_check_is_linear(scrub):
    for text in ("заказы: " + "1234567, " * 460, "заказы: " + "1" * 4000,
                 "заказы: 3184713454, 7700000425 " * 130, "заказы" + "," * 4000 + " 7700000425"):
        assert_fast(lambda: scrub(text), label=text[:40])


# --- references after coin keywords ----------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "usdt: INV-20260312-000123-ABCD-EFGH",
    "btc TXN-2026-03-12-000123-ABCDEF",
    "btc TXN-2026-03-12-000123-ABCDEF статус declined",
    "eth: order-2026-03-12-000123-abcdef",
    "usdt INV_20260312_000123_ABCD_EFGH",
    "Кошелёк: ORDER-2026-03-12-000123-XYZ",
    "кошелек: INV-20260312-000123-ABCD-EFGH не оплачен",
    "usdt 550e8400-e29b-41d4-a716-446655440000",
    "USDT trc20 invoice_2026_03_12_000123_abcdef",
    "перевёл usdt на TRC-20: 20260312-ORDER-000123-ABCDEF-XYZ",
    "USDT_TRC20_WITHDRAWAL_DISABLED",
    "ошибка USDT_ERC20_DEPOSIT_ADDRESS_INVALID",
    "BTC_NETWORK_FEE_EXCEEDS_LIMIT_V2",
    "SOLANA_RPC_ENDPOINT_TIMEOUT_2",
    "wallet-api-deployment-7d9f8b6c5-x2x4z упал",
    "пополнил на 500 usdt, комиссия 1 usdt",
])
def test_references_after_coin_keywords_stay(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected", [
    ("sol 7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK", "sol <wallet>"),
    ("кошелек nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3", "кошелек <wallet>"),
    ("адрес для пополнения GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H", "адрес для пополнения <wallet>"),
    ("usdt cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02", "usdt <wallet>"),
    ("Кошелёк для вывода USDT: 7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV",
     "Кошелёк для вывода USDT: <wallet>"),
    ("кошелёк TXk3v8Qp1zE9dLmN7yHcR4tW2sBfG6aJhK", "кошелёк <wallet>"),
    ("usdt TRC20 TXk9Yh2mNqP4vR7sT1uW3xZ5aB8cD6eF9g", "usdt TRC20 <wallet>"),
    # TON: dashes and underscores belong to the address, also glued or cut short.
    ("ton EQDrjaLahLkMB-hMCmkzOyBuHJ139ZUYmPHu6RRBKnbdLIYI", "ton <wallet>"),
    ("ton UQBFz01R2RlhMWLe1yMaz2DiT8JcDtBCwCbNRO4oLl2NBgYr", "ton <wallet>"),
    ("ton kfD4FPq-PRDieyQKkizFTRtSDyucUIqrj0v_zXJmqaDp6_0t", "ton <wallet>"),
    ("kfD4FPq-PRDieyQKkizFTRtSDyucUIqrj0v_zXJmqaDp6_0t", "<wallet>"),
    ("ton EQDrjaLahLkMB-hMCmkzOyBuHJ139ZUYm", "ton <wallet>"),
    ("ton EQDrjaLahLkMB-hMCmkzOyBuHJ139ZUYmPHu6RRBKnbdLIY", "ton <wallet>"),
    ("ton EQDrjaLahLkMB-hMCmkzOyBuHJ139ZUYmPHu6RRBKnbdLIYIабв", "ton <wallet>абв"),
    ("ton EQDrjaLahLkMB-hMCmkzOyBuHJ139ZUYmPHu6RRBKnbdLIYIы", "ton <wallet>ы"),
    ("tonEQDrjaLahLkMB-hMCmkzOyBuHJ139ZUYmPHu6RRBKnbdLIYI", "ton<wallet>"),
    ("ton EQaaaaaaaaaaaaaaaaaaaaaaaaaa1-bbbbbbbbbbbbbbbbbbbbb", "ton <wallet>"),
    ("кошелёк: EQDrjaLahLkMB-hMCmkzOyBuHJ139Z-YmPHu6RRBKnbdLIYIzz", "кошелёк: <wallet>"),
    ("кошелек UQA_b-c_d-e_f1234567890abcdefghijklmnopqrstuv", "кошелек <wallet>"),
    # Any other address is taken up to a dash or an underscore; the suffix is no address.
    ("sol 7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV-проверьте", "sol <wallet>-проверьте"),
    ("sol 7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV-abc", "sol <wallet>-abc"),
    ("sol 7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV-abc-def", "sol <wallet>-abc-def"),
    ("sol 7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK-это мой", "sol <wallet>-это мой"),
    ("кошелек 7EqQdEULxWcraVx3mXKFjc84LhCkMG_a_b", "кошелек <wallet>_a_b"),
    ("кошелек 7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK_old_2", "кошелек <wallet>_old_2"),
])
def test_wallets_after_coin_keywords_are_still_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "wallet")


def test_fallback_wallet_is_linear(scrub):
    for text in ("usdt " + "a" * 4091, "usdt EQ" + "-" * 4089, "tonEQ-" * 682, "usdt " + "a-" * 2045,
                 "usdt " + "nano_" * 818, "usdt " * 819):
        assert_fast(lambda: scrub(text), label=text[:40])


# --- user-agents end with their last token ---------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("UA Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) — ошибка 4001 на шаге 3DS в 12:30",
     "UA <user-agent> — ошибка 4001 на шаге 3DS в 12:30"),
    ('203.0.113.7 - - [12/Mar/2026:10:00:00] "POST /api/pay HTTP/1.1" 500 123 "-" '
     '"Mozilla/5.0 (X11; Linux) Chrome/120" rt=0.5 upstream=api-2 err=4001',
     '<ip> - - [12/Mar/2026:10:00:00] "POST /api/pay HTTP/1.1" 500 123 "-" "<user-agent>" rt=0.5 upstream=api-2 err=4001'),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0, потом ошибка 5003",
     "<user-agent>, потом ошибка 5003"),
    ("Mozilla/5.0 (X11; Linux) Chrome/120. Заказ 12345 не прошёл", "<user-agent>. Заказ 12345 не прошёл"),
    ("Клиент платит с Mozilla/5.0 (Linux; Android 13; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/120.0.0.0 Mobile Safari/537.36, после ввода кода 3DS получает ошибку 05 do not honor",
     "Клиент платит с <user-agent>, после ввода кода 3DS получает ошибку 05 do not honor"),
    ("юзерагент: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36; "
     "платёж висит в статусе PENDING, заказ 48213",
     "юзерагент: <user-agent>; платёж висит в статусе PENDING, заказ 48213"),
    ("Клиент с Mozilla/5.0 (Linux; Android 13) Chrome/120.0.0.0 Mobile Safari/537.36 получил ошибку 3DS_TIMEOUT, "
     "заказ 123456", "Клиент с <user-agent> получил ошибку 3DS_TIMEOUT, заказ 123456"),
    ("UA: Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 — ошибка 3DS_TIMEOUT",
     "UA: <user-agent> — ошибка 3DS_TIMEOUT"),
    ("2026-09-15 14:05:11 ERROR Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/128.0.0.0 Safari/537.36 -> 4001", "2026-09-15 14:05:11 ERROR <user-agent> -> 4001"),
    ('{"ua":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) '
     'Version/17.1 Safari/605.1.15","code":"05"}', '{"ua":"<user-agent>","code":"05"}'),
    ('"userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) '
     'Version/17.0 Safari/605.1.15", "status": "DECLINED"', '"userAgent": "<user-agent>", "status": "DECLINED"'),
    ("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) не пускает, статус 403",
     "<user-agent> не пускает, статус 403"),
    ("Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537.36 status=declined code=05 ip=203.0.113.7",
     "<user-agent> status=declined code=05 ip=<ip>"),
    ("Mozilla/5.0 (X11; Linux) Chrome/120 Safari/537.36 err=4001", "<user-agent> err=4001"),
    ("Mozilla/5.0 (X11; Linux) Chrome/120 (ошибка 4001) и дальше", "<user-agent> (ошибка 4001) и дальше"),
    ("Mozilla/5.0 (X11; Linux) Chrome/120 ok then error at api/v2", "<user-agent> ok then error at api/v2"),
    ("UA: Mozilla/5.0 (iPhone)\nошибка 4001", "UA: <user-agent>\nошибка 4001"),
    # What follows the user-agent is still seen by the later layers.
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 "
     "Safari/537.36 anna@example.com 79991234567", "<user-agent> <email> <phone>"),
    ("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0 "
     "ip=203.0.113.7 card=4242424242424242", "User-Agent: <user-agent> ip=<ip> card=424242**********"),
])
def test_text_after_a_user_agent_stays(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "user_agent")


@pytest.mark.parametrize("ua", [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
    "Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
    "Safari/537.36 YaBrowser/24.1.0.0 Yowser/2.5",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
    "Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/440.0.0.0.0;]",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Mobile/15E148 [FBAN/FBIOS;FBDV/iPhone14,2;FBMD/iPhone;FBSN/iOS;FBSV/17.0;FBSS/3;FBID/phone;FBLC/ru_RU;FBOP/5]",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Mobile/15E148 Safari/604.1 Telegram-Android/10.5.2 (Samsung SM-S908B; Android 13; SDK 33; HIGH)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Mobile/15E148 Pinterest for iOS/12.4.1 (iPhone14,2; 17.0)",
    # In-app browsers that write the version after a space.
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Mobile/15E148 Instagram 309.0.0.28.110 (iPhone14,2; iOS 17_0; ru_RU; ru-RU; scale=3.00; 1170x2532; 541635890)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Mobile/15E148 Instagram 310.0.0.21.111 (iPhone14,2; iOS 17_0; ru_RU; ru; scale=3.00; 1170x2532; 541635890) NW/3",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Version/4.0 Chrome/120.0.6099.230 Mobile Safari/537.36 Instagram 310.0.0.34.111 Android (33/13; 420dpi; "
    "1080x2400; samsung; SM-S908B; b0q; qcom; ru_RU; 541635890)",
    "Mozilla/5.0 (Linux; Android 12; M2101K6G Build/SKQ1.210908.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Version/4.0 Chrome/119.0.6045.163 Mobile Safari/537.36 trill_310003 JsSdk/1.0 NetType/WIFI "
    "Channel/googleplay AppName/musical_ly app_version/31.0.3 ByteLocale/ru ByteFullLocale/ru Region/RU "
    "AppId/1233 Spark/1.4.6.3-bugfix AppVersion/31.0.3 BytedanceWebview/d8a21c6",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
    "Mobile Safari/537.36 MicroMessenger/8.0.47(0x18002f2c) NetType/WIFI Language/zh_CN",
])
def test_whole_user_agents_are_one_placeholder(scrub, scanner, ua):
    check(scrub, scanner, "UA: " + ua, "UA: <user-agent>", "user_agent")
    check(scrub, scanner, ua + " ошибка 3DS", "<user-agent> ошибка 3DS", "user_agent")


def test_scanner_flags_the_user_agent_span_only(scrub, scanner):
    text = "Mozilla/5.0 (X11; Linux) Chrome/120 Safari/537.36 err=4001"
    assert [(leak.kind, leak.match) for leak in scanner.scan(text)] == [
        ("user_agent", "Mozilla/5.0 (X11; Linux) Chrome/120 Safari/537.36")]
    assert scanner.scan(scrub(text)) == []
    assert scanner.scan("<user-agent> err=4001") == []


def test_user_agent_is_linear(scrub):
    for text in ("Mozilla/5.0 (x)" + " a" * 2040, "Mozilla/5.0 (x)" + " a/1" * 1020, "Mozilla/5.0 (x) " + "(" * 4080,
                 "Mozilla/5.0 (" * 315, "Mozilla/5.0 (x)" + " Instagram 1.1" * 290, "Mozilla/5.0 (x) a/" + "a." * 2039,
                 "Mozilla/5.0 (x) " + "a1-" * 1360 + " 1.1", "Mozilla/5.0 (x)" + "[" * 4080,
                 "Mozilla/5.0 (x)" + " ab" * 1360 + "/", "Mozilla/5.0 (x)" + " a" * 2039 + "/1"):
        assert_fast(lambda: scrub(text), label=text[:40])


# --- clocks are no IPv6 addresses ------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "[12/Mar/2026:10:00:00 +0000] и 10:00:00:123",
    '[12/Mar/2026:10:00:00 +0300] "POST /api/pay"',
    "лог: 12:30:45:123 ошибка 4001",
    "в 10:00:00:123 упал, лог [15/Sep/2026:14:05:11 +0300]",
    "таймаут в 23:59:59:999, повтор в 2026:00:00:05",
])
def test_log_clocks_are_not_ipv6(scrub, scanner, text):
    kept(scrub, scanner, text)


@pytest.mark.parametrize("text,expected", [
    ("2001:0:0:1:0:12:30:45 и 2001:4860:4860:8888 и fe80::1", "<ip> и <ip> и <ip>"),
    ("клиент с 2001:db8:10:20:30:40:50:60", "клиент с <ip>"),
    ("fe80:0:0:0:200:f8ff:fe21:67cf", "<ip>"),
    ("12/Mar/2026:10:00:00 и 2001:0:0:1:0:12:30:45", "12/Mar/2026:10:00:00 и <ip>"),
    ("адрес 2001:4860:4860:8888 и время 10:00:00:123", "адрес <ip> и время 10:00:00:123"),
])
def test_ipv6_addresses_are_still_scrubbed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected, "ipv6")
