"""Extended rules for financial and identity data pasted into support chats."""

import pytest

from conftest import STRIPE_LIVE_SHORT
from tg_collector.config import AnonPolicy
from tg_collector.fintech import kz_id_ok, ua_rnokpp_ok
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510", "520082", "601111", "353011")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub


# --- card companions -------------------------------------------------------------------

def test_card_with_expiry_and_cvv_dump(scrub):
    assert scrub("реквизиты: 4242 4212 3456 7891 12/27 123") == "реквизиты: 424242********** <exp> <cvv>"
    assert scrub("4242421234567891|03/2026|4567") == "424242**********|<exp>|<cvv>"
    assert scrub("cvv 123 вводил правильно, всё равно отказ") == "cvv <cvv> вводил правильно, всё равно отказ"
    assert scrub("код с обратной стороны 789, срок 03/26") == "код с обратной стороны <cvv>, срок <exp>"
    assert scrub("exp 12/2027 не принимает, пишет invalid expiration") == "exp <exp> не принимает, пишет invalid expiration"
    assert scrub("cvv mismatch, decline 05") == "cvv mismatch, decline 05"


def test_cardholder_and_kyc_names(scrub):
    assert scrub("имя на карте IVAN PETROV, а в фб Ivan") == "имя на карте <cardholder>, а в фб Ivan"
    assert scrub("cardholder: John Doe — можно поменять?") == "cardholder: <cardholder> — можно поменять?"
    assert scrub("держатель карты не отвечает") == "держатель карты не отвечает"
    assert scrub("на имя Петров Тимур") == "на имя <cardholder>"


def test_otp_pin_and_error_codes(scrub):
    assert scrub("пришёл код из смс 482913, ввёл — decline") == "пришёл код из смс <otp>, ввёл — decline"
    assert scrub("Your verification code is 123456 for payment 25.00 USD") == \
        "Your verification code is <otp> for payment 25.00 USD"
    assert scrub("PIN 1234 к виртуалке нужен?") == "PIN <pin> к виртуалке нужен?"
    # Codes that describe an outcome are product vocabulary and must stay.
    for text in ["код ошибки 4001", "error code 50051", "reason code 4837", "decline code 05", "response code 91"]:
        assert scrub(text) == text
    assert scrub("промокод 12345") == "промокод 12345"


# --- credentials and secrets ------------------------------------------------------------------

def test_credential_dumps_passwords_and_keys(scrub):
    assert scrub("лог: buyer.example@gmail.com:Passw0rd!:JBSWY3DPEHPK3PXP:backup.example@mail.ru") == "лог: <credentials>"
    assert scrub("акк fb_user_01:Qwerty123:JBSWY3DPEHPK3PXP") == "акк <credentials>"
    assert scrub("пароль от акка qwerty123, 2fa ключ JBSWY3DPEHPK3PXPJBSWY3DP") == \
        "пароль от акка <password>, 2fa ключ <2fa-secret>"
    assert scrub("password: hunter2") == "password: <password>"
    assert scrub("пароль неверный, сбросьте") == "пароль неверный, сбросьте"
    assert scrub(f"api_key={STRIPE_LIVE_SHORT}, token: abcd1234efgh5678") == "api_key=<token>, token: <token>"
    assert scrub("token expired") == "token expired"


def test_cookies_proxies_and_user_agents(scrub):
    assert scrub("cookies: c_user=100012345678901; xs=12%3AabcDEF; datr=xyz1") == \
        "cookies: c_user=<cookie>; xs=<cookie>; datr=<cookie>"
    assert scrub("EAAGm0PX4ZCpsBAOZCZBZAZC1234567890abcdef") == "<token>"
    assert scrub("прокси 203.0.113.56:8000:user123:pa$$word и socks5://u:p@1.2.3.4:1080") == "прокси <proxy> и <proxy>"
    assert scrub("proxy.example.com:8080:login:secret") == "<proxy>"
    assert scrub("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36") == "<user-agent>"
    assert scrub("время 12:34:56, счёт 1500:3") == "время 12:34:56, счёт 1500:3"


# --- crypto ----------------------------------------------------------------------------------------

def test_wallets_hashes_and_explorer_links(scrub):
    assert scrub("кошелёк TXk3v8Qp1zE9dLmN7yHcR4tW2sBfG6aJhK") == "кошелёк <wallet>"
    assert scrub("erc20 0x52908400098527886E0F7030069857D2E4169EE7") == "erc20 <wallet>"
    assert scrub("btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq и 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == "btc <wallet> и <wallet>"
    assert scrub("ton UQBFz01R2RlhMWLe1yMaz2DiT8JcDtBCwCbNRO4oLl2NBgYr") == "ton <wallet>"
    assert scrub("хэш 3f1a9c8e7b6d5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f") == "хэш <txid>"
    assert scrub("tx 0x3f1a9c8e7b6d5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f") == "tx <txid>"
    assert scrub("https://tronscan.org/#/transaction/3f1a9c8e7b6d5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f") == "<url>"
    kept = Scrubber(AnonPolicy(allow_domains=("tronscan.org",)), Roster()).scrub(
        "https://tronscan.org/#/address/TXk3v8Qp1zE9dLmN7yHcR4tW2sBfG6aJhK")
    assert kept == "https://tronscan.org/#/address/<wallet>"
    assert scrub("memo 1234567 и binance uid 98765432") == "memo <id> и binance uid <id>"
    assert scrub("пополнил на 500 usdt, комиссия 1 usdt") == "пополнил на 500 usdt, комиссия 1 usdt"


# --- identity documents --------------------------------------------------------------------------------

def test_checksums():
    assert kz_id_ok("900101300123") is False
    assert kz_id_ok("020531600149") is True  # checksum-valid synthetic IIN
    assert ua_rnokpp_ok("3012340476") is True
    assert ua_rnokpp_ok("3012340477") is False


def test_cis_documents_and_dates(scrub):
    assert scrub("ИИН 020531600149 клиента") == "ИИН <iin> клиента"             # checksum: specific label
    assert scrub("ИИН 900101300123 клиента") == "ИИН <tax-id> клиента"          # typo: keyword still catches it
    assert scrub("вот 020531600149") == "вот <iin>"
    assert scrub("ИПН 3012340476 и просто 3012340476") == "ИПН <rnokpp> и просто <rnokpp>"
    assert scrub("паспорт N12345678, серия 45 09 123456") == "паспорт <passport>, серия <passport>"
    assert scrub("ДР 01.01.1990, born 1990-05-12") == "ДР <dob>, born <dob>"
    assert scrub("в/у 77 АВ 123456") == "в/у <driver-licence>"
    assert scrub("прописка: г. Алматы, ул. Абая 10, кв. 5") == "прописка: <address>"
    assert scrub("живу на ул. Ленина, д. 5, кв. 12, приходите") == "живу на <address>, приходите"
    assert scrub("ship to 1600 Pennsylvania Ave NW, Washington") == "ship to <address>, Washington"
    # KB vocabulary with digits that must survive.
    for text in ["выписка за 01.01.2026", "версия 2.15.3", "оплата 1500 USD 12.03.2026", "лимит 10 000 000 тенге"]:
        assert scrub(text) == text


# --- ad platforms and payment references -----------------------------------------------------------

def test_ad_ids_and_transaction_refs(scrub):
    assert scrub("act_1234567890123456 бм 1029384756123456 пиксель 987654321098765") == \
        "act_<id> бм <ad-account> пиксель <ad-account>"
    assert scrub("google ads 123-456-7890") == "google ads <ad-account>"
    assert scrub("rrn 123456789012, auth code A1B2C3, ARN 74123456789012345678901") == \
        "rrn <txn-ref>, auth code <txn-ref>, ARN <txn-ref>"
    assert scrub("спенд 1500$ на офере Nutra в GEO Казахстан, биллинг 250€") == \
        "спенд 1500$ на офере Nutra в GEO Казахстан, биллинг 250€"
    assert scrub("оплата в Facebook Ads, decline code 05 do not honor, мерчант FACEBK *ADS") == \
        "оплата в Facebook Ads, decline code 05 do not honor, мерчант FACEBK *ADS"


def test_bare_domains_respect_allow_list():
    s = Scrubber(AnonPolicy(allow_domains=("docs.acme.com",)), Roster())
    assert s.scrub("лендинг offer-nutra.site и docs.acme.com, версия 1.2.3") == "лендинг <domain> и docs.acme.com, версия 1.2.3"
    off = Scrubber(AnonPolicy(scrub_domains=False), Roster())
    assert off.scrub("лендинг offer-nutra.site") == "лендинг offer-nutra.site"


def test_scanner_agrees_with_domain_rules(scrub):
    scanner = LeakScanner(Known(card_bins=frozenset(BINS)))
    samples = [
        "cvv 123, код из смс 482913, пароль: hunter2, кошелёк TXk3v8Qp1zE9dLmN7yHcR4tW2sBfG6aJhK",
        "c_user=100012345678901; act_1234567890123456; ИИН 020531600149; 203.0.113.56:8000:u:p",
    ]
    for text in samples:
        assert scanner.scan(text), text
        assert not scanner.scan(scrub(text)), scrub(text)


def test_hardening_from_adversarial_review(scrub):
    from tg_collector.model import Entity
    from tg_collector.cards import find_cards
    # A neighbour that happens to pass Luhn with the card's first groups: the tail never stays visible.
    out = scrub("5105 1005 0631 3114 1930 ок")
    assert out.startswith("510510*") and not any(c.isdigit() for c in out.split("510510")[1].replace("ок", ""))
    # Hand masks with underscores and hollow circles; our own output is never re-flagged.
    assert scrub("карта 4242 42__ ____ 1234 и 4242 42○○ ○○○○ 1234") == "карта 424242********** и 424242**********"
    assert not find_cards("424242**********", ("424242",))
    # Lists of BINs, ids and order numbers are not phones; phones never merge across lines.
    assert scrub("наши БИНы: 424242 400000 510510") == "наши БИНы: 424242 400000 510510"
    assert scrub("сумма 1500.00\n8 999 123 45 67") == "сумма 1500.00\n<phone>"
    # Private-use characters in the input do not shift entity offsets.
    text = "\ue000\ue001 hi @alice"
    ent = Entity("Mention", 6, 6)
    assert Scrubber(AnonPolicy(), Roster(by_username={"alice": "U0044"})).scrub(text, [ent]) == "   hi @U0044"
    # Device identifiers by keyword. An IMEI passes Luhn by design, so the card
    # layer (which runs first) may mask it as a card: either way it is gone.
    assert scrub("IMEI 490154203237518 устройства") in ("IMEI <device-id> устройства", "IMEI 490154********* устройства")
    assert scrub("iccid 8970101234567890123X") == "iccid <device-id>"
