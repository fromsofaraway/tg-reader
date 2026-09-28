"""Long identifiers against the generic secret rules.

The base64 rule and the keyword-gated API-key rule must not take every long
run of letters, digits, '_', '-' and '/' as a token. Error constants, REST
paths, file names and campaign slugs are product knowledge and stay
(``rules.reads_as_identifier``), while random tokens, identifiers that hide a
phone, card, account or document number, grouped licence keys and
identifier-shaped logins in a credential context are still removed. Every
removed case is flagged by the leak scanner on the raw text and passes it on
the output; every kept case stays byte-identical and the scanner is silent
on it.
"""

import random
import string

import pytest

from conftest import assert_fast, check
from tg_collector.config import AnonPolicy
from tg_collector.rules import reads_as_identifier
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS)))


# --- product knowledge stays -----------------------------------------------------------------

@pytest.mark.parametrize("text", [
    # error and decline constants
    "PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001",
    "ERR_CARD_LIMIT_EXCEEDED_DAILY_TRANSACTION_COUNT_01",
    "ошибка PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001 при оплате",
    "ошибка PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001: недостаточно средств",
    "ошибка ERR_CARD_LIMIT_EXCEEDED_DAILY_TRANSACTION_COUNT_01 при оплате",
    "Код ошибки: ERR_CARD_LIMIT_EXCEEDED_DAILY_TRANSACTION_COUNT_01, что это?",
    "Банк вернул CARD_EXPIRED_OR_BLOCKED_BY_ISSUER_BANK_51",
    "ERROR_CODE=CARD_EXPIRED_OR_INVALID_EXPIRATION_DATE_54",
    "ошибка err_3ds_authentication_failed_by_issuer_bank_05",
    "ErrorCode: Card_Declined_By_Issuer_Insufficient_Funds_51",
    "ошибка прокси ERR_TUNNEL_CONNECTION_FAILED_UPSTREAM_TIMEOUT_502",
    "в логе PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001:retry",
    # REST paths, also right after a token keyword
    "/api/v2/merchants/12345/transactions/2026-03-12",
    "GET /api/v2/merchants/12345/transactions/2026-03-12/items returned 500",
    "Запрос на POST /api/v2/merchants/12345/transactions/refund возвращает 500",
    "вебхук на /webhooks/northwind/payment-status-callback/v2 не приходит",
    "token /api/v2/auth/refresh.json",
    "токен: /api/v2/auth/refresh.json",
    "access token /oauth/v2/token/refresh.json",
    "refresh token /api/v2/merchants/12345/transactions/2026-03-12",
    "эндпоинт /api/v2/oauth/token/refresh/2026-03-12 отдаёт 401",
    # file names and slugs, also with a date and a time
    "report_2026_03_12_final_version_v2_export.xlsx",
    "Выгрузил отчёт report_2026_03_12_final_version_v2_export.xlsx",
    "invoice_2026_03_12_acme_ltd_northwind_final.pdf",
    "docs/integration/merchant-onboarding-checklist-v3-2026.pdf",
    "Выгрузка payout_report_northwind_2026-03-12_14-30-00.csv",
    "бэкап backup_northwind_payments_db_20260312_153000_final.sql",
    "offer-nutra-kz-2026-03-12-landing-v2-final",
    "merchant-onboarding-PaymentV2-checklist-2026-final-draft",
    "getPaymentDeclinedInsufficientFundsErrorCode4001",
    # field names, also after the words that name a key or a login context
    "идентификатор recurring_payment_schedule_v2_monthly_billing не найден",
    "ключ payment_status_code_01_for_recurring_northwind_billing",
    "ключ p2p_transfer_limit_exceeded_for_northwind_2026_03",
    "поле sha256_signature_mismatch_for_callback_payload_v2 пустое",
    '{"recurring_payment_schedule_v2_monthly_billing": true}',
    "recurring_payment_schedule_v2_monthly_billing: true",
    # login and password words in the forms that do not name a value
    "после логина redirect_to_dashboard_v2_northwind_2026_03_12 не срабатывает",
    "при логине oauth_callback_state_mismatch_v2_northwind_2026 падает",
    "после смены пароля redirect_to_dashboard_v2_northwind_2026_03_12 пустой",
    "ошибка при логине ERR_AUTH_FAILED_INVALID_CREDENTIALS_2026_V2",
    # our own placeholders are not credential words
    "ошибка <token> при оплате",
])
def test_identifiers_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


# --- secrets are still removed ---------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    # random tokens, also with separators and '/' inside
    ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "<token>"),
    ("dGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIHRlc3Rpbmc=", "<token>"),
    ("Xk3-9fQ_a2Lm8ZpR-4wT7yBn_0cVdE6hJ1kLoP9qRsTuVwX", "<token>"),
    ("a8f3k2m9x1c4v7b2n5q8w1e4r7t0y3u6i9o2p5s8d1f4g7h0", "<token>"),
    ("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "<token>"),
    ("AbCd1234-EfGh5678-IjKl9012-MnOp3456-QrSt7890-UvWx", "<token>"),
    ("gAAAAABmZ1x_abcDEF123ghiJKL456mnoPQR789stuVWX012yzA=", "<token>"),
    ("1//0gAbCdEfGhIjKlMnOpQrStUvWxYz0123456789-AbCdEfGh_IjKlMn", "<token>"),
    ("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf", "<token>"),
    ("abcd1234efgh5678ijkl9012mnop3456qrst7890", "<token>"),
    ("/reset/Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFi/confirm/2026", "<token>"),
    ("a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6-7890abcd", "<token>"),
    ("thisismyverylongpassphrasefortesting2026", "<token>"),
    ("ключ: Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=", "ключ: <token>"),
    ("token: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "token: <token>"),
    ("token: my_super_secret_2026", "token: <token>"),
    ("session_id: abcdefghijklmnop_1234567890_qrstuvwxyzabcdefgh", "session_id: <token>"),
    # grouped licence keys
    ("license key: ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-ZABCD-12345", "license key: <token>"),
    ("ключ активации ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-ZABCD-12345", "ключ активации <token>"),
    # an identifier that hides a phone, card, account or document number
    ("dogovor_ooo_romashka_inn_7700000425_2026_03_12.pdf", "<token>.pdf"),
    ("client_79161234567_northwind_payment_report_2026.xlsx", "<token>.xlsx"),
    ("statement_40817810099910004312_acme_ltd_2026_03.pdf", "<token>.pdf"),
    ("выписка statement_40817810099910004312_2026_03_12.pdf", "выписка <token>.pdf"),
    ("passport_4510_123456_ivanov_ivan_1985_scan_final.jpg", "<token>.jpg"),
    ("паспорт passport_4510_123456_scan_2026_03_12_front_side.jpg", "паспорт <token>.jpg"),
    ("tg_user_5566778899_oleg_severov_2026_03_12_export", "<token>"),
    ("offer-79161234567-landing-v2-final-2026-03-12", "<token>"),
    ("callback_user_79161234567_request_2026_03_12", "<token>"),
    ("перезвонить callback-request-8-916-123-45-67-ivan-2026-03-12", "перезвонить <token>"),
    # the card layer runs before the secret rules and masks the number it
    # finds, whatever the file name glues it to
    ("refund_4242424242424242_request_2026_03_12_final", "refund_424242**********_request_2026_03_12_final"),
    ("snils_112-233-445-95_scan_front_side_2026_03_12_final", "<token>"),
    ("ORDER_REF_TXN20260312_NORTHWIND_ACME_FINAL_COPY", "<token>"),
    ("export_2026-03-12-79161234567_northwind_payments.csv", "<token>.csv"),
    ("выгрузка report_2026-03-12-1234567890_northwind_payout.csv", "выгрузка <token>.csv"),
    # a number that fills a whole path segment goes to the number rules
    ("/api/v2/users/79161234567/transactions/2026-03-12", "/api/v2/users/<phone>/transactions/2026-03-12"),
    ("/api/v2/inn/7700000425/status/check-2026-03-12", "/api/v2/inn/<inn>/status/check-2026-03-12"),
    ("/api/v2/accounts/40817810099910004312/statement", "/api/v2/accounts/<account>/statement"),
    # after a token keyword a long number anywhere keeps the whole value a secret
    ("token /api/v2/users/79161234567/transactions/export", "token /<token>"),
    ("токен /api/v2/users/123456789/sessions/current.json", "токен /<token>"),
    # a value with a single slash is a path only when the keyword is a path segment
    ("token: alPcoc/jdqcta414", "token: <token>"),
    ("токен доступа: Mg/pj8dD/hxQ0stp", "токен доступа: <token>"),
    # an identifier that names a secret
    ("prod_secret_2024_merchant_northwind_backup_01", "<token>"),
    ("secret: super_secret_admin_password_2026_northwind_prod", "secret: <token>"),
    ("мой ключ super_secret_admin_password_2026_northwind_prod", "мой ключ <token>"),
    # identifier-shaped logins: after a login, proxy or password word, or before ':password'
    ("прокси customer-acmeltd-cc-RU-city-moscow-sessid-abc12345-sesstime-10:Pa55w0rd@pr.example.io:7777",
     "прокси <token>:<credentials>"),
    ("прокси customer-acmeltd-cc-RU-city-moscow-sessid-abcdef-sesstime-10:Pa55w0rd@pr.example.io:7777",
     "прокси <token>:<credentials>"),
    ("customer-acmeltd-cc-RU-city-moscow-sessid-abcdef-sesstime-10:Pa55w0rd@pr.example.io:7777",
     "<token>:<credentials>"),
    ("логин customer-acmeltd-cc-RU-city-moscow-sessid-abc12345-sesstime-10 пароль Pa55w0rd",
     "логин <token> пароль <password>"),
    ("логин customer-acmeltd-cc-RU-city-moscow-sessid-abcdef-sesstime-10 пароль Pa55w0rd",
     "логин <token> пароль <password>"),
    ("Логином customer-acmeltd-cc-ru-city-moscow-sessid-abcdef-sesstime-10 не зайти",
     "Логином <token> не зайти"),
    ("юзер: customer-acmeltd-cc-ru-city-moscow-sessid-abcdef-sesstime-10",
     "юзер: <token>"),
    ("зайти под юзером customer-acmeltd-cc-ru-city-moscow-sessid-abcdef-sesstime-10",
     "зайти под юзером <token>"),
    ("с паролем northwind_admin_backup_2026_03_12_prod_eu_west_v2",
     "с паролем <password>"),
    ("прокси customer-acmeltd-cc-ru-city-moscow-sessid-abcdef-sesstime-10 не отвечает",
     "прокси <token> не отвечает"),
    ("curl -U customer-acmeltd-cc-RU-city-moscow-sessid-abc12345-sesstime-10:x https://ip.example.com",
     "curl -U <token>:x <url>"),
    ("curl -u customer-acmeltd-cc-ru-city-moscow-sessid-abcdef-sesstime-10 https://ip.example.com",
     "curl -u <token> <url>"),
])
def test_secrets_still_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_placeholder_before_an_identifier_is_not_a_credential_word(scrub, scanner):
    # "<2fa-secret>" and "@user" end in credential words; the scanner reads
    # the output the way the scrubber read the input and stays silent.
    check(scrub, scanner, "secret JBSWY3DPEHPK3PXP recurring_payment_schedule_v2_monthly_billing",
          "secret <2fa-secret> recurring_payment_schedule_v2_monthly_billing")
    check(scrub, scanner, "@ivan_petrov_1 recurring_payment_schedule_v2_monthly_billing",
          "@user recurring_payment_schedule_v2_monthly_billing")
    assert not scanner.scan("<user> customer-acmeltd-cc-ru-city-moscow-sessid-abcdef-sesstime-10")


def test_identifier_inside_a_kept_link_query():
    scrub = Scrubber(AnonPolicy(url_mode="keep"), Roster()).scrub
    text = "https://example.com/export?file=report_2026_03_12_final_version_v2_export.xlsx"
    assert scrub(text) == text
    token = "https://example.com/export?file=Xk3-9fQ_a2Lm8ZpR-4wT7yBn_0cVdE6hJ1kLoP9qRsTuVwX"
    assert scrub(token) == "https://example.com/export?file=<token>"


# --- roster vocabulary still sees names inside kept identifiers -------------------------------

def test_known_names_inside_kept_identifiers_are_removed():
    people, orgs = ("Олег Северов", "Северов"), ("Acme",)
    scrub = Scrubber(AnonPolicy(), Roster(person_terms=people, org_terms=orgs)).scrub
    scanner = LeakScanner(Known(names=frozenset(people), titles=frozenset(orgs)))
    for text, expected in [
        ("passport_scan_oleg_severov_2026_03_12_front_side.jpg", "passport_scan_oleg_<name>_2026_03_12_front_side.jpg"),
        ("invoice_2026_03_12_acme_ltd_northwind_final.pdf", "invoice_2026_03_12_<org>_ltd_northwind_final.pdf"),
    ]:
        out = scrub(text)
        assert out == expected, out
        assert scanner.scan(text) and not scanner.scan(out)


def test_known_ids_and_labelled_numbers_inside_kept_paths():
    scrub = Scrubber(AnonPolicy(), Roster(known_ids=(123456789,))).scrub
    scanner = LeakScanner(Known(user_ids=frozenset({123456789})))
    for text, expected in [
        ("файл payment/callback/2026-03-12/client/123456789.pdf", "файл payment/callback/2026-03-12/client/<id>.pdf"),
        ("скрин 123456789.png", "скрин <id>.png"),
        ("/api/v2/tg/123456789/export-2026-03-12", "/api/v2/tg/<id>/export-2026-03-12"),
        ("/api/v2/passport/4510123456/scan-2026-03-12", "/api/v2/passport/<passport>/scan-2026-03-12"),
        ("/api/v2/snils/11223344595/check-2026-03-12-v2", "/api/v2/snils/<snils>/check-2026-03-12-v2"),
        # a decimal fraction or a longer number is not the id
        ("курс 123456789.5 и сумма 1234567890", "курс 123456789.5 и сумма 1234567890"),
    ]:
        out = scrub(text)
        assert out == expected, (text, out)
        assert not scanner.scan(out), out
        if out != text:
            assert scanner.scan(text), text


# --- the shared helper -------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001", True),
    ("/api/v2/merchants/12345/transactions/2026-03-12", True),
    ("/api/v2/users/79161234567/transactions", True),
    ("err_3ds_2FA_p2p_B2B_sha256_x86_64_v2_Card_By", True),
    ("payout_2026-03-12_14-30-00_20260312_153000", True),
    ("api/v2/sdk/1.2.3/release.json", True),
    ("merchant_12345_payouts", False),
    ("TXN20260312_report", False),
    ("callback-8-916-123-45-67", False),
    ("2026-03-12-1234567890", False),
    ("202603121530_report", False),
    ("ABCDE-FGHIJ-KLMNO-PQRST", False),
    ("wJalrXUtnFEMI/K7MDENG", False),
    ("abc+def", False),
    ("Zm9vYmFy=", False),
])
def test_reads_as_identifier(value, expected):
    assert reads_as_identifier(value) is expected


def test_reads_as_identifier_path_numbers():
    assert reads_as_identifier("api/v2/users/79161234567/export")
    assert not reads_as_identifier("api/v2/users/79161234567/export", path_numbers_visible=False)
    assert reads_as_identifier("api/v2/merchants/12345/export", path_numbers_visible=False)
    assert reads_as_identifier("api/v2/reports/20260312/summary", path_numbers_visible=False)


@pytest.mark.parametrize("alphabet", [
    string.ascii_letters + string.digits + "+/",
    string.ascii_letters + string.digits + "-_",
    string.ascii_lowercase + string.digits,
    string.ascii_uppercase + "234567",
    string.ascii_letters + string.digits,
])
def test_random_tokens_are_never_identifiers(alphabet):
    rng = random.Random(20260312)
    for _ in range(3000):
        token = "".join(rng.choice(alphabet) for _ in range(rng.randint(40, 64)))
        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            assert not reads_as_identifier(token), token


def test_random_tokens_are_scrubbed(scrub, scanner):
    rng = random.Random(7)
    alphabet = string.ascii_letters + string.digits + "-_"
    for _ in range(300):
        token = rng.choice(string.ascii_letters) + "".join(rng.choice(alphabet) for _ in range(rng.randint(40, 63)))
        if not any(c.isdigit() for c in token) or token[-1] in "-_":
            continue
        # Other rules (wallets) may take a part first; the token never survives whole.
        out = scrub(f"ключ {token}")
        assert token not in out and out.startswith("ключ "), (token, out)
        assert scanner.scan(f"ключ {token}")
        assert not scanner.scan(out), (token, out)


# --- linear time -------------------------------------------------------------------------------

@pytest.mark.parametrize("run", [
    "a_" * 2048, "A1" * 2048, "aB" * 2048, "1_" * 2048, "Aa1" * 1366, "2026-03-12-" * 373,
    "getPayment" * 410, "V1234" * 820, "a" * 4096, "Ab" * 2047 + "=", "p2p_" * 1024, "12345-" * 683,
    "логин " + "a-" * 2045, "x" * 4000 + ":y",
])
def test_hostile_runs_are_fast(scrub, run):
    assert_fast(lambda: scrub(run), label=run[:40])
