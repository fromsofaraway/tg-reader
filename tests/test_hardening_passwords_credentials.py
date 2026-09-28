"""Passwords and credentials: what is one and what only talks about one.

* "user:pass" after a prose keyword ("доступ", "акк", "учётка") is a
  credential only when the second half looks like a password: the same shape
  spells out access levels, scopes and product versions.
* A secret-named config key whose value describes where the secret is kept
  ("выдаётся менеджером", "см. README", "${API_TOKEN}") keeps its value.
* "-p" belongs to a password only when the command that owns it has one to
  give: "docker compose -p Northwind2" and "git log -p HEAD~3" are a project
  and a git ref.
* A long identifier-shaped login before ":password" is removed together with
  the password (the residential-proxy shape).
* Russian phrasings that name a password: labels of up to five words, filler
  words ("пароль был X", "пароль сменил на X") and a bank's "кодовое слово".
* Password policy and instruction prose stays ("пароль 8-64 символа",
  "пароль: придёт отдельным письмом", "{"password": null}").
* A keyword glued to its value into one identifier is a constant, a setting
  or a file name ("ошибка PASSWORD_EXPIRED", "tokens_rotation_plan_v2.docx").
* The text of an XML or SOAP element whose tag names a secret is removed,
  and the markup around it stays.

Every scrubbed case is also flagged by the leak scanner on the raw text and
passes it on the output; every kept case stays byte-identical and the
scanner is silent on it and on our own placeholders.
"""


import pytest

from conftest import assert_fast, check
from tg_collector.config import AnonPolicy
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510")
# Secret-shaped fixtures are built from obviously fake parts, so nothing in
# this file can be mistaken for a live provider key.
STRIPE_TEST_KEY = "sk_" + "test_" + "AbCdEfGh1234567890"
LONG_TOKEN = "AbCdEf" + "1234567890" + "XyZ"
# The residential-proxy login shape: one long identifier, then the password.
PROXY_LOGIN = "customer-acmeltd-cc-RU-city-moscow-sessid-abcdef-sesstime-10"


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS, keep_terms=("Northwind",)),
                    Roster(keep_terms=("Northwind",))).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS), keep_terms=frozenset({"Northwind"})))


# --- "user:pass" after a prose keyword -------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("доступ: ivan:Qwerty123", "доступ: <credentials>"),
    ("доступ: admin:123456", "доступ: <credentials>"),
    ("доступ: ivan_petrov:SecretPass", "доступ: <credentials>"),
    ("доступ: ivan:Secret_Pass", "доступ: <credentials>"),
    ("доступ: db.acme.com:Qwerty123", "доступ: <credentials>"),
    ("доступы: shop_admin:Qwerty123", "доступы: <credentials>"),
    ("учётка: ivan.petrov:Qwerty_123", "учётка: <credentials>"),
    ("акк fb_user_01:Qwerty123", "акк <credentials>"),
    ("акк: buyer01:Qwerty123", "акк: <credentials>"),
    # Sentence punctuation after the pair belongs to the text.
    ("акк: ivan:Qwerty123, пароль сменю", "акк: <credentials>, пароль сменю"),
    # The keywords that always introduce credentials are unaffected.
    ("curl -u admin:S3cretPass", "curl -u <credentials>"),
    ("логин: ivan_petrov:S3cretPass", "логин: <credentials>"),
])
def test_prose_keyword_credentials_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "права доступа: payments:write_all",
    "доступ: scope:payments.write",
    "доступ: scope:payments.write.",
    "доступ: payments:write, остальное по запросу",
    "доступ: role:viewer",
    "доступ: role:viewer;",
    "уровень доступа — role:Admin",
    "доступы: grant_type:client_credentials",
    "доступ: api:v2.1",
    "аккаунт: iOS:17.4",
    "учётка v2:beta1",
    # "доступно" (available) is no login word at all.
    "Доступно — prod:readonly1",
])
def test_permissions_and_versions_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


# --- a secret-named key with a value that describes the secret ---------------------------------

@pytest.mark.parametrize("text", [
    '{"secret_key": "выдаётся менеджером"}',
    "'client_secret' => 'генерируется при создании магазина'",
    '{"access_token": "выдаётся на 3600 секунд"}',
    'export SECRET_KEY="см. README"',
    '"DB_PASSWORD": "не используется"',
    'api_key: "храним в Vault"',
    'secret_key = "{{ secret }}"',
    '{"password": "см. письмо"}',
    "API_TOKEN=${API_TOKEN}",
])
def test_secret_description_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


@pytest.mark.parametrize("text,expected", [
    ('SECRET_KEY="correct horse battery staple"', 'SECRET_KEY="<token>"'),
    ('{"secret_key": "correct horse battery staple"}', '{"secret_key": "<token>"}'),
    ('SECRET_KEY="мой секретный пароль 2026"', 'SECRET_KEY="<token>"'),
    ('SECRET_KEY="ваша мама"', 'SECRET_KEY="<token>"'),
    ('SECRET="хранитель севера"', 'SECRET="<token>"'),
    ('TOKEN="see you later alligator"', 'TOKEN="<token>"'),
    # A word that looks like a secret outweighs the description around it.
    ('"api_key": "ваш ключ AbCd 1234"', '"api_key": "<token>"'),
    ('{"secret_key": "ключ из кабинета: Xy7Pq2Lm"}', '{"secret_key": "<token>"}'),
])
def test_passphrases_still_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- "-p" on a command line ---------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("mysql -u root -p S3cret99", "mysql -u root -p <password>"),
    ("sshpass -p S3cretPass ssh root@host", "sshpass -p <password> ssh root@host"),
    ("docker login -p S3cretPass", "docker login -p <password>"),
    ("docker exec db mysql -uroot -pS3cret99", "docker exec db mysql -uroot -p<password>"),
    ("7z x a.7z -pArchive2026", "7z x a.7z -p<password>"),
    ("docker compose run app ./seed -p S3cret99!", "docker compose run app ./seed -p <password>"),
    ("make deploy && sshpass -p S3cretPass ssh host", "make deploy && sshpass -p <password> ssh host"),
    ("cd app && git pull && ./restore.sh -p S3cret99!", "cd app && git pull && ./restore.sh -p <password>"),
    # A new command after ';' is judged on its own.
    ("git pull; mysql -u root -pS3cret99", "git pull; mysql -u root -p<password>"),
    ("git pull; 7z x a.7z -pArchive2026", "git pull; 7z x a.7z -p<password>"),
    # A project flag and a password on the same line.
    ("docker compose -p Northwind2 exec db mysql -u root -pS3cret99",
     "docker compose -p Northwind2 exec db mysql -u root -p<password>"),
    ("пришлите вывод git log -p HEAD~3, пароль -p Qwerty2026",
     "пришлите вывод git log -p HEAD~3, пароль -p <password>"),
])
def test_cli_password_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "docker compose -p Northwind2 up -d",
    "docker-compose -f a.yml -p Stage2 up -d",
    "запустите docker compose -p Stage2 up",
    "git log -p HEAD~3",
    "git stash show -p stash@{0}",
    "mkdir -p App2/Logs",
    "kubectl logs -p Pod1",
    "helm install -p S3cret99",
    "выполните gh pr list -p Payments2",
    "npm run build -p Prod2026",
    "ansible-playbook site.yml -p Prod2",
    "k6 run -p Stage3 script.js",
])
def test_cli_project_and_ref_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


# --- a long login and the password after it ---------------------------------------------------

def test_long_login_and_password_go_together(scrub, scanner):
    check(scrub, scanner, f"{PROXY_LOGIN}:Pa55w0rd", "<credentials>")
    check(scrub, scanner, f"прокси {PROXY_LOGIN}:Pa55w0rd", "прокси <credentials>")
    check(scrub, scanner, f"прокси {PROXY_LOGIN}:hunter22", "прокси <credentials>")
    assert "Pa55w0rd" not in scrub(f"{PROXY_LOGIN}:Pa55w0rd@pr.example.com:7777")


@pytest.mark.parametrize("text", [
    "/api/v2/merchants/12345/transactions/2026-03-12:get",
    "ERR_PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR:4001",
    "PAYMENT_DECLINED_INSUFFICIENT_FUNDS_ERROR_4001:details",
    "merchant_northwind_payments_2026_03_12:status:ok",
    "correct-horse-battery-staple-2026-northwind",
    "offer-nutra-kz-2026-03-12-landing-v2: не открывается",
])
def test_long_identifiers_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


# --- Russian phrasings that name a password ---------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("пароль для входа в личный кабинет: Qwerty123", "пароль для входа в личный кабинет: <password>"),
    ("пароль от личного кабинета на сайте: Qwerty123", "пароль от личного кабинета на сайте: <password>"),
    ("пароль был Qwerty123", "пароль был <password>"),
    ("пароль теперь Qwerty123", "пароль теперь <password>"),
    ("пароль у него hunter22", "пароль у него <password>"),
    ("пароль сменил на Qwerty123", "пароль сменил на <password>"),
    ("my password is hunter2", "my password is <password>"),
    ("my password is Hunter2024", "my password is <password>"),
    ("кодовое слово: тюльпан", "кодовое слово: <password>"),
    ("контрольное слово Parol2024", "контрольное слово <password>"),
])
def test_password_phrasings_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "пароль был изменён",
    "пароль теперь обязателен",
    "пароль сменил на новый",
    "password is required",
    "кодовое слово не подходит",
    "кодовое слово не совпадает",
    "пароль для входа в приложение не приходит: ошибка 4001",
    "пароль при регистрации в приложении требует: минимум 8 символов",
    # Five words of prose can end on a colon of their own.
    "пароль от кабинета не работает в логах: AUTH_FAILED_4012",
])
def test_password_prose_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


# --- password policy and instruction prose ----------------------------------------------------

@pytest.mark.parametrize("text", [
    "пароль 8-64 символа",
    "пароль: 10-12 символов",
    "пароль (8-64 символа)",
    "пароль: минимум 8 символов",
    '{"password_policy": "min 8 chars"}',
    "пароль: придёт отдельным письмом",
    "пароль: генерируется автоматически",
    "пароль: только латиница",
    "пароль: латиница и цифры",
    "пароль: скрыт",
    '{"password": null}',
    "password: False",
    # The number belongs to the order the label names.
    "пароль к заказу 90829441 не нужен",
])
def test_password_policy_prose_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


@pytest.mark.parametrize("text,expected", [
    ("пароль: Qwerty123", "пароль: <password>"),
    ("пароль: 12345678 символов", "пароль: <password> символов"),
    ("пароль: Qwerty123 символов нет", "пароль: <password> символов нет"),
    ("пароль: 8symbols", "пароль: <password>"),
    ("пароль: Придёт1", "пароль: <password>"),
    ("пароль: придёт", "пароль: <password>"),
    ("пароль: скрыт123", "пароль: <password>"),
    ("пароль: Хранитель севера", "пароль: <password> севера"),
    ("пароль к заказу 90829441", "пароль к заказу <password>"),
    ("пароль к заказу: 90829441", "пароль к заказу: <password>"),
])
def test_values_after_a_password_label_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- a keyword glued to its value into one identifier -----------------------------------------

@pytest.mark.parametrize("text", [
    "ошибка PASSWORD_EXPIRED",
    "PASSWORD_RESET_REQUIRED",
    "PASSWORD_MIN_LENGTH=8",
    "password_min_length: 8",
    "passwordMinLength: 8",
    "сброс пароля password_reset_flow_v2 не работает",
    "TOKEN_INVALID_SIGNATURE_2026",
    "tokens_rotation_plan_v2.docx",
    "tokenization_v2_rollout_plan",
])
def test_constants_and_file_names_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


@pytest.mark.parametrize("text,expected", [
    ("PASSWORD_PROD=Qwerty123", "PASSWORD_PROD=<password>"),
    ("PASSWORD_QWERTY123", "PASSWORD<password>"),
    ("PASSWORD_Qwerty123", "PASSWORD<password>"),
    ("password1234", "password<password>"),
    ("passwordQwerty123", "password<password>"),
    ("password_hunter22", "password<password>"),
    ("password_qwerty123", "password<password>"),
    ("password_s3cr3t_2024", "password<password>"),
    ("passwords: Qwerty123", "passwords: <password>"),
    ('{"passwordConfirmation": "Qwerty123"}', '{"passwordConfirmation": "<password>"}'),
    ("token_abc123def456ghi789", "token<token>"),
    ("token_abcdef1234567890abcd", "token<token>"),
    ("TOKEN_PROD=abc123def456ghi789", "TOKEN<token>"),
    ("token_secret_2026=" + LONG_TOKEN, "token<token>"),
])
def test_glued_secrets_still_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_a_link_after_a_constant_stays_a_link(scrub, scanner):
    check(scrub, scanner, "PASSWORD_RESET_URL=https://acme.example.com/reset",
          "PASSWORD_RESET_URL=<url>")


# --- XML and SOAP elements -------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("<Password>Qwerty123</Password>", "<Password><password></Password>"),
    ("<password>Qwerty123</password>", "<password><password></password>"),
    ("<ns:Password>Qwerty123</ns:Password>", "<ns:Password><password></ns:Password>"),
    ("<db_password>Qwerty123</db_password>", "<db_password><password></db_password>"),
    ("<CVV2>123</CVV2>", "<CVV2><cvv></CVV2>"),
    ("<PIN>1234</PIN>", "<PIN><pin></PIN>"),
    ("<ApiKey>" + STRIPE_TEST_KEY + "</ApiKey>", "<ApiKey><token></ApiKey>"),
    ("<Token>" + LONG_TOKEN + "</Token>", "<Token><token></Token>"),
    ("<Secret>abc123XYZ</Secret>", "<Secret><token></Secret>"),
    ("<Login>ivan88</Login>", "<Login>@user</Login>"),
    ("<userName>ivan88</userName>", "<userName>@user</userName>"),
])
def test_element_values_removed(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_element_markup_stays(scrub, scanner):
    check(scrub, scanner,
          '<wsse:Password Type="PasswordText">Qwerty123</wsse:Password>',
          '<wsse:Password Type="<password>"><password></wsse:Password>')
    check(scrub, scanner,
          "<auth>\n  <login>merchant_42</login>\n  <password>S3cret!2024</password>\n</auth>",
          "<auth>\n  <login>@user</login>\n  <password><password></password>\n</auth>")
    check(scrub, scanner,
          "<soap:Envelope><soap:Body><Login>merchant_42</Login>"
          "<Password>S3cret!</Password></soap:Body></soap:Envelope>",
          "<soap:Envelope><soap:Body><Login>@user</Login>"
          "<Password><password></Password></soap:Body></soap:Envelope>")


@pytest.mark.parametrize("text", [
    "<TokenType>Bearer</TokenType>",
    "<PinRequired>true</PinRequired>",
    "<OtpLength>6</OtpLength>",
    "<ExpirePassword>true</ExpirePassword>",
    "<Shipping>free</Shipping>",
    "<ApiKey>${API_KEY}</ApiKey>",
    "<LoginUrl>/account/login</LoginUrl>",
    "<Secrets>3</Secrets>",
    # A tag that only starts with the word keeps its text, closing tag included.
    "<passwordHash>abc123</passwordHash>",
    "<TokenValue>Bearer</TokenValue>",
    # An element that talks about a password keeps its words and its markup.
    "<Description>Password is invalid</Description>",
    # Our own output is never a value.
    "<Password><password></Password>",
    "<Login>@user</Login>",
])
def test_element_settings_kept(scrub, scanner, text):
    assert scrub(text) == text
    assert scanner.scan(text) == []


def test_scanner_reads_elements_and_ignores_placeholders(scanner):
    assert [leak.kind for leak in scanner.scan("<password>Qwerty123</password>")] == ["password"]
    assert scanner.scan("<Password><password></Password>") == []
    assert scanner.scan("<password>") == []


# --- cost on hostile text ---------------------------------------------------------------------

# A message Telegram can carry, and a budget generous against the measured
# cost (tens of milliseconds) but tight against a quadratic rule (seconds).
MESSAGE_LEN = 4096
BUDGET = 0.2


@pytest.mark.parametrize("text", [
    ("git " * 10 + "-pAa1B " * 600)[:MESSAGE_LEN],
    ("docker compose " + "-pAa1B " * 600)[:MESSAGE_LEN],
    ("доступ: " + "ivan:Qwerty123, " * 300)[:MESSAGE_LEN],
    ("пароль " + "слово " * 600 + ": Qwerty123")[:MESSAGE_LEN],
    ("пароль: придёт " * 250)[:MESSAGE_LEN],
    ('SECRET_KEY="' + "см. " * 900 + '"')[:MESSAGE_LEN],
    ("password_" + "min_" * 800)[:MESSAGE_LEN],
    ("<Password>" * 400)[:MESSAGE_LEN],
    ("<Password>" + "a" * MESSAGE_LEN),
    ("<Password " + "x=1 " * 900 + ">v</Password>")[:MESSAGE_LEN],
    (PROXY_LOGIN + ":Pa55w0rd ") * 60,
])
def test_rules_stay_linear(scrub, scanner, text):
    assert_fast(lambda: (scrub(text), scanner.scan(text)), budget=BUDGET, label=text[:40])
