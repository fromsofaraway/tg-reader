"""Secrets in the shapes developers paste into support chats: Russian and
colloquial labels, quoted values, command lines and HTTP headers, dotted
API keys and PEM private keys. Every scrubbed case is also flagged by the
leak scanner on the raw text and passes it on the output; every kept case
stays byte-identical and the scanner is silent on it."""

import pytest

from conftest import PEM_BODY, SENDGRID, STRIPE_LIVE, assert_fast, check, pem_begin, pem_end
from tg_collector.config import AnonPolicy
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber

BINS = ("424242", "400000", "510510")
BEGIN, END = pem_begin(), pem_end()


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS, keep_terms=("Northwind",)),
                    Roster(person_terms=("Петров",), keep_terms=("Northwind",))).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS), keep_terms=frozenset({"Northwind"})))


# --- labels: Russian, abbreviated, misspelt --------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("токен доступа: AbCdEfGh1234567890", "токен доступа: <token>"),
    ("Токен доступа = AbCdEfGh1234567890", "Токен доступа = <token>"),
    ("токен доступа AbCdEfGh1234567890", "токен доступа <token>"),
    ("Токен доступа:\nAbCdEfGh1234567890", "Токен доступа:\n<token>"),
    ("токен_доступа AbCdEfGh1234567890", "токен_доступа <token>"),
    ("ваш токен доступа 0123456789abcdef0123456789abcdef я отозвал", "ваш токен доступа <token> я отозвал"),
    ("апи ключ: AbCdEfGh1234567890", "апи ключ: <token>"),
    ("апи-ключ AbCdEfGh1234567890", "апи-ключ <token>"),
    ("секретный ключ: AbCdEfGh1234567890", "секретный ключ: <token>"),
    ("Access Key ID: AbCdEfGh1234567890", "Access Key ID: <token>"),
    ("pw: hunter22", "pw: <password>"), ("PW hunter22", "PW <password>"), ("PW: hunter22", "PW: <password>"),
    ("pw=hunter22", "pw=<password>"), ("pw:hunter22", "pw:<password>"), ("pwd: hunter22", "pwd: <password>"),
    ("логин ivan pw hunter22", "логин ivan pw <password>"),
    ("pw от кабинета: Qwerty123", "pw от кабинета: <password>"),
    ("пасворд: Qwerty123", "пасворд: <password>"), ("пасворд Qwerty123", "пасворд <password>"),
    ("пассворд: Qwerty123", "пассворд: <password>"), ("пороль: Qwerty123", "пороль: <password>"),
    ("зашёл с паролем Qwerty123", "зашёл с паролем <password>"),
    ("аккаунт с паролем: Qwerty123", "аккаунт с паролем: <password>"),
    # A handle after the keyword is the handle rule's, never "@<password>".
    ("поделился паролем @oleg_support", "поделился паролем @user"),
    ("пароль @dm1n2024", "пароль @user"),
    ("пароль @Qwerty!23", "пароль @<password>"),
    # Glued to a Latin word the '@' starts no handle, so the value stays a password.
    ("password@Qwerty123", "password@<password>"), ("pw@hunter22", "pw@<password>"),
    ("pass@word1234", "pass@<password>"), ("password/@Qwerty123", "password/@<password>"),
])
def test_russian_and_colloquial_secret_labels(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    # A bare "ключ" (key) is not an api_key keyword: in integration support it names a JSON field.
    "в ответе ключ payment_status_code_01 означает успешную оплату",
    "ключ merchant_order_id_2024 обязателен в запросе",
    "ключ: decline_reason_code_51", "ключ: ERR_CODE_4012_TIMEOUT", "ключ 3ds_challenge_required не заполнен",
    "ключ: AbCdEfGh1234567890",  # accepted residual, see README "Known residuals"
    "ключевые слова: campaign_2024_summer_v2", "ключи от кабинета выдали, тикет SUP-1234",
    "ключ: 1234567890123456", "ключ: PAYMENT_DECLINED_INSUFFICIENT_FUNDS", "ключ: сумма 2345 USDT 3456 USDT",
    "ключевой момент: ошибка 4001 при оплате", "подключение: AbCdEfGh1234567890", "отключили AbCdEfGh1234567890",
    "токен доступа истёк, ошибка 401", "токен доступа: expired", "токен доступа: ошибка 401",
    "апи ключи выдаются в разделе Settings",
    "pwa не открывается, ошибка 4012", "pw reset link expired", "apw: hunter22", "pw2 версия",
    "пасворд не подходит, ошибка 4012", "пороль неверный", "поролон 2024", "пароли не совпадают",
    "с паролем всё ок, статус 200", "без пароля не войти",
    # The genitive "пароля" is prose ("password reset: error"), not a label.
    "сброс пароля: ошибка", "смена пароля: успешно", "сброс пароля: ошибка 4001",
    "для смены пароля: Настройки -> Безопасность",
])
def test_labels_that_are_prose_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


def test_password_keyword_keeps_the_handle_link():
    s = Scrubber(AnonPolicy(), Roster(by_username={"oleg_support": "U0042"}))
    assert s.scrub("с паролем @oleg_support не вышло") == "с паролем @U0042 не вышло"
    assert s.scrub("pw @oleg_support") == "pw @U0042"
    assert LeakScanner(Known()).scan("с паролем @U0042 не вышло, пароль: @U0042, паролем @user") == []


# --- quoted values keep their quotes -------------------------------------------------------

TEN_LINKS = " ".join(f"https://docs.acme.com/p{i}" for i in range(10))
TEN_URLS = " ".join(["<url>"] * 10)


@pytest.mark.parametrize("text,expected", [
    ('{"password": "hunter2", "user": "ivan"}', '{"password": "<password>", "user": "ivan"}'),
    ('{"passwd": "hunter2"}', '{"passwd": "<password>"}'),
    ('{"password":"hunter2","user":"ivan"}', '{"password":"<password>","user":"ivan"}'),
    ('{\n  "email": "ivan.petrov@example.com",\n  "password": "hunter2"\n}', '{\n  "email": "<email>",\n  "password": "<password>"\n}'),
    ("{'password': 'hunter2'}", "{'password': '<password>'}"),
    ("password: 'hunter2'", "password: '<password>'"),
    ("пароль: «Qwerty123»", "пароль: «<password>»"),
    ("мой пароль «ЗимаЛето!42», поменяю потом", "мой пароль «<password>», поменяю потом"),
    ("пароль “Qwerty123”", "пароль “<password>”"),
    ("password: [hunter2]", "password: [<password>]"),
    ("password: (hunter2)", "password: (<password>)"),
    ("password: `hunter2`", "password: `<password>`"),
    ("'password' => 'hunter2'", "'password' => '<password>'"),
    ('$password = "hunter2";', '$password = "<password>";'),
    ('password: "hunter2".', 'password: "<password>".'),
    ('password: "hunter2")', 'password: "<password>")'),
    ('password: "hunter2"; login', 'password: "<password>"; login'),
    ("пароль: «Qwerty123», логин: ivan", "пароль: «<password>», логин: @user"),
    # A quote inside the value is part of it; an unclosed quote hides the value anyway.
    ('password: pa"ss123', "password: <password>"),
    ("password: hunter2's", "password: <password>"),
    ('password: "hunter2', 'password: "<password>'),
    # A PHP-style arrow keeps both quotes too.
    ('password => "hunter2"', 'password => "<password>"'),
    ('password => "hunter2', 'password => "<password>'),
    # An earlier replacement in the value slot is kept, with its quotes.
    ('password: "https://docs.acme.com/x"', 'password: "<url>"'),
    (TEN_LINKS + '\npassword: "https://docs.acme.com/x"', TEN_URLS + '\npassword: "<url>"'),
    (f"password: my.{STRIPE_LIVE}", "password: <password>"),
    ("пароль от ivan@acme.com: hunter22", "пароль от <email>: <password>"),
])
def test_quoted_passwords_keep_their_shape(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ('PASSWORD="hunter2"', 'PASSWORD="<token>"'),
    ("PASSWORD: 'hunter2'", "PASSWORD: '<token>'"),
    ("PASSWORD=hunter2", "PASSWORD=<token>"),
    (TEN_LINKS + '\nPASSWORD="hunter2"', TEN_URLS + '\nPASSWORD="<token>"'),
    # dotenv starts a comment only after whitespace: a glued '#' is part of the secret.
    ("PASSWORD=Summer#24", "PASSWORD=<token>"),
    ("PWD: Summer#2024", "PWD: <token>"),
    ("PASSWORD = Summer#2024", "PASSWORD = <token>"),
    ("DB_PASSWORD=Summer#2024", "DB_PASSWORD=<token>"),
    ("API_KEY=abc123#prod", "API_KEY=<token>"),
    (TEN_LINKS + "\nPASSWORD=Summer#2024", TEN_URLS + "\nPASSWORD=<token>"),
    ("PASSWORD=hunter2 # prod", "PASSWORD=<token> # prod"),
    ('поставь DB_PASSWORD="Qwerty12" в .env', 'поставь DB_PASSWORD="<token>" в .env'),
])
def test_env_assignments_keep_their_token(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    '{"password": "<password>", "user": "ivan"}', 'PASSWORD="<token>"', "PASSWORD=<token>", "пароль: «<password>»",
    'password: <password>"', 'password: "<url>"', "pw: <password>", "ключ: <token>", "ключ: 424242**********",
    "ключ: <email>", "admin:<email>", "user:<phone>", "login: @user:<phone>", "-u <credentials> -p <password>",
    "mysql -p<password> app", "Authorization: Basic <token>", "паролем @U0042",
    f"{BEGIN}\n<private-key>\n{END}",
    f'PRIVATE_KEY="{BEGIN}\n<private-key>\n{END}"',
    f"пароль: {BEGIN}\n<private-key>\n{END}",
    '{"private_key": "' + BEGIN + "\\n<private-key>\\n" + END + '\\n"}',
])
def test_scanner_is_silent_on_scrubbed_secrets(scanner, text):
    assert scanner.scan(text) == []


# --- command lines and HTTP headers --------------------------------------------------------

LONG = "Zx9" * 23 + "Q"  # a 70-character secret after "-p"


@pytest.mark.parametrize("text,expected", [
    ("Authorization: Basic YWRtaW46UzNjcmV0UGFzcw==", "Authorization: Basic <token>"),
    ("authorization: basic dXNlcjpwYXNz", "authorization: basic <token>"),
    ("Authorization:Basic YWRtaW46UzNjcmV0UGFzcw==", "Authorization:Basic <token>"),
    ("Authorization: Basic\nYWRtaW46UzNjcmV0UGFzcw==", "Authorization: Basic\n<token>"),
    ("Proxy-Authorization: Basic ZGVwbG95OlMzY3JldFBhc3M=", "Proxy-Authorization: Basic <token>"),
    ("basic auth: YWRtaW46UzNjcmV0UGFzcw==", "basic auth: <token>"),
    ("Basic: YWRtaW46UzNjcmV0UGFzcw==", "Basic: <token>"),
    ("Authorization: Basic YWJjOmRlZg==", "Authorization: Basic <token>"),
    ("Authorization: Basic QWJjMTIzNDU2Nzg5MEFCQw", "Authorization: Basic <token>"),
    ("headers:\nAuthorization: Basic YWRtaW46UzNjcmV0UGFzcw==\nContent-Type: application/json",
     "headers:\nAuthorization: Basic <token>\nContent-Type: application/json"),
    ("curl -H 'Authorization: Basic YWRtaW46UzNjcmV0UGFzcw==' https://api.acme.com/v1",
     "curl -H 'Authorization: Basic <token>' <url>"),
    ("в заголовке Authorization: Basic YWRtaW46UzNjcmV0UGFzcw== приходит 401",
     "в заголовке Authorization: Basic <token> приходит 401"),
    ("curl -u admin:S3cretPass https://api.acme.com/v1/ping", "curl -u <credentials> <url>"),
    ("curl -u admin:secretpass -X POST", "curl -u <credentials> -X POST"),
    ("curl --user admin:S3cretPass -X POST", "curl --user <credentials> -X POST"),
    ("curl --user=admin:S3cretPass", "curl --user=<credentials>"),
    ('curl -u "admin:S3cret Pass" -X POST', "curl -u <credentials> -X POST"),
    ("curl -u 'admin:S3cretPass' -X POST", "curl -u <credentials> -X POST"),
    ('curl -u "merchant_1042:kJ8s2nD9qLm3" -X POST', "curl -u <credentials> -X POST"),
    ("curl -u admin:12345678", "curl -u <credentials>"),
    ("curl -u 1042:kJ8s2nD9qLm3xR7 -d amount=100", "curl -u <credentials> -d amount=100"),
    ("curl -X POST https://api.acme.com/v2/refunds \\\n  -u admin:S3cretPass \\\n  -d '{\"amount\": 1500}'",
     "curl -X POST <url> \\\n  -u <credentials> \\\n  -d '{\"amount\": 1500}'"),
    ("-u ivan:Petrov", "-u <credentials>"), ("--user=admin:pass1234", "--user=<credentials>"),
    ("-u admin:S3cretPass@host.acme.com", "-u admin:<email>"),
    ("docker login -u deploy -p S3cretPass registry.acme.com", "docker login -u deploy -p <password> <domain>"),
    ("docker login -u deploy -p 'S3cretPass' registry.acme.com", "docker login -u deploy -p <password> <domain>"),
    ("docker login -u deploy -p S3cretPass\nдальше", "docker login -u deploy -p <password>\nдальше"),
    ("docker login --username deploy --password S3cretPass registry.acme.com",
     "docker login --username deploy --password <password> <domain>"),
    ("mysql -h db.internal -u app -pS3cretPass app", "mysql -h db.internal -u app -p<password> app"),
    ("mysql -u root -pP@ssw0rd", "mysql -u root -p<password>"),
    ("mysql -u app --port 3306 -pS3cretPass", "mysql -u app --port 3306 -p<password>"),
    ("mysql -u root -p secret99", "mysql -u root -p <password>"),
    ("sshpass -p S3cretPass ssh root@host", "sshpass -p <password> ssh root@host"),
    ('sshpass -p "S3cret Pass" ssh root@host', "sshpass -p <password> ssh root@host"),
    # An over-long value is left to the generic secret rules, whole.
    ("-p " + LONG, "-p <token>"), ("-p" + LONG, "<token>"),
])
def test_command_line_and_header_credentials(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text,expected", [
    ("login admin:S3cretPass", "login <credentials>"),
    ("login: admin:S3cretPass", "login: <credentials>"),
    ("login\nadmin:S3cretPass", "login\n<credentials>"),
    ("логин ivan_petrov:S3cretPass", "логин <credentials>"),
    ("логин: ivan_petrov:S3cretPass", "логин: <credentials>"),
    ("логины: admin:S3cretPass", "логины: <credentials>"),
    ("акк: buyer01:Qwerty123", "акк: <credentials>"),
    ("акк fb_user_01:Qwerty123", "акк <credentials>"),
    ("доступы: shop_admin:Qwerty123", "доступы: <credentials>"),
    ("доступ: db.acme.com:Qwerty123", "доступ: <credentials>"),
    ("creds test_user:Qwerty123", "creds <credentials>"),
    ("admin:S3cretPass", "<credentials>"), ("root:toor1234", "<credentials>"), ("Admin1:Qwerty123", "<credentials>"),
    ("admin:2024.Qwerty", "<credentials>"), ("admin:1q2w3e4r", "<credentials>"),
    # The e-mail after a default account stays one <email>, its domain never leaks.
    ("admin:ivan2024@acme-corp.com", "admin:<email>"), ("admin:ivan2024@mail.acme.com", "admin:<email>"),
    # Unchanged shapes next to the new rules.
    ("доступ: acme.com:5432", "доступ: <domain>:5432"),
    ("логин: ivan_petrov", "логин: @user"),
    ("login: type:email", "login: @user:email"),
    ("формат login:pass", "формат login:@user"),
    ("login: john.doe:79991234567", "login: @user:<phone>"),
    ("login:ivan2024", "login:@user"), ("Login:Ivan2024", "Login:@user"), ("Login:Successful", "Login:@user"),
])
def test_single_colon_credentials(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    # "-p" as a port, a flag, a path or a profile.
    "ssh -p 2222 host", "mysql -P 3306 -h db.internal", "redis-cli -p 6379", "ls -p /var/log", "tar -p -xvf backup.tar",
    "find . -print0", "find . -perm 0644", "find . -path ./x -prune", "mysql -u root -p app_db", "mysql -u root -p",
    "mysql -u app -p 3306", "-p -h host", "the -p flag is optional", "--port 3306", "--profile prod1",
    "docker run -p 8080:80 northwind/gateway", "mkdir -p /var/log/northwind", "psql -h db.internal -p 5432 -U app",
    "cp -p file1 file2", "kubectl -p prod-1", "-p Иван",
    "mysql -u root -p\nПароль отправлю отдельно", "-p\nПривет как дела",
    # "-u" without a login.
    "git push -u origin main", "sudo -u postgres psql", "sudo -u www-data php artisan", "docker run -u 1000:1000 nginx",
    "docker run -u 1000:www-data nginx", "psql -U app -h db.internal -W", "kubectl -n prod get pods",
    "ID-u test:abc", "error code E-U 12:30", "--user-agent:Mozilla/5.0",
    # "basic" as a word.
    "basic plan costs 10 usd", "basic settings", "Basic Attention Token", "basic authentication failed",
    "basic auth is not supported", "тариф basic: 1000 usd", "Basic KYC: level1234", "basic verification: passed",
    "Basic settings are in the dashboard", "тариф Basic активирован", "Basic Plan2024 costs 10 usd",
    "Basic subscription2024 renewal", "версия Basic 2.0.1", "Basic auth не работает, ошибка 401",
    # Pairs that are prose, versions, times or format descriptions.
    "user:premium", "admin:settings", "test:passed", "Test:Passed", "status:active", "root:/var/www",
    "admin: не работает", "ratio 1000:1000", "time 12:30", "акк 10:00", "mysql:8.0.32", "postgres:16-alpine",
    "postgres:15.2-alpine3.18", "admin:1.2.3-rc1", "admin:2024-09-15", "login:Ошибка", "admin:Панель",
    "логин: не подходит", "login error: 401", "login timeout:30s", "учетка заблокирована: ошибка 4012",
    "доступ к кабинету: закрыт", "доступ: 24/7", "логи: server restarted", "логотип:Acme1234",
    "лог: ERROR:Connection refused", "лог: error:timeout", "лог: level:warn msg:retry", "логи: status:failed",
    "лог ошибки: code:500", "доступ: read:write", "доступ: role:viewer", "доступ: level:basic",
    "доступ: статус:активен", "акк: status:active", "акк: type:agency", "учетка: tier:pro", "creds: expired:yes",
    "данные для входа: email:phone", "логин:пароль", "пришлите в формате логин:пароль", "акк: логин:пароль",
    "доступ: логин:пароль", "top-priority", "version 2.3.1", "заказ 12345678", "SKU-2024",
])
def test_command_line_and_prose_lookalikes_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


def test_login_pairs_keep_the_handle_link():
    s = Scrubber(AnonPolicy(), Roster(by_username={"oleg_support": "U0042"}))
    assert s.scrub("login:oleg_support") == "login:@U0042"
    assert s.scrub("логин:oleg_support") == "логин:@U0042"
    assert s.scrub("user:oleg_support") == "user:@U0042"
    assert s.scrub("логин: oleg_support:S3cretPass") == "логин: <credentials>"


# --- dotted keys and PEM private keys ------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    (SENDGRID, "<token>"), (f"ключ {SENDGRID}, проверь", "ключ <token>, проверь"), (f"({SENDGRID})", "(<token>)"),
    (f"вот он: {SENDGRID}\nдальше", "вот он: <token>\nдальше"), (f"SENDGRID_API_KEY={SENDGRID}", "SENDGRID_API_KEY=<token>"),
    ("MTIzNDU2Nzg5MDEyMzQ1Njc4.GhIjKl.MnOpQrStUvWxYz1234567890abcdefghijklm", "<token>"),
    (f"{BEGIN}\n{PEM_BODY}\nMIIEvQIBADANBg==\n{END}", f"{BEGIN}\n<private-key>\n{END}"),
    (f'{pem_begin("RSA PRIVATE KEY")}\n{PEM_BODY}\nAb1==\n{pem_end("RSA PRIVATE KEY")}',
     f'{pem_begin("RSA PRIVATE KEY")}\n<private-key>\n{pem_end("RSA PRIVATE KEY")}'),
    (f'{pem_begin("EC PRIVATE KEY")}\r\n{PEM_BODY}\r\nAb1==\r\n{pem_end("EC PRIVATE KEY")}',
     f'{pem_begin("EC PRIVATE KEY")}\r\n<private-key>\r\n{pem_end("EC PRIVATE KEY")}'),
    (f'{pem_begin("EC PRIVATE KEY")}\nMHQCAQEEIAb1cd2\nAb3==\n{pem_end("EC PRIVATE KEY")}',
     f'{pem_begin("EC PRIVATE KEY")}\n<private-key>\n{pem_end("EC PRIVATE KEY")}'),
    (f'{pem_begin("OPENSSH PRIVATE KEY")}\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n'
     f'QyNTUxOQAAACB1x2c3d4e5f6a7b8c9d0e1\n{pem_end("OPENSSH PRIVATE KEY")}',
     f'{pem_begin("OPENSSH PRIVATE KEY")}\n<private-key>\n{pem_end("OPENSSH PRIVATE KEY")}'),
    (f'{pem_begin("PGP PRIVATE KEY BLOCK")}\n\nlQdGBGX1x2c3d4e5f6a7b8c9d0e1AbCd\n=Ab1c\n{pem_end("PGP PRIVATE KEY BLOCK")}',
     f'{pem_begin("PGP PRIVATE KEY BLOCK")}\n\n<private-key>\n{pem_end("PGP PRIVATE KEY BLOCK")}'),
    (f"{BEGIN}\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV\n{END}", f"{BEGIN}\n<private-key>\n{END}"),
    # A service-account JSON keeps its literal "\n" separators.
    ('{"private_key": "' + BEGIN + "\\n" + PEM_BODY + "\\nMIIEvQIBADANBg==\\n" + END + '\\n"}',
     '{"private_key": "' + BEGIN + "\\n<private-key>\\n" + END + '\\n"}'),
    ('{"private_key":"' + BEGIN + "\\n" + PEM_BODY + "\\n" + END + '\\n","client_email":"svc@acme.example.com"}',
     '{"private_key":"' + BEGIN + "\\n<private-key>\\n" + END + '\\n","client_email":"<email>"}'),
    (f'PRIVATE_KEY="{BEGIN}\n{PEM_BODY}\nMIIEvQIBADANBg==\n{END}"', f'PRIVATE_KEY="{BEGIN}\n<private-key>\n{END}"'),
    (f"пароль: {BEGIN}\n{PEM_BODY}\nAb1==\n{END}", f"пароль: {BEGIN}\n<private-key>\n{END}"),
    (f"вот ключ:\n{BEGIN}\n{PEM_BODY}\nAb1==\n{END}\nне работает, ошибка 4001",
     f"вот ключ:\n{BEGIN}\n<private-key>\n{END}\nне работает, ошибка 4001"),
    (f"{BEGIN}\n{PEM_BODY}\n{END} и второй {BEGIN}\nAb1cD2==\n{END}",
     f"{BEGIN}\n<private-key>\n{END} и второй {BEGIN}\n<private-key>\n{END}"),
    (f"{BEGIN} \n{PEM_BODY}\n {END}", f"{BEGIN} \n<private-key>\n {END}"),
    (f"{BEGIN}MIIEvQIBADANBgkqhkiG9w0BAQ=={END}", f"{BEGIN}<private-key>{END}"),
    # Whatever an earlier layer found inside the body goes with it.
    (f"{BEGIN}\n{PEM_BODY}\n4242424242424242\nivan@northwind.io +79991234567\n{END}", f"{BEGIN}\n<private-key>\n{END}"),
    ("PRIVATE_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf", "PRIVATE_KEY=<token>"),
    ("SECRET_KEY=-----BEGINxyz123", "SECRET_KEY=<token>"),
])
def test_dotted_keys_and_pem_blocks(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


@pytest.mark.parametrize("text", [
    "SG.1 подключён, см. SG.2 и SG.abc.def",
    f"{BEGIN}\n\n{END}",
    "BEGIN PRIVATE KEY без дефисов это не ключ, а -----BEGIN----- тоже",
    "PRIVATE_KEY_PATH=/etc/keys/app.pem", "MAX_PRIVATE_KEY_LENGTH=4096",
    f"{BEGIN.lower()}\nAb1==\n{END.lower()}",
    f"{END}\nAb1==\n{BEGIN}",
    "Northwind_Statement_2024_03_12_final_v3.pdf",
    "error code E4001, order 12345678, version 2.14.3",
])
def test_key_lookalikes_stay(scrub, scanner, text):
    check(scrub, scanner, text, text)


def test_pem_residuals_and_old_output(scrub, scanner):
    # Public material and a paste cut before its END line are scrubbed line by line (documented residual).
    assert scrub(f"-----BEGIN CERTIFICATE-----\n{PEM_BODY}\nAb1==\n-----END CERTIFICATE-----") == (
        "-----BEGIN CERTIFICATE-----\n<token>\nAb1==\n-----END CERTIFICATE-----")
    assert scrub(f"{BEGIN}\n{PEM_BODY}\nMIIEvQIBADANBg==") == f"{BEGIN}\n<token>\nMIIEvQIBADANBg=="
    # A key id shorter than SendGrid's stays a generic token next to its prefix.
    assert scrub("SG.abc123." + "T" * 20 + SENDGRID[-35:]) == "SG.abc123.<token>"
    # A dataset written before PEM blocks were recognised is caught by verify.
    assert [l.kind for l in scanner.scan(f"{BEGIN}\n<token>\nMIIEvQIBADANBg==\n{END}")] == ["private_key"]


def test_secret_shapes_stay_fast(scrub, scanner):
    shapes = [BEGIN * 150, BEGIN + "\n" + "a1" * 2000, "SG." * 1300, BEGIN + " " * 4000, BEGIN + "\n" * 4000,
              BEGIN + "\\n" * 2000, BEGIN + "\n" * 2000 + "x" + "\n" * 2000, (BEGIN + " " * 100) * 30,
              BEGIN + " " * 1000, "-u a:" * 800, "-p " * 1300, "-pZ9!" * 800, "логин admin:" * 300,
              "Authorization: Basic " + "QUJD" * 1000, "admin:" * 600, "password: " + '"' * 4000]
    for text in shapes:
        assert_fast(lambda text=text[:4096]: (scrub(text), scanner.scan(text)), label=text[:40])
