"""Bare domains, keep terms inside hosts, e-mail and handle look-alikes, and
identifiers inside links that policy keeps.

* A bare host is a host in any case when its suffix is a country or generic
  one ("Ромашка.РФ", "Acme.Ru"); a suffix that is an English word or a
  payment product ("Yandex.Money", "App.Store", "Done.It") makes a host only
  in lower case or in a fully shouted host. Documentation files
  ("README.md") are not hosts; a sentence-final dot does not hide a host.
* A keep term is a word, not a licence for every host that contains it:
  only the keep term itself, the keep term plus a public suffix, or a host
  inside a longer keep term stays. ``allow_domains`` treat bare hosts as
  they treat links (an exact entry keeps that host, a wildcard hides the
  subdomain).
* Retina asset names and package versions are not e-mails; an npm scope is
  not a handle inside a package-manager command or a node_modules path.
* A kept link carries no secrets: query values, redirect targets and
  organisation names in the path are replaced, the rest of the link stays.

Every scrubbed case is flagged by the leak scanner on the raw text and
passes it on the output; every kept case stays byte-identical and the
scanner is silent on it."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import assert_fast, check as check_text
from tg_collector.anonymize import Mapping, anonymize
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, Entity, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber
from tg_collector.verify import verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
HEX32 = "0123456789abcdef0123456789abcdef"
LIVE_KEY = "sk_live_" + "Ab1" * 8


def pair(policy=None, roster=None, known=None):
    """A scrubber and a scanner configured the way ``verify`` configures it."""
    policy = policy or AnonPolicy()
    roster = roster or Roster()
    known = known or Known(keep_terms=frozenset(roster.keep_terms), usernames=frozenset(roster.by_username),
                           titles=frozenset(roster.org_terms), names=frozenset(roster.person_terms))
    url_policy = Scrubber(policy, Roster(keep_terms=tuple(known.keep_terms)))
    scanner = LeakScanner(known, url_allowed=lambda url: url_policy.url_placeholder(url) == url,
                          domain_allowed=lambda host: url_policy.domain_placeholder(host) == host,
                          custom_patterns=policy.custom_patterns)
    return Scrubber(policy, roster), scanner


def check(scrubber, scanner, text, expected, entities=()):
    """The shared two-direction assertion, for a scrubber that also reads the
    Telegram entities of the message."""
    check_text(lambda raw: scrubber.scrub(raw, list(entities)), scanner, text, expected)


# --- the shape of a bare host --------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("Ромашка.РФ", "<domain>"),
    ("ромашка.рф", "<domain>"),
    ("ромашка.РФ", "<domain>"),
    ("Мойсайт.РФ не открывается", "<domain> не открывается"),
    ("сайт Пример.Рф", "сайт <domain>"),
    ("сайт Пример.РФ и Мой-Магазин.Рф", "сайт <domain> и <domain>"),
    ("Ромашка-Шоп.рф", "<domain>"),
    ("ёлка.рф и Ёлка.РФ", "<domain> и <domain>"),
    ("лендинг Kupi-Slona.Ru, Acme.Com, Acme.Kz, acme.RU", "лендинг <domain>, <domain>, <domain>, <domain>"),
    ("Acme.Ru, Lutik.Ru, Vasilek.RU, ACME.ru, Acme.Io", "<domain>, <domain>, <domain>, <domain>, <domain>"),
    ("Acme.ru не открывается", "<domain> не открывается"),
    ("ЗАЙДИТЕ НА ACME.RU", "ЗАЙДИТЕ НА <domain>"),
    ("ЗАЙДИТЕ НА ACME.STORE или acme.store", "ЗАЙДИТЕ НА <domain> или <domain>"),
    ("acme.kz и shop.acme.store", "<domain> и <domain>"),
    ("лендинг offer-nutra.site и пример.рф", "лендинг <domain> и <domain>"),
    ("кошелёк acme.money и acme.pay", "кошелёк <domain> и <domain>"),
    ("romashka.md не открывается", "<domain> не открывается"),
    ("my-readme.md и readme.md.ru", "<domain> и <domain>"),
    # A sentence-final dot, an ellipsis or a line end after the dot.
    ("наш сайт romashka.ru.", "наш сайт <domain>."),
    ("Сайт: romashka.ru.\nспасибо", "Сайт: <domain>.\nспасибо"),
    ("сайт romashka.ru... не грузится", "сайт <domain>... не грузится"),
    ("acme.ru.evil.com.", "<domain>."),
    ("код ошибки E1234 at api.pay.kz", "код ошибки E1234 at <domain>"),
])
def test_bare_hosts_in_any_spelling_are_scrubbed(text, expected):
    check(*pair(), text, expected)


@pytest.mark.parametrize("text", [
    "Yandex.Money не проходит",
    "привязка App.Store не принимает",
    "Apple.Pay и Google.Pay подключены",
    "Сбер.Pay и Apple.Pay",
    "Done.It works",
    "README.md",
    "см. README.md в репозитории SDK, раздел Webhooks",
    "Скачайте CHANGELOG.md, там всё про 2.14.0",
    "Скачайте CHANGELOG.md.",
    "см. docs/README.md и LICENSE.md",
    "version 2.1 at build. ru",
    "т.е. всё ок.",
    "и т.д. и т.п.",
])
def test_product_names_and_doc_files_are_not_hosts(text):
    check(*pair(), text, text)


def test_code_identifiers_shaped_like_hosts_stay_scrubbed():
    # Accepted residual: "user.info" is a valid host; allow_domains or
    # scrub_domains = false keep such names.
    check(*pair(), 'logger.info("ok") и user.info', '<domain>("ok") и <domain>')


def test_public_hosts_are_reported_for_allow_domains():
    s, scanner = pair()
    for _ in range(3):
        assert s.scrub("оплата на shop.acme.ru не проходит") == "оплата на <domain> не проходит"
    assert s.scrub("лендинг offer-nutra.site") == "лендинг <domain>"
    assert s.report()["top_surfaces"]["domain"] == {"shop.acme.ru": 3, "offer-nutra.site": 1}
    check(*pair(AnonPolicy(allow_domains=("aliexpress.com",))), "оплата на aliexpress.com не проходит",
          "оплата на aliexpress.com не проходит")
    check(*pair(roster=Roster(keep_terms=("Yandex.Money",))), "yandex.money не проходит", "yandex.money не проходит")


# --- a keep term does not shield a host that contains it ---------------------------

@pytest.mark.parametrize("keep,text,expected", [
    (("Acme",), "acme.evilclient.ru", "<domain>"),
    (("Acme",), "мой сайт acme-shop.ru и shop.acme.ru", "мой сайт <domain> и <domain>"),
    (("Northwind",), "api.northwind.ru недоступен", "<domain> недоступен"),
    (("Northwind",), "shop-client.northwind.app", "<domain>"),
    (("Northwind",), "northwind.shop-client.ru", "<domain>"),
    (("Northwind",), "наш тенант romashka.northwind.io", "наш тенант <domain>"),
    (("Northwind",), "тенант romashka.northwind.io.", "тенант <domain>."),
    (("Northwind",), "romashka-northwind.ru и romashka.pay.northwind.io", "<domain> и <domain>"),
    (("Northwind",), "api.sandbox.northwind-payments-gateway-2.example.com", "<domain>"),
    (("Northwind",), "статус на status.northwind.io", "статус на <domain>"),
    (("Pay",), "pay.shop-client.ru и acme-pay.site", "<domain> и <domain>"),
    (("pay",), "pay.evilclient.ru", "<domain>"),
    (("Ромашка",), "ромашка-банк.рф", "<domain>"),
    (("Wallet",), "магазин wallet.acmeshop.kz не открывается", "магазин <domain> не открывается"),
    (("Acme Pay",), "acme pay.ru", "acme <domain>"),
    (("support",), "support.romashka.ru", "<domain>"),
    (("northwind.app",), "northwind.app и shop.northwind.app", "northwind.app и <domain>"),
    (("ASP.NET Core",), "ASP.NET 8", "<domain> 8"),
])
def test_keep_term_inside_a_host_does_not_keep_it(keep, text, expected):
    check(*pair(AnonPolicy(keep_terms=keep), Roster(keep_terms=keep)), text, expected)


@pytest.mark.parametrize("keep,text", [
    (("Northwind",), "зайдите в кабинет northwind.ru"),
    (("Northwind",), "Northwind.Pay не работает"),
    (("Northwind",), "northwind.pay и NORTHWIND.RU"),
    (("Ромашка",), "ромашка.рф"),
    (("ASP",), "ASP.NET core"),
    (("northwind.app",), "northwind.app"),
    (("Northwind.App",), "Northwind.app"),
    (("ASP.NET Core",), "мы на ASP.NET Core 8"),
    (("Socket.io client", "Yandex.Money API"), "Socket.io client и Yandex.Money API"),
    (("Northwind",), "Northwind Desk и northwind"),
])
def test_host_that_is_only_a_keep_term_stays(keep, text):
    check(*pair(AnonPolicy(keep_terms=keep), Roster(keep_terms=keep)), text, text)


def test_keep_terms_next_to_scrubbed_hosts_stay_protected():
    roster = Roster(org_terms=("Acme",), keep_terms=("Acme",))
    check(*pair(AnonPolicy(keep_terms=("Acme",)), roster), "acme.evilclient.ru и Acme", "<domain> и Acme")
    check(*pair(AnonPolicy(keep_terms=("Acme",)), roster), "Acme, Acme-карты и Acme-Pay. Acme.",
          "Acme, Acme-карты и Acme-Pay. Acme.")
    roster = Roster(org_terms=("Northwind",), keep_terms=("Northwind",))
    check(*pair(AnonPolicy(keep_terms=("Northwind",)), roster), "Northwind. Northwind-карты, northwind",
          "Northwind. Northwind-карты, northwind")
    assert LeakScanner(Known(keep_terms=frozenset({"Acme"}))).scan("<domain> и Acme") == []
    assert [l.kind for l in LeakScanner(Known(keep_terms=frozenset({"Acme"}))).scan("acme.evilclient.ru")] == ["domain"]


def test_domain_policy_switches_still_apply_with_keep_terms():
    roster = Roster(keep_terms=("Acme",))
    check(*pair(AnonPolicy(scrub_domains=False), roster), "acme.evilclient.ru и offer-nutra.site",
          "acme.evilclient.ru и offer-nutra.site")
    check(*pair(AnonPolicy(allow_domains=("acme.ru",)), roster), "acme.ru, shop.acme.ru, acme.evilclient.ru",
          "acme.ru, <domain>, <domain>")
    check(*pair(AnonPolicy(allow_domains=("*.acme.ru",)), roster), "acme.ru и shop.acme.ru", "acme.ru и <sub>.acme.ru")


# --- allow_domains: bare hosts follow the link semantics ------------------------------------

def test_wildcard_allow_hides_tenant_subdomains_in_bare_text():
    s, scanner = pair(AnonPolicy(allow_domains=("*.northwind.io",)))
    check(s, scanner, "тенант romashka.northwind.io и northwind.io и Romashka.Northwind.IO",
          "тенант <sub>.northwind.io и northwind.io и <sub>.Northwind.IO")
    assert [l.match for l in scanner.scan("тенант romashka.northwind.io")] == ["romashka.northwind.io"]
    assert scanner.scan("<sub>.northwind.io") == []


def test_exact_allow_keeps_only_that_host():
    check(*pair(AnonPolicy(allow_domains=("northwind.io",))), "тенант romashka.northwind.io и northwind.io",
          "тенант <domain> и northwind.io")
    check(*pair(AnonPolicy(allow_domains=("docs.acme.com",))), "лендинг offer-nutra.site и docs.acme.com, версия 1.2.3",
          "лендинг <domain> и docs.acme.com, версия 1.2.3")


def test_wildcard_allow_hides_a_capitalised_subdomain_in_links():
    s, scanner = pair(AnonPolicy(allow_domains=("*.acme.com",)))
    check(s, scanner, "https://Client1.Acme.com/orders/12 и https://client2.acme.com/x",
          "https://<sub>.acme.com/orders/12 и https://<sub>.acme.com/x")


# --- e-mail and handle look-alikes -----------------------------------------------------

@pytest.mark.parametrize("text", [
    "arr@2x.png",
    "кнопка button@2x.png не грузится",
    "logo@2x.png.",
    "icon@3x.jpg и icon@1.5x.webp",
    "обновите northwind-sdk@2.1.0",
    "npm i lodash@4.17.21",
    "npm i @types/node",
    "npm install @northwind/checkout-sdk",
    "yarn add @angular/core@17",
    "pnpm add --save-dev @types/node",
    "npm i -D @types/node @northwind/checkout-sdk@^1.2",
    "npm i @northwind/pay-js@2.3.1",
    "поставьте `npm i @types/node` и перезапустите",
    "npx @northwind/cli init",
    "node_modules/@types/node",
    "ошибка в node_modules/@northwind/pay-js/dist/index.js",
])
def test_assets_versions_and_npm_scopes_stay(text):
    check(*pair(), text, text)


@pytest.mark.parametrize("text,entities", [
    ("npm i @types/node", [Entity("Mention", 6, 6)]),
    ("node_modules/@types/node", [Entity("Mention", 13, 6)]),
])
def test_npm_scope_tagged_as_a_mention_stays(text, entities):
    check(*pair(), text, text, entities)


@pytest.mark.parametrize("text,expected", [
    ("ivan@1c.ru", "<email>"),
    ("ivan@163.com", "<email>"),
    ("ivan.petrov@10.0.0.1", "<email>"),
    ("ivan@10.0.0.1.", "<email>."),
    ("ivan@2x.ru", "<email>"),
    ("ivan@2x.png.ru", "<email>"),
    ("ivan@12.34.ru", "<email>"),
])
def test_mail_domains_that_look_like_versions_stay_emails(text, expected):
    check(*pair(), text, expected)


@pytest.mark.parametrize("text,expected,entities", [
    ("пост в канале @acme_shop_news/123", "пост в канале @user/123", []),
    ("пост в канале @acme_shop_news/123", "пост в канале @user/123", [Entity("Mention", 14, 15)]),
    ("контакты: @anna_manager/oleg_backup", "контакты: @user/oleg_backup", []),
    ("пишите @client_shop/support", "пишите @user/support", []),
    ("пишите @some_buyer_99/whatsapp", "пишите @user/whatsapp", []),
    ("пишите @manager_ivan/support_anna", "пишите @user/support_anna", []),
    ("канал @romashka_news/123 там пост", "канал @user/123 там пост", [Entity("Mention", 6, 14)]),
    ("мой инст @anna_beauty/reels", "мой инст @user/reels", [Entity("Mention", 9, 12)]),
    ("npm i @types/node — пишите @anna_beauty/reels", "npm i @types/node — пишите @user/reels", []),
    ("npm-сервер лежит, пишите @anna_beauty/reels", "npm-сервер лежит, пишите @user/reels", []),
    ("через npm не ставится, пишите @anna_beauty/reels", "через npm не ставится, пишите @user/reels", []),
    ("пишите @unknown_guy/ или @unknown_guy/Менеджер", "пишите @user/ или @user/Менеджер", []),
    ("npm i @unknown_guyу/x", "npm i @user/x", []),
    # Accepted residuals: without a package-manager command the scope shape is
    # a handle, and the other look-alikes keep their old placeholders.
    ("установите пакет @northwind/checkout-sdk", "установите пакет @user/checkout-sdk", []),
    ('"@babel/core": "^7.0"', '"@user/core": "^7.0"', []),
    ("@channel посмотрите", "@user посмотрите", []),
    ("git@github.com:org/repo.git", "<credentials>", []),
    ("ОЛЕГ СЕВЕРОВ, [12.03.2024 10:15]", "<name>, [12.03.2024 10:15]", []),
])
def test_handles_after_a_slash_are_still_handles(text, expected, entities):
    check(*pair(), text, expected, entities)


def test_known_username_wins_over_the_npm_shape():
    roster = Roster(by_username={"ivan_petrov": "U0002"})
    known = Known(usernames=frozenset({"ivan_petrov"}))
    s, scanner = pair(roster=roster, known=known)
    check(s, scanner, "npm i @ivan_petrov/sdk", "npm i @U0002/sdk")
    check(s, scanner, "npm i @ivan_petrov/sdk", "npm i @U0002/sdk", [Entity("Mention", 6, 12)])
    assert [l.kind for l in scanner.scan("npm i @ivan_petrov/sdk")] == ["username"]


# --- identifiers inside a link that policy keeps ---------------------------------------

ALLOW = AnonPolicy(allow_domains=("acme.com",))
KEEP = AnonPolicy(url_mode="keep")


@pytest.mark.parametrize("policy", [ALLOW, KEEP], ids=["allow", "keep"])
@pytest.mark.parametrize("text,expected", [
    ("https://acme.com/login?password=hunter2", "https://acme.com/login?password=<password>"),
    ("https://acme.com/login?user=ivan&pass=Qwerty123", "https://acme.com/login?user=ivan&pass=<password>"),
    ("https://acme.com/cabinet?inn=7700000425&kpp=770701001", "https://acme.com/cabinet?inn=<inn>&kpp=770701001"),
    ("https://acme.com/kyc?passport=4510123456", "https://acme.com/kyc?passport=<passport>"),
    ("https://acme.com/kyc?паспорт=4510123456", "https://acme.com/kyc?паспорт=<passport>"),
    (f"https://acme.com/cb?token=abc&api_key={LIVE_KEY}", "https://acme.com/cb?token=abc&api_key=<token>"),
    (f"https://acme.com/cb?key={LIVE_KEY}", "https://acme.com/cb?key=<token>"),
    ("https://acme.com/3ds?code=482913", "https://acme.com/3ds?code=<otp>"),
    ("https://acme.com/api?otp=482913&pin=1234", "https://acme.com/api?otp=<otp>&pin=<pin>"),
    (f"https://acme.com/reset-password?token={HEX32}", "https://acme.com/reset-password?token=<token>"),
    ("https://acme.com/?ip=203.0.113.7&phone=79161234567", "https://acme.com/?ip=<ip>&phone=<phone>"),
    ("https://acme.com/pay?cvv=123&exp=12/27", "https://acme.com/pay?cvv=<cvv>&exp=<exp>"),
    ("https://acme.com/?dob=12.03.1990&date=12.03.2024", "https://acme.com/?dob=<dob>&date=12.03.2024"),
    ("https://acme.com/r?tg=@some_buyer_99&e=ivan@example.com", "https://acme.com/r?tg=@user&e=<email>"),
    ("https://acme.com/redirect?to=romashka-shop.ru", "https://acme.com/redirect?to=<domain>"),
    # Escapes that spell link structure ("%2F") stay; the rest is read as text.
    ("https://acme.com/redirect?url=https%3A%2F%2Fromashka-shop.ru%2Fx",
     "https://acme.com/redirect?url=https:%2F%<domain>%2Fx"),
    ("https://acme.com/clients/romashka/setup и https://acme.com/clients/ромашка-шоп/x",
     "https://acme.com/clients/<org>/setup и https://acme.com/clients/<org>-шоп/x"),
    ("https://acme.com/u/@ivan_petrov/posts?ref=ivan_petrov", "https://acme.com/u/@U0002/posts?ref=@U0002"),
])
def test_kept_links_lose_their_secrets(policy, text, expected):
    roster = Roster(by_username={"ivan_petrov": "U0002"}, org_terms=("Ромашка",))
    known = Known(usernames=frozenset({"ivan_petrov"}), titles=frozenset({"Ромашка"}))
    check(*pair(policy, roster, known), text, expected)


@pytest.mark.parametrize("policy", [ALLOW, KEEP], ids=["allow", "keep"])
@pytest.mark.parametrize("text,expected", [
    # W3: a browser percent-encodes what the user typed, so an identifier
    # arrives encoded. It is read as text before the layers run over it.
    ("https://acme.com/search?q=%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2",
     "https://acme.com/search?q=<name>"),
    ("https://acme.com/search?q=%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2%20%D0%98%D0%B2%D0%B0%D0%BD",
     "https://acme.com/search?q=<name>%20Иван"),
    ("https://acme.com/?user=Иван%20Петров", "https://acme.com/?user=Иван%20<name>"),
    ("https://acme.com/?user=Иван+Петров", "https://acme.com/?user=Иван%20<name>"),
    ("https://acme.com/clients/%D0%A0%D0%BE%D0%BC%D0%B0%D1%88%D0%BA%D0%B0",
     "https://acme.com/clients/<org>"),
    ("https://acme.com/client/%D0%A0%D0%BE%D0%BC%D0%B0%D1%88%D0%BA%D0%B0/orders",
     "https://acme.com/client/<org>/orders"),
    ("https://acme.com/?phone=8%20916%20123%2045%2067", "https://acme.com/?phone=<phone>"),
    ("https://acme.com/?card=4242%204242%204242%204242", "https://acme.com/?card=424242**********"),
    ("https://acme.com/?email=ivan%40example.com", "https://acme.com/?email=<email>"),
    ("https://acme.com/?fio=%D0%A1%D0%BC%D0%B8%D1%80%D0%BD%D0%BE%D0%B2%20%D0%90%D0%BB%D0%B5%D0%BA%D1%81%D0%B5%D0%B9"
     "%20%D0%92%D0%B8%D0%BA%D1%82%D0%BE%D1%80%D0%BE%D0%B2%D0%B8%D1%87", "https://acme.com/?fio=<name>"),
])
def test_percent_encoded_values_in_a_kept_link_are_read_as_text(policy, text, expected):
    roster = Roster(person_terms=("Петров", "Смирнов"), org_terms=("Ромашка",))
    known = Known(names=frozenset({"Петров", "Смирнов"}), titles=frozenset({"Ромашка"}))
    check(*pair(policy, roster, known), text, expected)


@pytest.mark.parametrize("policy", [ALLOW, KEEP], ids=["allow", "keep"])
@pytest.mark.parametrize("text", [
    # Nothing identifying: the segment is written back exactly as it arrived.
    "https://acme.com/docs/%D0%BE%D0%BF%D0%BB%D0%B0%D1%82%D0%B0",
    "https://acme.com/docs/getting%20started",
    "https://acme.com/?utm_campaign=spring%202024",
    "https://acme.com/?q=a+b",
    "https://acme.com/a%2Fb?x=%26y",
    "https://acme.com/api/v2/orders/12345?status=paid",
])
def test_ordinary_encoding_in_a_kept_link_survives(policy, text):
    check(*pair(policy, Roster(person_terms=("Петров",), org_terms=("Ромашка",))), text, text)


def test_link_targets_are_normalised_like_text():
    """A Url or TextUrl target skips the text layer, so ``url_placeholder``
    normalises it itself: a hiding character inside the link is no shelter."""
    s = Scrubber(KEEP, Roster(person_terms=("Петров",), org_terms=("Ромашка",)))
    for hidden in ("https://acme.com/u/Пет\u200bров", "https://acme.com/u/Пет\xadров"):
        assert s.url_placeholder(hidden) == "https://acme.com/u/<name>"
    assert s.url_placeholder("https://acme.com/u/Рома\u0301шка") == \
        "https://acme.com/u/<org>"


def test_verify_reports_what_an_encoded_link_spells():
    _, scanner = pair(ALLOW, Roster(person_terms=("Петров",)),
                      Known(names=frozenset({"Петров"})))
    raw = "https://acme.com/search?q=%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2"
    assert "name" in {leak.kind for leak in scanner.scan(raw)}
    assert scanner.scan("https://acme.com/search?q=<name>") == []


def test_redirect_targets_follow_the_link_policy():
    check(*pair(ALLOW), "https://acme.com/redirect?to=https://romashka-shop.ru/x",
          "https://acme.com/redirect?to=<url>")
    check(*pair(ALLOW), "https://acme.com/redirect?to=offer-nutra.site/x&t=1", "https://acme.com/redirect?to=<url>")
    check(*pair(AnonPolicy(allow_domains=("acme.com", "docs.acme.com"))),
          "https://acme.com/redirect?to=https://docs.acme.com/x?password=hunter2",
          "https://acme.com/redirect?to=https://docs.acme.com/x?password=<password>")
    # url_mode = "keep" keeps a nested link as it keeps any other link.
    s = Scrubber(KEEP, Roster())
    assert s.scrub("https://acme.com/redirect?to=https://romashka-shop.ru/x") == \
        "https://acme.com/redirect?to=https://romashka-shop.ru/x"


@pytest.mark.parametrize("text", [
    "https://acme.com/orders/12345678901?tab=history",
    "https://acme.com/errors/code/05",
    "https://acme.com/guides/pin-reset?step=2",
    "https://acme.com/errors/decline-codes?code=05",
    "https://acme.com/a?code=05&reason=do_not_honor",
    "https://acme.com/sdk?version=2.14.0&platform=ios",
    "https://acme.com/v/1.2.3?v=1.2.3.4",
    "https://acme.com/search?q=decline+05&sort=date",
    "https://acme.com/api#section-token-auth",
    "https://acme.com/changelog#v2.14.0",
    "https://acme.com/ru/кабинет/пароль/сброс",
    "https://acme.com/api/token/refresh и https://acme.com/cards/expiry?format=MM/YY",
    "https://acme.com/merchant/MID-12345/settings",
])
def test_kept_links_keep_routes_and_product_values(text):
    check(*pair(ALLOW, Roster(org_terms=("Ромашка",))), text, text)


@pytest.mark.parametrize("text", [
    # Keyword-like path segments are routes and stay; verify still reports
    # the ones shaped like values (a documented, fuzzy false positive).
    "https://acme.com/northwind/password-reset/pull/42",
    "https://acme.com/sdk/login/android_v2",
    "https://acme.com/pin/1234",
])
def test_kept_link_paths_are_not_read_as_keyword_values(text):
    assert Scrubber(ALLOW, Roster()).scrub(text) == text


def test_kept_links_from_entities_and_other_modes():
    link = "https://acme.com/login?password=hunter2"
    masked = "https://acme.com/login?password=<password>"
    s, scanner = pair(ALLOW)
    check(s, scanner, link, masked, [Entity("Url", 0, len(link))])
    out = s.scrub("см. документацию", [Entity("TextUrl", 0, 3, url=link)])
    assert out == f"см. ({masked}) документацию" and not scanner.scan(out)
    s, scanner = pair(AnonPolicy(url_mode="domain", allow_domains=("acme.com",)))
    check(s, scanner, f"{link} и https://romashka.ru/x?password=hunter2", f"{masked} и <url:romashka.ru>")
    check(*pair(AnonPolicy(allow_domains=("*.acme.com",))), "https://shop.acme.com/login?password=hunter2",
          "https://<sub>.acme.com/login?password=<password>")


DOMAIN = AnonPolicy(url_mode="domain")


@pytest.mark.parametrize("text,expected", [
    # W3: under "domain" the host is all that survives, so a host that spells
    # a client or a person is hidden whole.
    ("личный кабинет https://romashka.ru/cabinet", "личный кабинет <url>"),
    ("https://lk.romashka-shop.kz/login", "<url>"),
    ("сайт https://petrov.pro/", "сайт <url>"),
    ("https://ivan-petrov.github.io/cv", "<url>"),
    # a host that names nobody keeps its name; a client name in the path does
    # not make the host one.
    ("https://acme.com/romashka", "<url:acme.com>"),
    ("https://shop.example.com/x", "<url:shop.example.com>"),
])
def test_domain_mode_hides_a_host_that_names_a_client(text, expected):
    roster = Roster(org_terms=("Ромашка",), person_terms=("Петров",))
    known = Known(titles=frozenset({"Ромашка"}), names=frozenset({"Петров"}))
    check(*pair(DOMAIN, roster, known), text, expected)


def test_domain_mode_keeps_allowed_and_kept_hosts():
    s = Scrubber(AnonPolicy(url_mode="domain", allow_domains=("romashka.ru",)), Roster(org_terms=("Ромашка",)))
    assert s.scrub("https://romashka.ru/cabinet") == "https://romashka.ru/cabinet"
    check(*pair(DOMAIN, Roster(org_terms=("Northwind",), keep_terms=("Northwind",))),
          "https://northwind.io/docs", "<url:northwind.io>")


@pytest.mark.parametrize("text,kind", [
    ("<mailto:ivan@example.com>", "email"),
    ("пишите <sip:ivan@example.com>", "email"),
    ("<tel:+79161112233>", "phone"),
    ("<https://evil.example.com/x?phone=79161112233>", "phone"),
    ("<1:db8::1>", "ipv6"),
])
def test_scanner_reads_typed_autolinks(text, kind):
    """A "<word:...>" wrapper is only opaque when the word is one the
    scrubber writes: "<url:acme.com>" is its own, "<mailto:...>" is not."""
    assert kind in {leak.kind for leak in LeakScanner(Known()).scan(text)}


@pytest.mark.parametrize("text", [
    "<email>", "<phone>", "<url>", "<url:shop.example.com>", "<mailto:<email>>", "<email> и <phone>",
    "<sub>.example.com", "<wallet>", "<ip>", "<name> и <org>",
])
def test_scanner_stays_silent_on_our_own_placeholders(text):
    assert LeakScanner(Known()).scan(text) == []


def test_scanner_leaves_an_allowed_autolink_alone():
    _, scanner = pair(ALLOW)
    assert scanner.scan("<https://acme.com/x>") == []


@pytest.mark.parametrize("policy", [ALLOW, KEEP], ids=["allow", "keep"])
def test_user_info_of_a_kept_link_is_a_credential(policy):
    s, scanner = pair(policy)
    for link in ("https://ivan:hunter2@acme.com/x", "https://ivan@acme.com/x"):
        out = s.scrub("см", [Entity("TextUrl", 0, 2, url=link)])
        assert out == "см (https://<credentials>@acme.com/x)" and not scanner.scan(out)
        check(s, scanner, link, "https://<credentials>@acme.com/x", [Entity("Url", 0, len(link))])
    assert s.scrub("https://ivan:hunter2@acme.com/x") == "<proxy>/x"
    wildcard = Scrubber(AnonPolicy(allow_domains=("*.acme.com",)), Roster())
    assert wildcard.url_placeholder("https://ivan:x@Shop.acme.com:8443/a?password=hunter2") == \
        "https://<credentials>@<sub>.acme.com:8443/a?password=<password>"


WALLET = "Ab3dEf7hJk9mNp2qRs4tUv6wXy8zAb3dEf7h"  # base58-shaped, fictional
TRON = "TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE"
EVM = "0x52908400098527886E0F7030069857D2E4169EE7"
TXID = "0x" + "ab" * 32


@pytest.mark.parametrize("policy,roster,text,expected", [
    # W3: a wallet or a hash inside a kept link goes through the same table
    # as the rest of it, so no later layer reads its placeholder as text.
    (KEEP, Roster(org_terms=("Wallet",)), f"https://acme.com/pay?wallet={WALLET}",
     "https://acme.com/pay?<org>=<wallet>"),
    (KEEP, Roster(org_terms=("Wallet",)), f"https://acme.com/pay?wallet={TRON}",
     "https://acme.com/pay?<org>=<wallet>"),
    (KEEP, Roster(person_terms=("Wallet",)), f"https://acme.com/pay?w={EVM}", "https://acme.com/pay?w=<wallet>"),
    (AnonPolicy(url_mode="keep", custom_patterns=("txid",)), Roster(), f"https://acme.com/tx/{TXID}",
     "https://acme.com/tx/<txid>"),
    (KEEP, Roster(), f"https://etherscan.io/tx/{TXID}", "https://etherscan.io/tx/<txid>"),
    (KEEP, Roster(), f"https://acme.com/explorer/usdt/{WALLET}", "https://acme.com/explorer/usdt/<wallet>"),
    (AnonPolicy(url_mode="keep", card_bins=("424242",)), Roster(), "https://acme.com/pay/4242424242424242?x=1",
     "https://acme.com/pay/424242**********?x=1"),
    (AnonPolicy(url_mode="keep", card_bins=("424242",)), Roster(), "https://acme.com/p?card=4242424242424242&cvv=123",
     "https://acme.com/p?card=424242**********&cvv=<cvv>"),
    # A label glued to an address with an underscore is not a shelter.
    (KEEP, Roster(), f"https://acme.com/кошелек_{EVM}&", "https://acme.com/кошелек_<wallet>&"),
    (AnonPolicy(), Roster(), "usdt_TJRabPrwbZy45sbavfcjinPJC18kjpRTv8", "usdt_<wallet>"),
])
def test_wallets_and_hashes_in_a_kept_link(policy, roster, text, expected):
    out = Scrubber(policy, roster).scrub(text)
    assert out == expected
    assert "<<" not in out and ">>" not in out


def test_custom_pattern_does_not_eat_a_masked_card_in_a_link():
    policy = AnonPolicy(url_mode="keep", custom_patterns=(r"\d{6}",))
    text = "https://acme.com/pay/4242424242424242"
    assert Scrubber(policy, Roster()).scrub(text, [Entity("Url", 0, len(text))]) == \
        "https://acme.com/pay/424242**********"
    assert Scrubber(KEEP, Roster()).url_placeholder("https://4242424242424242@acme.com/") == \
        "https://<credentials>@acme.com/"
    assert Scrubber(AnonPolicy(), Roster()).scrub(f"https://acme.com/explorer/usdt/{WALLET}") == "<url>"


def test_scrubbed_kept_links_render_unchanged_for_verify():
    roster = Roster(by_username={"ivan_petrov": "U0002"})
    s = Scrubber(ALLOW, roster)
    url_policy = Scrubber(ALLOW, Roster())
    out = s.scrub("https://acme.com/login?login=ivan_petrov&password=Qwerty123")
    assert out == "https://acme.com/login?login=@U0002&password=<password>"
    head = out.split("<", 1)[0]
    assert url_policy.url_placeholder(head) == head
    kept = "https://acme.com/r?ref=@U0002&tg=@user"
    assert url_policy.url_placeholder(kept) == kept


def test_dropped_links_do_not_count_inner_replacements():
    s = Scrubber(AnonPolicy(), Roster())
    assert s.scrub("https://romashka.ru/?e=ivan@example.com&password=hunter2") == "<url>"
    assert not any(k.startswith("url:") for k in s.report()["counts"])


def test_link_and_domain_rules_stay_fast_on_hostile_runs():
    s, scanner = pair(ALLOW, Roster(by_username={"ivan_petrov": "U0002"}, org_terms=("Ромашка",),
                                    keep_terms=("Northwind",)))
    for text in ("https://acme.com/x?" + "a=1&" * 1024, "https://acme.com/x?" + "password=Qwerty1&" * 240,
                 "https://acme.com/" + "pin/1234/" * 450, "a." * 2048 + "ru", "A." * 2048 + "STORE",
                 "npm " + "x " * 2040 + "@types/node", "a@" + "1." * 2048, "northwind.ru " * 300,
                 "user:" * 800 + "@203.0.113.7:8080"):
        def pass_over(text=text):
            out = s.scrub(text)
            scanner.scan(text)
            scanner.scan(out)

        assert_fast(pass_over, label=text[:40])


# --- the whole pipeline -------------------------------------------------------------------

def test_anonymize_and_verify_agree_on_hosts_and_kept_links(tmp_path):
    policy = AnonPolicy(keep_terms=("Northwind",), allow_domains=("acme.com", "*.northwind.app"))
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-2004, kind=KIND_SUPERGROUP, title="Ромашка / Northwind", participant_ids=(1, 11))
    store.put_chats([chat])
    store.put_users([ME, RawUser(id=11, first_name="Иван")])
    store.set_me_id(1)
    texts = [
        "вход https://acme.com/login?password=hunter2 и редирект https://acme.com/r?to=romashka-shop.ru",
        "тенант romashka.northwind.app, кабинет northwind.ru, лендинг acme.evilclient.ru",
        "см. README.md, Yandex.Money не проходит, сайт Ромашка.РФ.",
        "npm i @northwind/pay-js@2.3.1, иконка arr@2x.png",
    ]
    store.append_messages(chat.id, [RawMessage(chat_id=chat.id, id=i + 1, date=T0 + timedelta(minutes=i), sender_id=11,
                                               sender_kind=SENDER_USER, text=t) for i, t in enumerate(texts)])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1), policy)
    assert [m.text for m in ds.messages] == [
        "вход https://acme.com/login?password=<password> и редирект https://acme.com/r?to=<domain>",
        "тенант <sub>.northwind.app, кабинет northwind.ru, лендинг <domain>",
        "см. README.md, Yandex.Money не проходит, сайт <domain>.",
        "npm i @northwind/pay-js@2.3.1, иконка arr@2x.png",
    ]
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(), {})
    report = tmp_path / "verify_report.json"
    assert verify(out, store, policy, report).ok
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        for raw in ("https://acme.com/login?password=hunter2", "тенант romashka.northwind.app", "сайт Ромашка.РФ."):
            fh.write(json.dumps({"text": raw}, ensure_ascii=False) + "\n")
    kinds = {(l.kind, l.match) for l in verify(out, store, policy, report).leaks}
    assert {("password", "password=hunter2"), ("domain", "romashka.northwind.app"), ("domain", "Ромашка.РФ")} <= kinds
