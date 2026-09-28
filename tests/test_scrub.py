import pytest

from conftest import BOT_TOKEN, JWT, STRIPE_LIVE_LONG, assert_fast
from tg_collector.config import AnonPolicy
from tg_collector.model import Entity
from tg_collector.scrub import (
    Known, LeakScanner, Roster, Scrubber, org_terms_from_titles, title_tokens,
)


@pytest.fixture
def roster():
    return Roster(
        by_username={"ivan_petrov": "U0002", "acme_bot": "U0009"},
        by_user_id={42: "U0002"},
        person_terms=("Петров", "Smith"),
        org_terms=("Ромашка", "Acme"),
        keep_terms=("Northwind",),
    )


@pytest.fixture
def scrub(roster):
    return Scrubber(AnonPolicy(), roster).scrub


# --- regex layer ---------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("8 (999) 123-45-67", "<phone>"),
    ("+7 999 123 45 67", "<phone>"),
    ("+79991234567", "<phone>"),
    ("89991234567", "<phone>"),
    ("+1-202-555-0143", "<phone>"),
    ("тел 999-123-45-67 ок", "тел <phone> ок"),
])
def test_phones_are_removed(scrub, text, expected):
    assert scrub(text) == expected


@pytest.mark.parametrize("text", [
    "тикет W102186",
    "заказ 1234567890",
    "дата 2024-01-10 и 10.01.2024",
    "сумма 10 000 000 000 руб",
    "время 12:30:45",
    "версия 2.15.3 build 4711",
    "ошибка 0x80070005",
    "INC-2024-000123",
    "12345678901",
])
def test_product_numbers_survive(scrub, text):
    assert scrub(text) == text


def test_emails_links_handles(scrub):
    out = scrub("пишите на ivan.petrov+x@example.co.uk, @ivan_petrov, @unknown_guy, "
                "https://acme.ru/a?b=1 www.foo.bar/z t.me/ivan_petrov tg://user?id=42")
    assert out == "пишите на <email>, @U0002, @user, <url> <url> <tg-link> <tg-link>"


def test_handle_inside_email_is_not_double_scrubbed(scrub):
    assert scrub("a@b.com") == "<email>"


def test_ips_cards_tokens(scrub):
    out = scrub("host 192.168.1.10:8080, 2001:db8::1, fe80::1%eth0, card 5105 1051 0510 5100, "
                f"md5 5d41402abc4b2a76b9719d911017c592, bot {BOT_TOKEN}")
    assert out.startswith("host <ip>, <ip>, <ip>%eth0, card 510510**********, md5 <token>, bot <token>")


def test_jwt_and_long_secret(scrub):
    assert scrub(f"token {JWT}") == "token <token>"
    assert scrub(f"key {STRIPE_LIVE_LONG}") == "key <token>"


def test_luhn_rejects_random_16_digits(scrub):
    assert scrub("id 1234 5678 9012 3456") == "id 1234 5678 9012 3456"


def test_iban(scrub):
    assert scrub("IBAN DE89370400440532013000 ok") == "IBAN <iban> ok"


def test_timestamps_not_ipv6(scrub):
    assert scrub("в 12:30:45 и 09:15") == "в 12:30:45 и 09:15"


# --- vocabulary layer ----------------------------------------------------------

def test_names_and_orgs_with_inflection(scrub):
    assert scrub("Петров и Петрову, у Ромашки, Ромашкой, Acme, Mr. Smith") == \
        "<name> и <name>, у <org>, <org>, <org>, Mr. <name>"


def test_keep_terms_are_never_scrubbed(scrub):
    assert scrub("Northwind Desk и northwind") == "Northwind Desk и northwind"


def test_case_insensitive_cyrillic(scrub):
    assert scrub("ПЕТРОВ петров") == "<name> <name>"


def test_custom_patterns_and_terms():
    policy = AnonPolicy(custom_patterns=(r"КПП\s*\d{9}",), custom_terms=("Globex",))
    s = Scrubber(policy, Roster(org_terms=("Globex",)))
    assert s.scrub("КПП 770701001 у Globex") == "<redacted> у <org>"


def test_custom_pattern_cannot_damage_placeholders():
    s = Scrubber(AnonPolicy(custom_patterns=(r"\d+",)), Roster(by_username={"alice": "U0044"}))
    assert s.scrub("hi @alice ticket 42", [Entity("Mention", 3, 6)]) == "hi @U0044 ticket <redacted>"


def test_russian_legal_ids():
    s = Scrubber(AnonPolicy(), Roster())
    assert s.scrub("ИНН 7700000425 и 770000000082, КПП 770701001") == "ИНН <tax-id> и <inn>, КПП 770701001"
    assert s.scrub("ОГРН 1027700000041, ОГРНИП 391315064287204") == "ОГРН <ogrn>, ОГРНИП <ogrn>"
    assert s.scrub("СНИЛС 112-233-445 95") == "СНИЛС <snils>"
    assert s.scrub("р/с 40702810900000012345") == "р/с <account>"
    assert s.scrub("паспорт серия 45 09 123456 выдан") == "паспорт серия <passport> выдан"
    # Random numbers of the same length that fail the checksums survive.
    assert s.scrub("заказ 7707083894, номер 1027700132190") == "заказ 7707083894, номер 1027700132190"


def test_telegram_desktop_header_and_bare_identifiers():
    roster = Roster(by_username={"ivan_petrov": "U0002", "ivan": "U0003"}, known_ids=(123456789, -1001234567890))
    s = Scrubber(AnonPolicy(), roster)
    assert s.scrub("Иван Петров, [12.03.2024 10:15]\nпривет") == "<name>, [12.03.2024 10:15]\nпривет"
    assert s.scrub("мой ник ivan_petrov, а ivan это слово") == "мой ник @U0002, а ivan это слово"
    # The "-100" mark belongs to the chat id and goes with it.
    assert s.scrub("id 123456789, чат -1001234567890 или 1234567890, версия 1.2.3.4") == \
        "id <id>, чат <id> или <id>, версия 1.2.3.4"


def test_private_use_characters_in_input_are_neutralised():
    # Replaced by same-width spaces (not removed) so Telegram entity offsets stay valid.
    s = Scrubber(AnonPolicy(), Roster(by_username={"alice": "U0044"}))
    assert s.scrub("\ue000\ue100\ue001 hi @alice \ue000") == "    hi @U0044  "


def test_entity_edge_inside_surrogate_pair_is_snapped():
    s = Scrubber(AnonPolicy(), Roster(by_user_id={7: "U0007"}))
    text = "😀Иван"
    # Offset 1 points inside the emoji's surrogate pair; the whole pair is consumed.
    assert s.scrub(text, [Entity("MentionName", 1, 5, user_id=7)]) == "@U0007"
    assert "\ufffd" not in s.scrub(text, [Entity("MentionName", 1, 5, user_id=7)])


def test_url_modes():
    roster = Roster()
    assert Scrubber(AnonPolicy(url_mode="domain"), roster).scrub("см https://docs.acme.com/x") == "см <url:docs.acme.com>"
    assert Scrubber(AnonPolicy(url_mode="keep"), roster).scrub("см https://docs.acme.com/x") == "см https://docs.acme.com/x"
    exact = Scrubber(AnonPolicy(allow_domains=("docs.acme.com",)), roster)
    assert exact.scrub("см https://docs.acme.com/x и https://evil.io/y и https://acme.com/z") == \
        "см https://docs.acme.com/x и <url> и <url>"
    wildcard = Scrubber(AnonPolicy(allow_domains=("*.acme.com",)), roster)
    assert wildcard.scrub("https://client1.acme.com/orders/12 и https://acme.com/z") == \
        "https://<sub>.acme.com/orders/12 и https://acme.com/z"
    for policy in (AnonPolicy(url_mode="keep"), AnonPolicy(allow_domains=("t.me",))):
        assert Scrubber(policy, roster).scrub("https://t.me/c/123/45 tg://user?id=5") == "<tg-link> <tg-link>"


# --- entity layer ----------------------------------------------------------------

def test_entities_use_utf16_offsets(scrub):
    # The emoji is one code point but two UTF-16 units; Telegram offsets count units.
    text = "😀 привет @ivan_petrov и Иван"
    ents = [Entity("Mention", 10, 12), Entity("MentionName", 25, 4, user_id=42)]
    assert scrub(text, ents) == "😀 привет @U0002 и @U0002"


def test_entity_email_phone_card(scrub):
    text = "mail x@y.z tel 123 card 5105105105105100"
    ents = [Entity("Email", 5, 5), Entity("Phone", 15, 3), Entity("BankCard", 24, 16)]
    assert scrub(text, ents) == "mail <email> tel <phone> card 510510**********"


def test_text_url_entity_hides_target_unless_allowed():
    text = "см. документацию"
    ent = Entity("TextUrl", 4, 12, url="https://docs.example.com/a")
    assert Scrubber(AnonPolicy(), Roster()).scrub(text, [ent]) == "см. документацию"
    assert Scrubber(AnonPolicy(allow_domains=("docs.example.com",)), Roster()).scrub(text, [ent]) == \
        "см. документацию (https://docs.example.com/a)"
    tg = Entity("TextUrl", 4, 12, url="tg://user?id=123456")
    assert Scrubber(AnonPolicy(url_mode="keep"), Roster()).scrub(text, [tg]) == "см. документацию"


def test_overlapping_and_out_of_range_entities_are_safe(scrub):
    text = "@ivan_petrov hi"
    ents = [Entity("Bold", 0, 12), Entity("Mention", 0, 12), Entity("Mention", 0, 12), Entity("Email", 100, 5)]
    assert scrub(text, ents) == "@U0002 hi"


def test_code_blocks_still_scrubbed(scrub):
    text = "log: user=ivan@x.io ip=10.0.0.1"
    assert scrub(text, [Entity("Code", 5, 26)]) == "log: user=<email> ip=<ip>"


def test_empty_text(scrub):
    assert scrub("") == ""
    assert scrub("", [Entity("Mention", 0, 3)]) == ""


# --- titles ---------------------------------------------------------------------------

def test_title_tokens_drop_generic_words():
    assert title_tokens("ООО Ромашка — техподдержка Northwind") == ["Ромашка", "Northwind"]


def test_org_terms_from_titles_suggests_product_name_but_scrubs_it():
    titles = ["Acme x Northwind support", "ООО Ромашка / Northwind", "Northwind — Beta Inc", "Northwind chat Gamma", "Delta"]
    org, candidates = org_terms_from_titles(titles, 0.2)
    assert candidates == ["Northwind"]
    assert org == ["Acme", "Beta", "Delta", "Gamma", "Northwind", "Ромашка"]  # a candidate stays an org term


def test_org_terms_from_titles_never_whitelists_a_client_with_several_chats():
    titles = ["Ромашка support", "Ромашка sales", "Ромашка integration"] + [f"Client{i} support" for i in range(7)]
    org, candidates = org_terms_from_titles(titles, 0.2)
    assert "Ромашка" in org and candidates == ["Ромашка"]  # suggested to the operator, not kept


# --- leak scanner ---------------------------------------------------------------------

def test_scanner_finds_planted_leaks():
    known = Known(
        user_ids=frozenset({123456789, 77}), chat_ids=frozenset({-1001234567890}),
        usernames=frozenset({"ivan_petrov", "ivan"}), phones=frozenset({"79991234567"}),
        names=frozenset({"Петров"}), titles=frozenset({"Ромашка"}), keep_terms=frozenset({"Ivan"}),
    )
    scanner = LeakScanner(known)
    kinds = {l.kind for l in scanner.scan(
        "U0002 (client, Ivan): @ivan_petrov id 123456789 chat 1234567890 tel +7 999 123-45-67 Петрову из Ромашки x@y.io")}
    assert {"user_id", "username", "phone", "name", "title", "email"} <= kinds
    assert not scanner.scan("U0002 (client, Ivan): всё чисто @U0002 <email> 77 W102186 12:30")


def test_scanner_bare_username_only_when_handle_like():
    known = Known(usernames=frozenset({"ivan", "ivan_petrov92"}))
    scanner = LeakScanner(known, regex_rules=False)
    assert not scanner.scan("Ivan wrote")
    assert scanner.scan("ivan_petrov92 wrote")
    assert scanner.scan("@ivan wrote")


def test_scanner_allows_policy_urls():
    scanner = LeakScanner(Known(), url_allowed=lambda u: "docs.ok" in u)
    assert not scanner.scan("https://docs.ok/x")
    assert scanner.scan("https://other/x")


def test_scrubbing_stays_fast_on_hostile_inputs(scrub):
    # Telegram caps a message at 4096 characters; every shape must stay far below a second.
    hostile = [
        "a" * 2000 + "@" + "b" * 2000,
        "+7 999 " * 580,
        "1 " * 2048,
        "0123456789abcdef " * 240,
        "12 34 56 78 90 " * 270,
        "@" * 4096,
        "http://" + "x." * 2000,
    ]
    for text in hostile:
        assert_fast(lambda text=text: scrub(text), label=text[:40])


def test_transliterated_names_and_orgs_are_scrubbed(scrub):
    assert scrub("Petrov, PETROVA, petrovu, Romashka LLC, romashki") == "<name>, <name>, <name>, <org> LLC, <org>"
    from tg_collector.scrub import translit
    assert translit("Щукин-Ёлкин") == "Shchukin-Elkin" and translit("Acme") == "Acme"


def test_cards_are_masked_to_bin():
    from tg_collector.cards import mask_card
    assert mask_card("5105 1051 0510 5100") == "510510**********"
    assert mask_card("5105-1051-0510-510") == "510510*********"
    assert mask_card("4242 42** **** 1234") == "424242**********"
    assert mask_card("424242******1234") == "424242**********"
    assert mask_card("12345") == "<card>"
    s = Scrubber(AnonPolicy(), Roster())
    assert s.scrub("оплатил картой 5105 1051 0510 5100, спасибо") == "оплатил картой 510510********** , спасибо".replace(" ,", ",")


def test_known_bins_catch_typos_and_hand_masks():
    policy = AnonPolicy(card_bins=("424242", "400000"))
    s = Scrubber(policy, Roster())
    # Wrong checksum (typo) but a known BIN: still masked.
    assert s.scrub("карта 4242 4212 3456 7891 не работает") == "карта 424242********** не работает"
    # Already masked by hand, dashes, x-es: normalised to the same shape.
    assert s.scrub("карта 4242-42xx-xxxx-1234 и 400000 ** **** 9876") == "карта 424242********** и 400000**********"
    # Unknown BIN with a failing checksum is not a card (an order number, say).
    assert s.scrub("заказ 5105 1051 0510 5101") == "заказ 5105 1051 0510 5101"
    # Masked output is not a leak; an unmasked known-BIN card is.
    scanner = LeakScanner(Known(card_bins=frozenset(policy.card_bins)))
    assert not scanner.scan("карта 424242********** ок")
    assert scanner.scan("карта 4242421234567891")


def test_card_separators_masks_and_lengths():
    bins = ("424242",)
    s = Scrubber(AnonPolicy(card_bins=bins), Roster())
    scanner = LeakScanner(Known(card_bins=frozenset(bins)))
    # A line break is not a separator on purpose: two phones on adjacent lines
    # must not merge into a "card".
    for text in ["4242.4212.3456.7890", "4242\u00a04212\u00a03456\u00a07890", "4242\t4212\t3456\t7890",
                 "4242 42хх хххх 7890", "№4242421234567890", "card:4242-4212-3456-7890"]:
        out = s.scrub(text)
        assert "424242**********" in out and not any(c.isdigit() for c in out.split("424242")[-1]), (text, out)
        assert not scanner.scan(out), (text, out)
    # A Luhn-valid card followed by unrelated digits: only the card is masked.
    assert s.scrub("5105 1051 0510 5100 1234") == "510510********** 1234"
    # 19-digit Maestro (Luhn-valid as a whole) is masked whole.
    assert s.scrub("6011 1111 1111 1111 110") == "601111*************"
    # 15-digit Amex.
    assert s.scrub("3530 111333 30001") == "353011*********"


def test_card_does_not_swallow_expiry_and_iban_survives_id_rules():
    s = Scrubber(AnonPolicy(card_bins=("400000",)), Roster())
    assert s.scrub("карта 4000 0076 5067 1250 12/27 cvv 123") == "карта 400000********** <exp> cvv <cvv>"
    assert s.scrub("5105 1051 0510 5100 12/27") == "510510********** <exp>"
    assert s.scrub("IBAN KZ86125KZT5004100100 и DE89 3704 0044 0532 0130 00") == "IBAN <iban> и <iban>"
    # A bare digit run that only passes Luhn on a prefix is an id, not a card.
    assert s.scrub("tiktok 7123456789012345678") == "tiktok <ad-account>"  # keyword-gated ad id, not a card
    assert s.scrub("трейс 7123456789012345678") == "трейс 7123456789012345678"
    assert s.scrub("act_1234567890123456") == "act_<id>"  # ad account id, not a card


def test_cards_are_recognised_by_shape_not_by_digit_count():
    from tg_collector.cards import find_cards
    bins = ("424242", "400000", "510510")
    s = Scrubber(AnonPolicy(card_bins=bins), Roster())
    scanner = LeakScanner(Known(card_bins=frozenset(bins)))
    untouched = [
        "8 999 123-45-67\n8 999 765-43-21",          # two phones on adjacent lines
        "наши БИНы: 424242 400000 510510",             # a list of BINs
        "заказ 424242 123456 не найден",
        "выписка за 01.01.2026-06.01.2026",
        "5650.07 10591.25 81007.33",
        "коды:\n8459\n1912\n3495\n0042",
        "договор № 12345678901234",                    # 14 digits, Luhn fails
        "md5 5d424242123456789a76b9719d911017c5",
    ]
    for text in untouched:
        assert not find_cards(text, bins), text
    assert s.scrub(untouched[0]) == "<phone>\n<phone>"
    caught = {
        "1500 6011 1111 1111 1117 ок": "1500 601111********** ок",
        "карта 4242  4212  3456  7891 ок": "карта 424242********** ок",
        "карта 4242–4212–3456–7891 ок": "карта 424242********** ок",
        "карта 4242\u20094212\u20093456\u20097891": "карта 424242**********",
        "*4242 4212 3456 0000*": "*424242**********" + "*",
        "карта ４２４２ ４２１２ ３４５６ ００００": "карта 424242**********",
        "карта 4242 42●● ●●●● 1234": "карта 424242**********",
        "14242421234567891": "1424242**********",
        "6011 11** **** 1117 не проходит": "601111********** не проходит",
        "3530 111333 30001": "353011*********",
        "6011 1111 1111 1111 110": "601111*************",
    }
    for text, expected in caught.items():
        out = s.scrub(text)
        assert expected in out, (text, out)
        assert not scanner.scan(out), (text, out)
        assert scanner.scan(text), text


def test_kept_urls_and_text_urls_do_not_carry_cards():
    bins = ("424242",)
    policy = AnonPolicy(card_bins=bins, allow_domains=("acme.com",))
    s = Scrubber(policy, Roster())
    assert s.scrub("see https://acme.com/cards/4242421234567891 pls") == "see https://acme.com/cards/424242********** pls"
    text = "оплата 4242 4212 3456 7891 готово"
    ent = Entity("TextUrl", 0, len(text), url="https://acme.com/pay")
    assert s.scrub(text, [ent]) == "оплата 424242********** готово (https://acme.com/pay)"


def test_bracketed_links_are_consumed_whole_and_never_crash():
    # An IPv6 literal host is one link; a bracketed host that is not an
    # address is rejected by the URL parser and must be hidden, not raise.
    roster = Roster()
    drop = Scrubber(AnonPolicy(), roster)
    keep = Scrubber(AnonPolicy(url_mode="keep"), roster)
    domain = Scrubber(AnonPolicy(url_mode="domain"), roster)
    assert drop.scrub("см http://[::1]:8000/x") == "см <url>"
    assert keep.scrub("см http://[::1]:8000/x") == "см http://[::1]:8000/x"
    assert domain.scrub("см http://[::1]:8000/x http://[abc]/x") == "см <url:[::1]> <url>"
    for s in (drop, keep, domain):
        assert s.scrub("перейдите по http://[ваш-домен]/admin") == "перейдите по <url>"
        assert s.scrub("http://[]/x http://[]") == "<url> <url>"
    assert drop.scrub("http://[abc]/x http://[::1 www.[abc]/x tg://[abc") == "<url> <url> <url> <tg-link>"
    assert drop.scrub("HTTP://[::1]:8000/X") == "<url>"
    assert keep.scrub("http://[2001:db8::1]:443/api http://[abc]/x") == "http://[2001:db8::1]:443/api <url>"
    assert keep.scrub("https://t.me:[abc]/x https://t.me/[abc] t.me/joinchat/[x]") == "<url> <tg-link> <tg-link>"
    assert domain.scrub("http://[fe80::1%25eth0]/x http://[v1.fe80::1]/x") == "<url:[fe80::1%25eth0]> <url:[v1.fe80::1]>"
    assert Scrubber(AnonPolicy(allow_domains=("::1",)), roster).scrub(
        "http://[::1]:8000/x http://[2001:db8::1]/z") == "http://[::1]:8000/x <url>"
    # Entities reach the same parser.
    assert drop.scrub("см http://[abc]/x", [Entity("Url", 3, 14)]) == "см <url>"
    assert keep.scrub("нажмите сюда", [Entity("TextUrl", 8, 4, url="http://[abc")]) == "нажмите сюда"
    assert keep.scrub("нажмите сюда", [Entity("TextUrl", 8, 4, url="http://[::1]:8000/x")]) == "нажмите сюда (http://[::1]:8000/x)"


@pytest.mark.parametrize("text,expected", [
    ("https://acme.com/path?q=[1]", "<url>"),
    ("https://acme.com/a[b]c[d] конец", "<url> конец"),
    ("instagram.com/some_buyer[1]", "<url>"),
    ("curl http://[2001:db8::1]:9000/v1/status вернул E1234", "curl <url> вернул E1234"),
    ("wiki: [ссылка](https://acme.com/x?a=[b]) готово", "wiki: [ссылка](<url>) готово"),
    # A ']' that does not close a group opened inside the link still ends it.
    ("[см. https://acme.com/x] [текст](https://acme.com/y)", "[см. <url>] [текст](<url>)"),
    ("[[https://acme.com/x]]", "[[<url>]]"),
    ("https://acme.com/x] хвост", "<url>] хвост"),
    ("https://acme.com/x]@oleg_support", "<url>]@user"),
    ("https://acme.com/x[ хвост]", "<url> хвост]"),
    ("см http://[::1]:8000/x] потом", "см <url>] потом"),
    ("https://acme.com/x[12.03.2024 10:15]", "<url> 10:15]"),
    ("Иван, [12.03.2024 10:15]\nhttps://acme.com/x", "<name>, [12.03.2024 10:15]\n<url>"),
])
def test_bracket_groups_inside_links(text, expected):
    s = Scrubber(AnonPolicy(), Roster())
    assert s.scrub(text) == expected
    assert LeakScanner(Known()).scan(expected) == []


def test_bracketed_links_in_kept_mode_and_the_scanner():
    keep = Scrubber(AnonPolicy(url_mode="keep"), Roster())
    assert keep.scrub("instagram.com/some_buyer[1]") == "instagram.com/some_buyer[1]"
    assert keep.scrub("https://acme.com/x?u=[ivan@acme.com]&p=+79991234567]") == "https://acme.com/x?u=[<email>]&p=<phone>]"
    # verify's wiring: an unparseable link is never "allowed", so it is reported instead of raising.
    scanner = LeakScanner(Known(), url_allowed=lambda url: keep.url_placeholder(url) == url)
    assert [(l.kind, l.match) for l in scanner.scan("перейдите по http://[ваш-домен]/admin")] == [
        ("url", "http://[ваш-домен]/admin")]
    # A kept IPv6 host is still reported, like a kept IPv4 host.
    kept_all = LeakScanner(Known(), url_allowed=lambda url: True)
    assert [(l.kind, l.match) for l in kept_all.scan("http://[2001:db8::1]:443/api")] == [("ipv6", "2001:db8::1")]
    # Our own placeholders, bracketed or not, are never flagged.
    assert LeakScanner(Known()).scan("<url:[::1]> <url> <url:::1> <url:[fe80::1%25eth0]> <url:[v1.fe80::1]>") == []


def test_bracketed_links_stay_fast(scrub):
    shapes = ["http://" + "[a]" * 1300, "http://" + "[" * 4000, "http://[" + "a" * 4000, "http://" + "[[a]]" * 800,
              "http://x" + "]" * 4000, "[a]" * 1365, "http://x/" + ("[" + "a" * 100) * 40]
    scanner = LeakScanner(Known())
    for text in shapes:
        assert_fast(lambda text=text[:4096]: (scrub(text), scanner.scan(text)), label=text[:40])
