"""The vocabulary layer: inflection classes, ё/е, adjectival and short
surnames, underscores, product words in chat titles, scanner symmetry."""


from conftest import assert_fast
from tg_collector.config import AnonPolicy
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber, _term_pattern, org_terms_from_titles, title_tokens


def scrub_with(**roster):
    return Scrubber(AnonPolicy(), Roster(**roster)).scrub


def test_adjectival_and_fleeting_vowel_surnames():
    s = scrub_with(person_terms=("Ковальский", "Кравец", "Заяц"))
    assert s("у Ковальского, Ковальскому, Ковальская, Ковальским, Kovalsky, Kovalskiy, Кравца, Kravtsa, Зайца") == \
        "у <name>, <name>, <name>, <name>, <name>, <name>, <name>, <name>, <name>"
    assert s("ошибка 05, версия 1.2.3, тикет #12345, кузнец") == "ошибка 05, версия 1.2.3, тикет #12345, кузнец"
    keep = Scrubber(AnonPolicy(), Roster(person_terms=("Толстой",), keep_terms=("толстый",))).scrub
    assert keep("толстый файл, Толстого") == "толстый файл, <name>"


def test_yo_and_ye_spellings_are_equivalent():
    s = scrub_with(person_terms=("Ковалёв", "Семёнова"))
    assert s("Ковалев, Ковалева, Семенова, Семеновой, КОВАЛЕВ, Kovalyov, Semyonov, Ковалёв") == ", ".join(["<name>"] * 8)
    assert scrub_with(person_terms=("Ковалев",))("Ковалёв") == "<name>"
    assert Scrubber(AnonPolicy(), Roster(person_terms=("Ковалёв",), keep_terms=("Ковалев",))).scrub("Ковалёв") == "Ковалёв"
    assert s("ошибка E-4021, версия 2.3.1, тикет #4471, семь семян, ковка") == "ошибка E-4021, версия 2.3.1, тикет #4471, семь семян, ковка"
    assert LeakScanner(Known(names=frozenset({"Ковалёв"})), regex_rules=False).scan("Ковалев")


def test_multi_word_terms_inflect_per_word():
    assert scrub_with(person_terms=("Иван Петров",))("спросите Ивана Петрова, Ivana Petrova, Ivan  Petrov, Иванов Петров") == \
        "спросите <name>, <name>, <name>, <name>"
    assert scrub_with(person_terms=("Alex from Payments",))("payments Alex, Alex from Payments") == "payments Alex, <name>"


def test_short_surnames():
    s = scrub_with(person_terms=("Ким", "Цой", "Пак", "Тен", "Ли"))
    assert s("Ким, Кима, Киму, Кимом, Цой, Цоя, Цою, Пак, Паку, Тена, г-н Ли") == ", ".join(["<name>"] * 10) + ", г-н Ли"
    assert s("пакет, пакеты, тенге, тень, кимоно, ханой, тендер") == "пакет, пакеты, тенге, тень, кимоно, ханой, тендер"
    assert LeakScanner(Known(names=frozenset({"Ким"})), regex_rules=False).scan("Кима")


def test_underscores_are_word_boundaries():
    s = Scrubber(AnonPolicy(), Roster(by_username={"ivan_petrov": "U0002"}, person_terms=("Петров",), org_terms=("Ромашка",),
                                      keep_terms=("Northwind",))).scrub
    assert s("Договор_Ромашка.pdf scan_ivan_petrov.pdf Петров_ИП_счет.pdf Northwind_export.log romashka_export.log") == \
        "Договор_<org>.pdf scan_@U0002.pdf <name>_ИП_счет.pdf Northwind_export.log <org>_export.log"
    assert scrub_with(org_terms=("Bank", "Pay"))("ERR_BANK_TIMEOUT PAY_DECLINED_05 error_code=PAY_004 order_id=987654 bank pay") == \
        "ERR_BANK_TIMEOUT PAY_DECLINED_05 error_code=PAY_004 order_id=987654 <org> <org>"
    sc = LeakScanner(Known(titles=frozenset({"Ромашка", "Bank"})), regex_rules=False)
    assert [l.kind for l in sc.scan("Договор_Ромашка.pdf")] == ["title"] and sc.scan("ERR_BANK_TIMEOUT") == []


def test_closed_inflection_class_spares_homographs():
    s = scrub_with(person_terms=("Марк", "Лист", "Bank", "Card", "Support", "Мороз", "Волк"))
    assert s("маркет, маркетинг, market, marked, listing, listed, banking, carded, supported") == \
        "маркет, маркетинг, market, marked, listing, listed, banking, carded, supported"
    assert s("Марка, Листом, banks, cards, морозы, волком") == ", ".join(["<name>"] * 6)
    s2 = scrub_with(person_terms=("Ника", "Максим", "Света", "Люба", "Bill", "Виктор", "Acme"))
    assert s2("никаких, максимум, светлая, billing, Виктория") == "никаких, максимум, светлая, billing, Виктория"
    assert s2("Нике, Максима, Свете, Любу, bills, Виктора, Acmes") == ", ".join(["<name>"] * 7)


def test_existing_inflection_expectations_still_hold():
    s = Scrubber(AnonPolicy(), Roster(person_terms=("Петров", "Smith"), org_terms=("Ромашка", "Acme"), keep_terms=("Northwind",))).scrub
    assert s("Петров и Петрову, у Ромашки, Ромашкой, Acme, Mr. Smith") == "<name> и <name>, у <org>, <org>, <org>, Mr. <name>"
    assert s("Petrov, PETROVA, petrovu, Romashka LLC, romashki") == "<name>, <name>, <name>, <org> LLC, <org>"


def test_product_words_in_chat_titles_are_not_org_terms():
    assert title_tokens("Ромашка — карты") == ["Ромашка"]
    assert title_tokens("Лютик x Northwind: интеграция API") == ["Лютик", "Northwind"]
    assert org_terms_from_titles(["Ромашка сервис", "Василёк — карты", "Одуванчик / Платежи"], 0.2)[0] == ["Василёк", "Одуванчик", "Ромашка"]
    assert title_tokens("acme support") == ["acme"] and title_tokens("ВТБ чат") == ["ВТБ"]


def test_scanner_shares_the_vocabulary_pattern():
    sc = LeakScanner(Known(names=frozenset({"Ковальский", "Кравец", "Заяц", "Ковалёв", "Ким"}), titles=frozenset({"Ромашка"})),
                     regex_rules=False)
    assert sorted(l.match for l in sc.scan("карта Ковальского, Kovalsky, Кравца, Зайца, Ковалев, Кима, Договор_Ромашка.pdf")) == \
        sorted(["Ковальского", "Kovalsky", "Кравца", "Зайца", "Ковалев", "Кима", "Ромашка"])


def test_term_pattern_stays_fast_with_a_large_roster():
    rx = _term_pattern([f"Фамилия{i}" for i in range(500)] + [f"Орг{i} Групп{i}" for i in range(100)])
    text = ("Фамилия12 сказал Орг3 Групп3 работает " * 100)[:4096]
    assert len(rx.findall(text)) >= 100
    assert_fast(lambda: rx.findall(text), label="large roster")
