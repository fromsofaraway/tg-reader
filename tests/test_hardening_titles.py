"""Chat titles as organisation vocabulary: frequent title words are only
suggested for keep_terms (never kept by a guess), a known person's name is
never suggested, merged legacy groups contribute their old title, and
two-character letter+digit org names ("Z9") are scrubbed. Every rule is
checked in both directions: the raw form is scrubbed and flagged by verify,
product knowledge stays byte-identical and the scanner stays silent on it."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from tg_collector.anonymize import Mapping, anonymize, display_name, vocabulary
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import write_dataset
from tg_collector.model import KIND_GROUP, KIND_SUPERGROUP, SENDER_USER, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber, org_terms_from_titles, title_tokens
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1001, first_name="Олег", last_name="Северов", username="oleg_support")
SALES = RawUser(id=1002, first_name="Анна", last_name="Смирнова", username="anna_sales")
CLIENT = RawUser(id=200001, first_name="Ivan")
OUTPUT = Output(timezone="Europe/Berlin")

BIG_CLIENT = ["Ромашка support", "Ромашка sales", "Ромашка integration"] + [f"Client{i} support" for i in range(7)]
PRODUCT_EVERYWHERE = [f"Northwind x Client{i}" for i in range(10)]
SURNAME_TITLES = ["Acme Ltd / Смирнова", "Ромашка / Смирнова", "Beta / Смирнова"] + [f"Client{i} support" for i in range(7)]

# Every placeholder the scrubber writes: the scanner must never flag one.
PLACEHOLDERS = ("<email> <phone> <url> <tg-link> <ip> <iban> <token> <name> <org> @user <id> <redacted> <inn> "
                "<ogrn> <snils> <account> <passport> <domain> @U0042 C0001 424242********** <card> <cvv> <otp> "
                "<password> <wallet> <seed-phrase>")


def titled_store(tmp_path, titles, text, users=(ME, SALES)):
    """One supergroup per title; a client (its own user per chat) writes ``text`` in each."""
    store = RawStore(tmp_path / "raw")
    store.set_me_id(ME.id)
    clients = [RawUser(id=200000 + i, first_name="Ivan") for i in range(len(titles))]
    store.put_users([*users, *clients])
    member_ids = tuple(u.id for u in users)
    store.put_chats([RawChat(id=-1001000000100 - i, kind=KIND_SUPERGROUP, title=t,
                             participant_ids=(*member_ids, clients[i].id)) for i, t in enumerate(titles)])
    for i, c in enumerate(clients):
        store.append_messages(-1001000000100 - i, [RawMessage(
            chat_id=-1001000000100 - i, id=1, date=T0 + timedelta(minutes=i), sender_id=c.id,
            sender_kind=SENDER_USER, text=text)])
    return store


def chats_store(tmp_path, chats, texts, users=(ME,)):
    """Explicit chats; ``texts`` maps a raw chat id to the client's messages there."""
    store = RawStore(tmp_path / "raw")
    store.set_me_id(ME.id)
    store.put_users([*users, CLIENT])
    store.put_chats(chats)
    mid = 0
    for cid, lines in texts.items():
        msgs = []
        for text in lines:
            mid += 1
            msgs.append(RawMessage(chat_id=cid, id=mid, date=T0 + timedelta(minutes=mid), sender_id=CLIENT.id,
                                   sender_kind=SENDER_USER, text=text))
        store.append_messages(cid, msgs)
    return store


def run(tmp_path, store, policy=AnonPolicy(), roles=None):
    ds = anonymize(store, Mapping(tmp_path / "m.json"), roles or Roles.build(ME.id, sales=["@anna_sales"]), policy)
    out = tmp_path / "dataset"
    write_dataset(ds, out, OUTPUT, {})
    return ds, out


def texts(ds):
    return {m.text for m in ds.messages}


def dataset_files_text(out):
    return "\n".join(p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file())


def plant(out, text):
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": text}, ensure_ascii=False) + "\n")


# --- frequent title words are suggested, never kept by a guess ------------------

def test_client_with_several_chats_is_scrubbed_and_absent_from_every_file(tmp_path):
    store = titled_store(tmp_path, BIG_CLIENT, "у Ромашки проблема, Client0 тоже")
    ds, out = run(tmp_path, store)
    assert texts(ds) == {"у <org> проблема, <org> тоже"}
    assert ds.private["keep_terms_suggested"] == ["Ромашка"] and "Ромашка" in ds.private["org_terms_scrubbed"]
    assert "generic_title_terms_kept" not in ds.notes
    assert "Ромашк" not in dataset_files_text(out)  # manifest.json included
    assert verify(out, store, AnonPolicy(), tmp_path / "v.json").ok


def test_title_only_client_name_never_reaches_the_manifest(tmp_path):
    store = titled_store(tmp_path, BIG_CLIENT, "привет, есть вопрос")
    ds, out = run(tmp_path, store)
    assert texts(ds) == {"привет, есть вопрос"}
    assert "Ромашк" not in dataset_files_text(out)
    assert "Ромашка" not in json.dumps(ds.notes, ensure_ascii=False)


def test_verify_hunts_frequent_title_words(tmp_path):
    store = titled_store(tmp_path, BIG_CLIENT, "ok")
    _, out = run(tmp_path, store)
    known = known_from_store(store, AnonPolicy())
    assert "Ромашка" in known.titles and "Ромашка" not in known.keep_terms
    assert verify(out, store, AnonPolicy(), tmp_path / "v0.json").ok
    plant(out, "planted: у Ромашки проблема")
    report = verify(out, store, AnonPolicy(), tmp_path / "v.json")
    assert not report.ok and any(l.kind == "title" and l.match == "Ромашки" for l in report.leaks)


def test_custom_terms_beat_title_frequency(tmp_path):
    policy = AnonPolicy(custom_terms=("Ромашка",))
    ds, _ = run(tmp_path, titled_store(tmp_path, BIG_CLIENT, "у Ромашки проблема"), policy)
    assert texts(ds) == {"у <org> проблема"}
    assert ds.private["keep_terms_suggested"] == []  # a blacklisted word is never offered for the whitelist


def test_custom_terms_win_even_when_the_word_is_in_every_title(tmp_path):
    titles = ["Ромашка support", "Ромашка sales", "Ромашка integration"]
    policy = AnonPolicy(generic_title_share=1.0, custom_terms=("Ромашка",))
    ds, _ = run(tmp_path, titled_store(tmp_path, titles, "у Ромашки проблема, ERR_ROMASHKA_TIMEOUT"), policy)
    assert texts(ds) == {"у <org> проблема, ERR_ROMASHKA_TIMEOUT"}


def test_display_name_checker_obeys_custom_terms_too(tmp_path):
    shop = RawUser(id=1003, first_name="Ромашка Support")
    store = titled_store(tmp_path, BIG_CLIENT, "ok", users=(ME, SALES, shop))
    vocab = vocabulary(store, AnonPolicy(custom_terms=("Ромашка",)))
    assert vocab.kept_names[shop.id] == ""


def test_product_name_is_scrubbed_and_suggested_until_configured(tmp_path):
    bot = RawUser(id=300001, first_name="Northwind Bot", username="northwind_bot", is_bot=True)
    store = titled_store(tmp_path, PRODUCT_EVERYWHERE, "Northwind не отвечает, Client3 ждёт, ERR_NORTHWIND_TIMEOUT",
                         users=(ME, SALES, bot))
    ds, out = run(tmp_path, store)
    # Over-scrub until the operator confirms the word, never a leak.
    assert texts(ds) == {"<org> не отвечает, <org> ждёт, ERR_NORTHWIND_TIMEOUT"}
    assert ds.private["keep_terms_suggested"] == ["Northwind"]
    assert vocabulary(store, AnonPolicy()).kept_names[bot.id] == ""
    assert verify(out, store, AnonPolicy(), tmp_path / "v.json").ok


def test_product_name_in_keep_terms_is_kept_and_not_suggested_again(tmp_path):
    bot = RawUser(id=300001, first_name="Northwind Bot", username="northwind_bot", is_bot=True)
    policy = AnonPolicy(keep_terms=("Northwind",))
    store = titled_store(tmp_path, PRODUCT_EVERYWHERE, "Northwind не отвечает, Client3 ждёт, версия 2.15.3, E1042",
                         users=(ME, SALES, bot))
    ds, out = run(tmp_path, store, policy)
    assert texts(ds) == {"Northwind не отвечает, <org> ждёт, версия 2.15.3, E1042"}
    assert ds.private["keep_terms_suggested"] == [] and "Northwind" not in ds.private["org_terms_scrubbed"]
    assert vocabulary(store, policy).kept_names[bot.id] == "Northwind Bot"
    known = known_from_store(store, policy)
    assert "Northwind" in known.keep_terms and "Client3" in known.titles
    assert LeakScanner(known).scan("Northwind не отвечает, версия 2.15.3, E1042") == []
    assert verify(out, store, policy, tmp_path / "v.json").ok


@pytest.mark.parametrize("titles, text, expected", [
    (["Ромашка support"] * 3 + [f"Client{i} support" for i in range(12)], "у Ромашки проблема", "у <org> проблема"),
    (["Ромашка support"] * 4 + [f"Client{i} support" for i in range(16)], "у Ромашки проблема", "у <org> проблема"),
    (["Romashka support", "Romashka sales", "Romashka integration"], "Romashka has an issue", "<org> has an issue"),
    (["Ромашка — support", "[Ромашка] integration", "РОМАШКА sales"], "у\nРомашки проблема, ООО «Ромашка» ждёт",
     "у\n<org> проблема, ООО «<org>» ждёт"),
    (BIG_CLIENT, "Romashka тоже, ромашки нет", "<org> тоже, <org> нет"),
])
def test_big_client_is_scrubbed_in_every_shape(tmp_path, titles, text, expected):
    ds, _ = run(tmp_path, titled_store(tmp_path, titles, text))
    assert texts(ds) == {expected}


@pytest.mark.parametrize("policy, reported", [
    # Under "domain" a host that reads as the client is hidden altogether, so
    # nothing is left for the scanner to find.
    (AnonPolicy(url_mode="domain"), set()),
    # Known false positive, fixed by the suggested keep_terms entry: the
    # scanner hunts the product name inside a kept link or a longer keep term.
    (AnonPolicy(allow_domains=("northwind.example",)), {("title", "northwind")}),
    (AnonPolicy(keep_terms=("Northwind Pay",)), {("title", "northwind")}),
])
def test_unconfigured_product_name_is_reported_by_verify_until_kept(tmp_path, policy, reported):
    store = titled_store(tmp_path, PRODUCT_EVERYWHERE, "см. https://northwind.example/docs, Northwind Pay упал, Northwind тоже")
    ds, out = run(tmp_path / "a", store, policy)
    assert "Northwind тоже" not in "\n".join(texts(ds))
    report = verify(out, store, policy, tmp_path / "v.json")
    assert {(l.kind, l.match.lower()) for l in report.leaks} == reported
    fixed = AnonPolicy(url_mode=policy.url_mode, allow_domains=policy.allow_domains,
                       keep_terms=(*policy.keep_terms, "Northwind"))
    ds, out = run(tmp_path / "b", store, fixed)
    assert "Northwind тоже" in "\n".join(texts(ds))
    assert verify(out, store, fixed, tmp_path / "v2.json").ok


@pytest.mark.parametrize("share", [0.2, 1.0])
def test_share_only_changes_the_suggestion(tmp_path, share):
    ds, _ = run(tmp_path, titled_store(tmp_path, BIG_CLIENT, "у Ромашки проблема"), AnonPolicy(generic_title_share=share))
    assert texts(ds) == {"у <org> проблема"}
    assert ds.private["keep_terms_suggested"] == (["Ромашка"] if share == 0.2 else [])


def test_frequent_generic_word_is_an_org_term_until_kept(tmp_path):
    titles = ["Acme VIP", "Beta VIP", "Gamma VIP", "Delta"]
    store = titled_store(tmp_path, titles, "VIP клиент, тикет #4471")
    ds, _ = run(tmp_path / "a", store)
    assert texts(ds) == {"<org> клиент, тикет #4471"} and ds.private["keep_terms_suggested"] == ["VIP"]
    policy = AnonPolicy(keep_terms=("VIP",))
    ds, _ = run(tmp_path / "b", store, policy)
    assert texts(ds) == {"VIP клиент, тикет #4471"}
    assert LeakScanner(known_from_store(store, policy)).scan("VIP клиент, тикет #4471") == []


@pytest.mark.parametrize("policy", [AnonPolicy(keep_chat_titles=True), AnonPolicy(scrub_chat_titles=False)])
def test_title_vocabulary_off_keeps_text_and_suggests_nothing(tmp_path, policy):
    ds, _ = run(tmp_path, titled_store(tmp_path, BIG_CLIENT, "у Ромашки проблема"), policy)
    assert texts(ds) == {"у Ромашки проблема"} and ds.private["keep_terms_suggested"] == []


# --- a known person's name is never suggested for keep_terms --------------------

def test_surname_in_many_titles_is_scrubbed_audited_and_not_suggested(tmp_path):
    store = titled_store(tmp_path, SURNAME_TITLES, "Смирнова, Смирновой передайте. Анна Смирнова тоже.")
    ds, out = run(tmp_path, store)
    joined = "\n".join(texts(ds))
    assert "Смирнов" not in joined and "передайте" in joined
    assert ds.private["keep_terms_suggested"] == []
    assert "Смирнова" in ds.private["org_terms_scrubbed"]
    assert "Смирнов" not in dataset_files_text(out)
    assert verify(out, store, AnonPolicy(), tmp_path / "v.json").ok
    known = known_from_store(store, AnonPolicy())
    assert "Смирнова" in known.names and "Смирнова" not in known.keep_terms
    plant(out, "Смирновой передайте")
    report = verify(out, store, AnonPolicy(), tmp_path / "v2.json")
    assert not report.ok and {l.match for l in report.leaks} == {"Смирновой"}


def test_latin_title_spelling_of_a_surname_is_not_suggested(tmp_path):
    titles = ["Acme Ltd / Smirnova", "Ромашка / Smirnova", "Beta / Smirnova"] + [f"Client{i} support" for i in range(7)]
    ds, _ = run(tmp_path, titled_store(tmp_path, titles, "Smirnova и Смирнова передайте"))
    assert texts(ds) == {"<org> и <name> передайте"}
    assert ds.private["keep_terms_suggested"] == []


def test_yo_latin_spelling_of_a_surname_is_not_suggested(tmp_path):
    semyonova = RawUser(id=1002, first_name="Анна", last_name="Семёнова", username="anna_sales")
    titles = ["Acme Ltd / Semyonova", "Ромашка / Semyonova", "Beta / Semyonova"] + [f"Client{i} support" for i in range(7)]
    ds, _ = run(tmp_path, titled_store(tmp_path, titles, "Semyonova и Семёнова передайте", users=(ME, semyonova)))
    assert texts(ds) == {"<org> и <name> передайте"}
    assert ds.private["keep_terms_suggested"] == []


def test_inflected_title_form_of_a_surname_is_not_suggested(tmp_path):
    titles = ["Alpha / Смирновой", "Beta / Смирновой", "Gamma / Смирновой"] + [f"Client{i} support" for i in range(7)]
    ds, _ = run(tmp_path, titled_store(tmp_path, titles, "Смирнова, Смирновой передайте"))
    assert "Смирнов" not in "\n".join(texts(ds))
    assert ds.private["keep_terms_suggested"] == []


def test_free_text_and_full_mode_surnames_are_not_suggested(tmp_path):
    free_text = RawUser(id=1002, first_name="Анна Смирнова", username="anna_sales")
    store = titled_store(tmp_path, SURNAME_TITLES, "Смирнова, Смирновой передайте", users=(ME, free_text))
    ds, _ = run(tmp_path / "a", store)
    assert texts(ds) == {"<org>, <org> передайте"} and ds.private["keep_terms_suggested"] == []
    full = AnonPolicy(name_mode="full")
    store = titled_store(tmp_path / "b", SURNAME_TITLES, "Смирнова, Смирновой передайте")
    ds, _ = run(tmp_path / "b", store, full)
    assert texts(ds) == {"<org>, <org> передайте"} and ds.private["keep_terms_suggested"] == []
    # Same as below the threshold: a full name with a scrubbed word is dropped entirely.
    assert vocabulary(store, full).kept_names[SALES.id] == ""


def test_first_name_in_titles_is_suggested_only_when_first_names_are_kept(tmp_path):
    titles = ["Ромашка / Анна", "Лютик / Анна", "Beta / Анна"] + [f"Client{i} support" for i in range(7)]
    store = titled_store(tmp_path, titles, "Анна, передайте Анне")
    ds_none, _ = run(tmp_path / "none", store, AnonPolicy(name_mode="none"))
    assert "Анн" not in ds_none.messages[0].text and ds_none.private["keep_terms_suggested"] == []
    ds_first, _ = run(tmp_path / "first", store)
    assert ds_first.messages[0].text == "<org>, передайте <org>"  # a title word until it is kept
    assert ds_first.private["keep_terms_suggested"] == ["Анна"]  # first names are kept by policy in first mode


def test_product_word_is_still_suggested_next_to_people(tmp_path):
    titles = ["Northwind / Acme Ltd", "Northwind / Ромашка", "Northwind / Beta"] + [f"Northwind Client{i}" for i in range(7)]
    wind = RawUser(id=1004, first_name="Иван", last_name="Wind")
    nort = RawUser(id=1005, first_name="Пётр", last_name="Норт")
    staff = RawUser(id=1006, first_name="Northwind", last_name="Support")
    store = titled_store(tmp_path, titles, "Northwind release 2.3 is out, Смирнова в курсе",
                         users=(ME, SALES, wind, nort, staff))
    ds, _ = run(tmp_path / "a", store)
    assert ds.private["keep_terms_suggested"] == ["Northwind"]
    policy = AnonPolicy(keep_terms=("Northwind",))
    store = titled_store(tmp_path / "b", titles, "Northwind release 2.3 is out, Смирнова в курсе")
    ds, out = run(tmp_path / "b", store, policy)
    assert texts(ds) == {"Northwind release 2.3 is out, <name> в курсе"}
    assert verify(out, store, policy, tmp_path / "v.json").ok


def test_word_that_merely_contains_a_surname_is_still_suggested(tmp_path):
    petrov = RawUser(id=1004, first_name="Иван", last_name="Петров")
    titles = ["Петровка / Acme Ltd", "Петровка / Ромашка", "Петровка / Beta"] + [f"Client{i} support" for i in range(7)]
    ds, _ = run(tmp_path, titled_store(tmp_path, titles, "ok", users=(ME, SALES, petrov)))
    assert ds.private["keep_terms_suggested"] == ["Петровка"]


def test_shared_login_named_after_the_product_blocks_the_suggestion_under_none_mode(tmp_path):
    # Known cost: under name_mode = "none" the first-name field is scrubbed
    # word by word, so a shared "Northwind Support" login makes the product
    # word look like a name. It is still listed among the scrubbed title words.
    login = RawUser(id=1006, first_name="Northwind Support", username="nw_help")
    store = titled_store(tmp_path, PRODUCT_EVERYWHERE, "Northwind release 2.3 is out", users=(ME, SALES, login))
    ds, _ = run(tmp_path / "none", store, AnonPolicy(name_mode="none"))
    assert ds.private["keep_terms_suggested"] == [] and "Northwind" in ds.private["org_terms_scrubbed"]
    ds, _ = run(tmp_path / "kept", store, AnonPolicy(name_mode="none", keep_terms=("Northwind",)))
    assert texts(ds) == {"Northwind release 2.3 is out"}
    ds, _ = run(tmp_path / "first", store)
    assert ds.private["keep_terms_suggested"] == ["Northwind"]


@pytest.mark.parametrize("users, titles, text", [
    # Swapped profile fields: the first-name field holds the surname.
    ((ME, RawUser(id=1002, first_name="Смирнова", last_name="Анна", username="anna_sales"),
      RawUser(id=1003, first_name="Анна")), SURNAME_TITLES, "Смирнова, Смирновой передайте"),
    # Lower-case, punctuated titles and an upper-case mention.
    ((ME, SALES), ["alpha — смирнова:", "beta (смирнова)", "gamma, смирнова!"], "СМИРНОВА, Смирновой передайте"),
    # A Latin profile with Latin titles.
    ((ME, RawUser(id=1002, first_name="Anna", last_name="Smirnova", username="anna_sales")),
     ["Alpha / Smirnova", "Beta / Smirnova", "Gamma / Smirnova"], "Smirnova, ask Smirnova please"),
])
def test_other_surname_shapes_are_not_suggested(tmp_path, users, titles, text):
    ds, _ = run(tmp_path, titled_store(tmp_path, titles, text, users=users))
    assert "mirnov" not in "\n".join(texts(ds)).lower() and "мирнов" not in "\n".join(texts(ds)).lower()
    assert ds.private["keep_terms_suggested"] == []


def test_product_word_in_a_last_name_field_is_not_suggested(tmp_path):
    staff = RawUser(id=1002, first_name="Анна", last_name="Northwind", username="anna_sales")
    titles = [f"Northwind / Client{i}" for i in range(10)]
    text = "Northwind release 2.3 is out, Анна Northwind в курсе"
    store = titled_store(tmp_path, titles, text, users=(ME, staff))
    ds, _ = run(tmp_path / "a", store)
    assert texts(ds) == {"<org> release 2.3 is out, Анна <org> в курсе"}
    assert ds.private["keep_terms_suggested"] == [] and "Northwind" in ds.private["org_terms_scrubbed"]
    ds, out = run(tmp_path / "b", store, AnonPolicy(keep_terms=("Northwind",)))
    # The kept word survives on its own; the full name "Анна Northwind" is a
    # longer known term and goes whole, as verify expects.
    assert texts(ds) == {"Northwind release 2.3 is out, <name> в курсе"}
    assert verify(out, store, AnonPolicy(keep_terms=("Northwind",)), tmp_path / "v.json").ok


def test_keep_terms_beat_custom_terms(tmp_path):
    policy = AnonPolicy(keep_terms=("Смирнова",), custom_terms=("Смирнова",))
    ds, _ = run(tmp_path, titled_store(tmp_path, SURNAME_TITLES, "Смирнова, Смирновой передайте"), policy)
    assert texts(ds) == {"Смирнова, Смирновой передайте"}


def test_operator_keep_term_still_wins_over_a_surname(tmp_path):
    ds, _ = run(tmp_path, titled_store(tmp_path, SURNAME_TITLES, "Смирнова, Смирновой передайте"),
                AnonPolicy(keep_terms=("Смирнова",)))
    assert texts(ds) == {"Смирнова, Смирновой передайте"}  # explicit keep_terms are absolute by design


def test_surname_is_suggested_when_last_names_are_not_scrubbed(tmp_path):
    ds, _ = run(tmp_path, titled_store(tmp_path, SURNAME_TITLES, "Смирнова, Смирновой передайте"),
                AnonPolicy(scrub_last_names=False))
    assert texts(ds) == {"<org>, <org> передайте"}
    assert ds.private["keep_terms_suggested"] == ["Смирнова"]


# --- merged legacy groups contribute their title -------------------------------

ROMASHKA = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка support", participant_ids=(ME.id, CLIENT.id))
BETA = RawChat(id=-1003, kind=KIND_SUPERGROUP, title="Beta support", participant_ids=(ME.id, CLIENT.id))


def legacy(title, migrated_to=ROMASHKA.id):
    return RawChat(id=-2, kind=KIND_GROUP, title=title, migrated_to=migrated_to)


def test_legacy_group_title_feeds_org_terms(tmp_path):
    chats = [ROMASHKA, legacy("Лютик support (old)"), BETA]
    lines = {-2: ["мы Лютик", "мы из Лютика"],
             -1001: ["Лютик стал Ромашкой", "Лютиком довольны, ticket #4471", "the old version, ticket #4471",
                     "старый Лютик", "мы\nЛютик"],
             -1003: ["y"]}
    store = chats_store(tmp_path, chats, lines)
    assert vocabulary(store, AnonPolicy()).org_terms == ("Beta", "Лютик", "Ромашка")  # "(old)" is a marker
    ds, out = run(tmp_path, store)
    assert texts(ds) == {"мы <org>", "мы из <org>", "<org> стал <org>", "<org> довольны, ticket #4471",
                         "the old version, ticket #4471", "старый <org>", "мы\n<org>", "y"}
    known = known_from_store(store, AnonPolicy())
    assert known.titles == frozenset({"Beta", "Лютик", "Ромашка"})
    assert {l.match for l in LeakScanner(known).scan("Лютик стал Ромашкой")} == {"Лютик", "Ромашкой"}
    assert LeakScanner(known).scan("the old version, ticket #4471, <org> стал <org>") == []
    assert verify(out, store, AnonPolicy(), tmp_path / "v.json").ok
    plant(out, "мы Лютик")
    assert not verify(out, store, AnonPolicy(), tmp_path / "v2.json").ok


def test_legacy_title_is_ignored_when_titles_are_kept(tmp_path):
    store = chats_store(tmp_path, [ROMASHKA, legacy("Лютик support"), BETA], {-2: ["мы Лютик"], -1001: ["Лютик стал Ромашкой"]})
    ds, _ = run(tmp_path, store, AnonPolicy(keep_chat_titles=True))
    assert texts(ds) == {"мы Лютик", "Лютик стал Ромашкой"}


def test_legacy_title_in_keep_terms_stays(tmp_path):
    store = chats_store(tmp_path, [ROMASHKA, legacy("Лютик support"), BETA], {-2: ["мы Лютик"], -1001: ["Лютик стал Ромашкой"]})
    ds, _ = run(tmp_path, store, AnonPolicy(keep_terms=("Лютик",)))
    assert texts(ds) == {"мы Лютик", "Лютик стал <org>"}


@pytest.mark.parametrize("title", ["Ромашка support", "Ромашка support (legacy)", "Ромашка support (archived)", ""])
def test_legacy_title_without_new_words_changes_nothing(tmp_path, title):
    lines = {-2: ["the legacy version"], -1001: ["ticket archived, the old one closed, у Ромашки ок"], -1003: ["Beta"]}
    store = chats_store(tmp_path, [ROMASHKA, legacy(title), BETA], lines)
    assert vocabulary(store, AnonPolicy()).org_terms == ("Beta", "Ромашка")
    ds, _ = run(tmp_path, store)
    assert texts(ds) == {"the legacy version", "ticket archived, the old one closed, у <org> ок", "<org>"}


def test_both_titles_empty_do_not_count_as_a_title(tmp_path):
    empty = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="", participant_ids=(ME.id, CLIENT.id))
    store = chats_store(tmp_path, [empty, legacy(""), BETA], {-2: ["a"], -1001: ["b"], -1003: ["Beta"]})
    assert vocabulary(store, AnonPolicy()).org_terms == ("Beta",)


def test_latin_and_upper_case_legacy_titles(tmp_path):
    store = chats_store(tmp_path, [ROMASHKA, legacy("Lyutik support"), BETA], {-2: ["мы Lyutik", "LYUTIK!"]})
    ds, _ = run(tmp_path / "a", store)
    assert texts(ds) == {"мы <org>", "<org>!"}
    store = chats_store(tmp_path / "b", [ROMASHKA, legacy("РОМАШКА чат"), BETA],
                        {-2: ["РОМАШКА и ромашки", "Ромашке привет", "ERR_ROMASHKA_TIMEOUT romashka"]})
    ds, _ = run(tmp_path / "b", store)
    assert texts(ds) == {"<org> и <org>", "<org> привет", "ERR_ROMASHKA_TIMEOUT <org>"}


def test_legacy_title_is_the_only_source_of_the_client_name(tmp_path):
    primary = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Client 42 support", participant_ids=(ME.id, CLIENT.id))
    store = chats_store(tmp_path, [primary, legacy("Acme Ltd support"), BETA],
                        {-2: ["Acme на связи"], -1001: ["hi from Acme", "Acme moved here"]})
    ds, _ = run(tmp_path, store)
    assert texts(ds) == {"<org> на связи", "hi from <org>", "<org> moved here"}
    assert "Acme" in known_from_store(store, AnonPolicy()).titles


def test_orphan_legacy_group_uses_its_own_title_once(tmp_path):
    orphan = legacy("Лютик support", migrated_to=-1009)  # the supergroup is not in the store
    store = chats_store(tmp_path, [orphan, BETA], {-2: ["мы Лютик"], -1003: ["y"]})
    assert vocabulary(store, AnonPolicy()).org_terms == ("Beta", "Лютик")


def test_placeholder_legacy_title_is_reported_among_scrubbed_words(tmp_path):
    store = chats_store(tmp_path, [ROMASHKA, legacy("Новая группа"), BETA], {-2: ["новая версия вышла"]})
    ds, _ = run(tmp_path, store)
    # Accepted over-scrub, visible to the operator, fixed with keep_terms.
    assert "Новая" in ds.private["org_terms_scrubbed"]
    ds, _ = run(tmp_path / "kept", store, AnonPolicy(keep_terms=("новая",)))
    assert texts(ds) == {"новая версия вышла"}


def test_legacy_peer_counts_once_towards_the_suggestion_threshold(tmp_path):
    chats = [RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка x Northwind", participant_ids=(ME.id, CLIENT.id)),
             legacy("Ромашка x Northwind (old)"),
             RawChat(id=-1003, kind=KIND_SUPERGROUP, title="Beta x Northwind", participant_ids=(ME.id, CLIENT.id)),
             RawChat(id=-1004, kind=KIND_SUPERGROUP, title="Gamma x Лютик", participant_ids=(ME.id, CLIENT.id)),
             RawChat(id=-1005, kind=KIND_SUPERGROUP, title="Delta x Ромашка", participant_ids=(ME.id, CLIENT.id))]
    lines = {-2: ["old Ромашка"], -1001: ["new Ромашка Northwind"], -1003: ["b"], -1004: ["g"], -1005: ["d"]}
    store = chats_store(tmp_path, chats, lines)
    vocab = vocabulary(store, AnonPolicy())
    # Ромашка is in two logical chats (one of them through both peers), Northwind in two.
    assert vocab.keep_term_candidates == ()
    ds, _ = run(tmp_path, store, AnonPolicy(keep_terms=("Northwind",)))
    assert texts(ds) == {"old <org>", "new <org> Northwind", "b", "g", "d"}


def test_legacy_only_occurrence_counts_for_the_suggestion(tmp_path):
    chats = [RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка", participant_ids=(ME.id, CLIENT.id)),
             legacy("Ромашка x Northwind"),
             RawChat(id=-1003, kind=KIND_SUPERGROUP, title="Beta x Northwind", participant_ids=(ME.id, CLIENT.id)),
             RawChat(id=-1004, kind=KIND_SUPERGROUP, title="Gamma x Northwind", participant_ids=(ME.id, CLIENT.id))]
    store = chats_store(tmp_path, chats, {-2: ["a"], -1001: ["b"], -1003: ["c"], -1004: ["d"]})
    assert vocabulary(store, AnonPolicy()).keep_term_candidates == ("Northwind",)


@pytest.mark.parametrize("first_name, text, expected", [
    ("Анна Старая", "пишет Анна Старая, Старая ответила", "пишет <name>, <name> ответила"),
    ("John Legacy", "Legacy replied", "<name> replied"),
    ("Иван Архив", "Архив ответил", "<name> ответил"),
])
def test_migration_markers_are_still_surnames(tmp_path, first_name, text, expected):
    person = RawUser(id=1009, first_name=first_name)
    store = chats_store(tmp_path, [ROMASHKA, BETA], {-1001: [text]}, users=(ME, person))
    surname = first_name.split()[1]
    assert surname in vocabulary(store, AnonPolicy()).person_terms
    assert surname in known_from_store(store, AnonPolicy()).names
    ds, _ = run(tmp_path, store)
    assert texts(ds) == {expected}


# --- two-character organisation names ------------------------------------------

def test_letter_digit_title_tokens_are_org_terms():
    assert title_tokens("Z9 Retail support") == ["Z9", "Retail"]
    assert title_tokens("K7 Airlines") == ["K7", "Airlines"]
    assert title_tokens("M8 Trading support") == ["M8"]  # "Trading" is a generic company-name half
    assert title_tokens("4W support") == ["4W"]
    assert title_tokens("Ж9 Ритейл") == ["Ж9", "Ритейл"]  # Cyrillic Х
    assert org_terms_from_titles(["M8 Northwind support", "Acme Northwind support", "Ромашка Northwind support"], 0.2) \
        == (["Acme", "M8", "Northwind", "Ромашка"], ["Northwind"])
    assert org_terms_from_titles(["Z9 Northwind", "Z9 Acme", "Z9 Ромашка", "Z9 Лютик"], 0.2)[1] == ["Z9"]


@pytest.mark.parametrize("title", [
    "ООО ЗЮ support", "QA chat", "ИП Ян", "Acme v2 support", "Acme L2 support", "Q3 2024", "1С интеграция Acme",
    "Acme H1 2025", "Acme P1 incidents", "4G/5G Acme", "Acme HD", "IT Acme", "Acme QA", "Acme 24/7", "Acme 42",
    "Acme 3D", "Acme 4K", "Acme T1 escalations", "Поддержка Т2 Acme", "Acme 1C", "Лютик x Northwind", "Т-Банк",
    "Acme KZ", "Acme UK", "Acme QR", "Acme ID", "Acme HR", "Acme РФ", "ПО Acme", "Чат по Acme", "Acme of Northwind",
])
def test_plain_short_words_and_product_tokens_are_not_title_tokens(title):
    assert [t for t in title_tokens(title) if len(t) < 3] == []


def test_short_org_terms_are_scrubbed_whole_word_and_spare_constants():
    s = Scrubber(AnonPolicy(), Roster(org_terms=("Z9", "Retail", "K7"))).scrub
    assert s("Z9 просит retail-отчёт по ритейлу. z9_report.pdf; ERR_Z9_LIMIT") == \
        "<org> просит <org>-отчёт по ритейлу. <org>_report.pdf; ERR_Z9_LIMIT"
    product = "Z99, 2Z9, 0z9F, K77, ERR_Z9_LIMIT, Z9_TOKEN, версия v2, тир L2, Q3, 3D secure, 1С, 4K, 5G"
    assert s(product) == product
    assert Scrubber(AnonPolicy(), Roster(org_terms=("X",))).scrub("Лютик x Northwind") == "Лютик x Northwind"
    assert Scrubber(AnonPolicy(), Roster(org_terms=("Z9",), keep_terms=("Z9",))).scrub("Z9 ждёт") == "Z9 ждёт"


def test_cyrillic_letter_digit_org_term_and_display_names():
    assert Scrubber(AnonPolicy(), Roster(org_terms=("Ж9",))).scrub("Ж9 и Zh9, Ж99 нет") == "<org> и <org>, Ж99 нет"
    checker = Scrubber(AnonPolicy(), Roster(org_terms=("Z9",)))
    assert display_name(RawUser(id=7, first_name="Z9 Анна"), "first", checker) == ""
    assert display_name(RawUser(id=8, first_name="Anna", last_name="Z9"), "first", checker) == "Anna"  # first name only
    assert display_name(RawUser(id=8, first_name="Anna", last_name="Z9"), "full", checker) == ""


def test_custom_pattern_workaround_for_short_names_keeps_working():
    policy = AnonPolicy(custom_patterns=(r"(?<![^\W_])Z9(?![^\W_])",))
    scrubbed = Scrubber(policy, Roster()).scrub("Z9 просит отчёт, z9 тоже; Z95 нет")
    assert scrubbed == "<redacted> просит отчёт, <redacted> тоже; Z95 нет"
    assert LeakScanner(Known(), custom_patterns=policy.custom_patterns).scan(scrubbed) == []


def test_two_letter_custom_term_is_honoured_in_both_spellings(tmp_path):
    store = chats_store(tmp_path, [ROMASHKA, BETA], {-1001: ["ЯР ждёт ответа, YaR тоже; ярмарка нет"]})
    ds, out = run(tmp_path, store, AnonPolicy(custom_terms=("ЯР",)))
    assert texts(ds) == {"<org> ждёт ответа, <org> тоже; ярмарка нет"}
    known = known_from_store(store, AnonPolicy(custom_terms=("ЯР",)))
    assert {l.match for l in LeakScanner(known).scan("ЯР ждёт, YaR тоже; ярмарка нет")} == {"ЯР", "YaR"}
    assert verify(out, store, AnonPolicy(custom_terms=("ЯР",)), tmp_path / "v.json").ok


def test_scanner_mirrors_short_org_terms():
    scanner = LeakScanner(Known(titles=frozenset({"Z9", "ЗЮ"})))
    assert {(l.kind, l.match) for l in scanner.scan("Z9 ждёт, ЗЮ и ZYu тоже, Z95 нет")} \
        == {("title", "Z9"), ("title", "ЗЮ"), ("title", "ZYu")}
    scrubbed = Scrubber(AnonPolicy(), Roster(org_terms=("Z9", "ЗЮ"))).scrub("Z9 ждёт, ЗЮ и ZYu тоже, ERR_Z9_LIMIT")
    assert scrubbed == "<org> ждёт, <org> и <org> тоже, ERR_Z9_LIMIT"
    assert scanner.scan(scrubbed) == []
    assert scanner.scan("Z99, 2Z9, 0z9F, ERR_Z9_LIMIT, Z9_TOKEN, версия v2") == []
    wide = LeakScanner(Known(titles=frozenset({"Z9", "K7", "ЯР", "K2", "4D", "Q2", "B1", "M8", "4W"})))
    assert wide.scan(PLACEHOLDERS) == []


def test_two_letter_surname_alone_still_stays():
    s = Scrubber(AnonPolicy(), Roster(person_terms=("Ли", "Иван Ли"))).scrub
    assert s("Ли написал; Иван Ли написал; поговорили ли вы") == "Ли написал; <name> написал; поговорили ли вы"
    assert LeakScanner(Known(names=frozenset({"Ли"}))).scan("Ли написал") == []


def test_short_org_name_from_a_title_end_to_end(tmp_path):
    z9 = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Z9 Retail support", participant_ids=(ME.id, CLIENT.id))
    k7 = RawChat(id=-1003, kind=KIND_SUPERGROUP, title="K7 Airlines / Acme v2", participant_ids=(ME.id, CLIENT.id))
    lines = {-1001: ["Z9 просит retail-отчёт. z9_report.pdf; ERR_Z9_LIMIT"],
             -1003: ["K7 попросили отчёт; k7 ok", "версия v2, тир L2, Q3, 3D secure, 1С, 4K, 5G, заказ #4471"]}
    store = chats_store(tmp_path, [z9, k7], lines)
    ds, out = run(tmp_path, store)
    assert texts(ds) == {"<org> просит <org>-отчёт. <org>_report.pdf; ERR_Z9_LIMIT", "<org> попросили отчёт; <org> ok",
                         "версия v2, тир L2, Q3, 3D secure, 1С, 4K, 5G, заказ #4471"}
    known = known_from_store(store, AnonPolicy())
    assert {"Z9", "K7"} <= known.titles and not {"v2", "V2"} & known.titles
    assert LeakScanner(known).scan("версия v2, тир L2, Q3, 3D secure, 1С, 4K, 5G, заказ #4471") == []
    assert verify(out, store, AnonPolicy(), tmp_path / "v.json").ok
    plant(out, "Z9 снова пишет")
    report = verify(out, store, AnonPolicy(), tmp_path / "v2.json")
    assert not report.ok and any(l.kind == "title" and l.match == "Z9" for l in report.leaks)


# --- generic company-name halves and fintech nouns are not org terms -----------

GENERIC_TITLES = ["ООО Ромашка Групп", "Acme Pay", "Василёк Банк", "Одуванчик Технологии", "Лютик Медиа",
                  "Northwind x Colibri Store", "Лютик Сервиса", "Acme Card", "Ромашка Wallet", "Гербера Перевод",
                  "Ирис Кошелёк", "Сирень Обмен", "Пион Онлайн", "Колокольчик Процессинг"]


@pytest.mark.parametrize("title,tokens", [
    ("ООО Ромашка Групп", ["Ромашка"]),
    ("Acme Pay", ["Acme"]),
    ("Василёк Банк", ["Василёк"]),
    ("Одуванчик Технологий", ["Одуванчик"]),
    ("Northwind x Colibri Store", ["Northwind", "Colibri"]),
    ("Лютик Сервиса / Карт", ["Лютик"]),
    ("Ромашка Банк / Northwind", ["Ромашка", "Northwind"]),
    ("Northwind x Альфа Групп", ["Northwind", "Альфа"]),
    ("Acme Pay | Northwind", ["Acme", "Northwind"]),
    ("Чат поддержки Ромашка Сервис", ["Ромашка"]),
    ("Группа компаний Одуванчик", ["Одуванчик"]),
    ("Чат клиентов Ромашки", ["Ромашки"]),
    ("Поддержка клиентов Ромашка", ["Ромашка"]),
    ("Отдел выплат Acme", ["Acme"]),
    ("Служба поддержки Ромашка", ["Ромашка"]),
    ("Магазины Лютик / магазина", ["Лютик"]),
    ("Crypto Exchange Support", []),  # residual: an all-generic title yields no org term
    ("Stores", []),
    ("ООО Ромашка — техподдержка Northwind", ["Ромашка", "Northwind"]),
    # A surname-shaped form of a generic stem still names somebody.
    ("Туров и партнёры", ["Туров"]),
    ("Туров Олег — Ромашка", ["Туров", "Олег", "Ромашка"]),
    ("Банков Консалтинг", ["Банков"]),
    ("ИП Банков — выплаты", ["Банков"]),
    ("Казина Анна", ["Казина", "Анна"]),
    ("Кошельков / Acme", ["Кошельков", "Acme"]),
    ("Тестова Анна", ["Тестова", "Анна"]),
    ("Софтин Олег", ["Софтин", "Олег"]),
    ("Story", ["Story"]),
    ("Testa", ["Testa"]),
    ("Cloudy Payoneer Groupon", ["Cloudy", "Payoneer", "Groupon"]),
])
def test_generic_title_words_in_every_case_form(title, tokens):
    assert title_tokens(title) == tokens


def test_generic_title_words_stay_in_text_and_names_still_go():
    org, suggested = org_terms_from_titles(GENERIC_TITLES, 0.2)
    assert org == ["Acme", "Colibri", "Northwind", "Василёк", "Гербера", "Ирис", "Колокольчик", "Лютик", "Одуванчик",
                   "Пион", "Ромашка", "Сирень"] and suggested == []
    scrub = Scrubber(AnonPolicy(), Roster(org_terms=tuple(org))).scrub
    scanner = LeakScanner(Known(titles=frozenset(org)))
    for text in ("добавьте меня в группу, в группе 5 человек",
                 "банк отклонил операцию, в банке сказали ждать, банк-эмитент молчит",
                 "Apple Pay не работает, we pay on Friday, App Store review",
                 "новые технологии, wallet balance, card blocked, медиа файлы",
                 "перевод не прошёл, переводы висят; кошелька нет; обмен валюты; процессинг отклонил; онлайн оплата",
                 "Служба поддержки ответит завтра, свяжитесь с поддержкой",
                 "Оплата через Apple Pay и Google Pay не проходит, код 05, заказ #4471"):
        assert scrub(text) == text
        assert scanner.scan(text) == []
    text = "клиент Ромашки и Colibri просят группу"
    assert scrub(text) == "клиент <org> и <org> просят группу"
    assert {l.match for l in scanner.scan(text)} == {"Ромашки", "Colibri"} and scanner.scan(scrub(text)) == []
    assert scrub("Ромашка Банк просит выплату") == "<org> Банк просит выплату"
    assert scanner.scan(PLACEHOLDERS) == []


def test_surname_shaped_title_words_are_still_scrubbed():
    org, _ = org_terms_from_titles(["Туров Олег — Ромашка", "Acme Pay", "Казина Анна"], 0.2)
    scrub = Scrubber(AnonPolicy(), Roster(org_terms=tuple(org))).scrub
    assert scrub("Туров сказал, что Apple Pay работает; Казина в курсе") == \
        "<org> сказал, что Apple Pay работает; <org> в курсе"


def test_title_only_words_do_not_change_the_surname_filters():
    # Free-text names and forward headers still read these words as surnames.
    from tg_collector.anonymize import split_free_text_name
    for name, surname in (("Anna Card", "Card"), ("Johnny Cash", "Cash"), ("Olga Merchant", "Merchant"),
                          ("Иван Банков", "Банков"), ("Anna Bank", "Bank")):
        assert split_free_text_name(RawUser(id=1, first_name=name))[1] == (surname,)


def test_generic_title_words_end_to_end(tmp_path):
    chats = [RawChat(id=-1001 - i, kind=KIND_SUPERGROUP, title=t, participant_ids=(ME.id, CLIENT.id))
             for i, t in enumerate(["Ромашка Банк", "Лютик Pay", "Василёк Групп"])]
    lines = {-1001: ["банк отклонил, в банке сказали; Apple Pay работает; в группе 5 человек",
                     "Ромашка и Лютику передайте, Василька тоже"], -1002: ["Pay ок"], -1003: ["группа ок"]}
    store = chats_store(tmp_path, chats, lines)
    ds, out = run(tmp_path, store)
    assert texts(ds) == {"банк отклонил, в банке сказали; Apple Pay работает; в группе 5 человек",
                         "<org> и <org> передайте, <org> тоже", "Pay ок", "группа ок"}
    assert verify(out, store, AnonPolicy(), tmp_path / "v.json").ok
    assert ds.private["org_terms_scrubbed"] == ["Василёк", "Лютик", "Ромашка"]


def test_title_or_name_equal_to_a_placeholder_word_does_not_flag_the_placeholder():
    scanner = LeakScanner(Known(titles=frozenset({"Token", "Proxy", "Wallet", "Address", "Acme", "Seed"}),
                                names=frozenset({"Cookie", "Petrov", "Phone"})))
    assert scanner.scan("<token> <proxy> <wallet> <address> <cookie> <phone> <seed-phrase> " + PLACEHOLDERS) == []
    # A kept host inside "<url:...>" and a look-alike that is not our placeholder are still reported.
    assert {l.match for l in scanner.scan("<url:acme.example.com> <petrov> Token")} == {"acme", "petrov", "Token"}
    scrub = Scrubber(AnonPolicy(), Roster(org_terms=("Token", "Proxy"))).scrub
    out = scrub("token: AbCdEf1234567890AbCdEf1234567890AbCdEf12, proxy работает")
    assert "<org>" in out and scanner.scan(out) == []
