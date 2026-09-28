"""The shapes and vocabularies that more than one layer has to agree on.

A handle, a masked card, the three username patterns, the split between the
dataset writer's composed strings and its free text, and the high-precision
identifiers of the self-check each live in one place now. These tests pin
what each of them does, on both sides: what the scrubber removes the leak
scanner flags on the raw text and passes on the output, and what carries
product knowledge stays byte-identical with the scanner silent.
"""

import dataclasses
import re
import typing
from datetime import datetime, timedelta, timezone

import pytest

from conftest import assert_fast, check
from tg_collector import rules, verify as verify_module
from tg_collector import anonymize as anonymize_module
from tg_collector.anonymize import Mapping, anonymize, vocabulary
from tg_collector.config import AnonPolicy, Output
from tg_collector.dataset import (
    CHUNK_INDEX, COMPOSED_JSON_KEYS, DISPLAY_NAME_KEY, TRANSCRIPT_DIRS, AnonChat, AnonMessage, AnonUser,
    Dataset, write_dataset,
)
from tg_collector.fintech import _AT_HANDLE, _OPERATION_LABEL, _OPERATION_LIST, _quoted_value
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.scrub import Known, LeakScanner, Roster, Scrubber
from tg_collector.verify import known_from_store, verify

BINS = ("424242", "400000", "510510")
ZWSP = "\u200b"  # a zero-width space pasted into a keep term
T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support", phone="+79161112233")
CLIENT = RawUser(id=11, first_name="Иван", last_name="Петров", username="ivan_petrov")


@pytest.fixture
def scrub():
    return Scrubber(AnonPolicy(card_bins=BINS), Roster()).scrub


@pytest.fixture
def scanner():
    return LeakScanner(Known(card_bins=frozenset(BINS)))


def roster_and_scanner(by_username, keep_terms=(), chat_usernames=frozenset()):
    """A scrubber and a leak scanner that know the same usernames and the
    same keep terms, the way the anonymizer and verify build them."""
    policy = AnonPolicy(keep_terms=list(keep_terms))
    scrubber = Scrubber(policy, Roster(by_username=dict(by_username), chat_usernames=chat_usernames,
                                       keep_terms=tuple(keep_terms)))
    scanner = LeakScanner(Known(usernames=frozenset(by_username), chat_usernames=chat_usernames,
                                keep_terms=frozenset(keep_terms)), regex_rules=False)
    return scrubber.scrub, scanner


def build_store(tmp_path, texts, policy=AnonPolicy()):
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка", username="romashka_support",
                   participant_ids=(ME.id, CLIENT.id))
    store.put_chats([chat])
    store.put_users([ME, CLIENT])
    store.set_me_id(ME.id)
    store.append_messages(chat.id, [
        RawMessage(id=i, chat_id=chat.id, date=T0 + timedelta(minutes=i), sender_kind=SENDER_USER,
                   sender_id=CLIENT.id, text=t)
        for i, t in enumerate(texts, 1)
    ])
    return store


# --- anonymize.Mapping is the id store, not typing.Mapping ----------------------------

def test_the_read_only_dict_annotations_do_not_name_the_id_store():
    """``class Mapping`` (the virtual-id store) must not shadow the imported
    ``typing.Mapping``: annotations that name it stay resolvable."""
    source = open(anonymize_module.__file__, encoding="utf-8").read()
    assert "Mapping[" not in source
    for name in ("display_name", "_person_terms", "_fields_swapped", "_user_name_terms",
                 "_keep_term_suggestions", "_chat_title", "_contact_names", "_drop_names_of_others"):
        typing.get_type_hints(getattr(anonymize_module, name))


def test_the_public_mapping_is_still_the_virtual_id_store(tmp_path):
    m = Mapping(tmp_path / "m.json")
    vid = m.user(1)
    assert re.fullmatch(r"U\d{5}", vid) and m.user(1) == vid
    m.save()
    assert Mapping.load(tmp_path / "m.json").user(1) == vid


# --- the scanner hunts the roster's own username patterns ------------------------------

def test_the_at_form_is_replaced_and_flagged_whatever_the_keep_terms_say():
    """'@' makes a handle a handle: keep terms govern only the bare word."""
    for keeps in ((), ("Ivan_Petrov",), ("ivan_petrov " + ZWSP,)):
        scrub, scanner = roster_and_scanner({"ivan_petrov": "U00002"}, keeps)
        assert scrub("@ivan_petrov привет") == "@U00002 привет"
        assert [l.kind for l in scanner.scan("@ivan_petrov привет")] == ["username"]
        assert not scanner.scan("@U00002 привет")


def test_a_short_username_after_a_handle_keyword_is_replaced_and_flagged():
    scrub, scanner = roster_and_scanner({"ivan_petrov": "U00002", "ivan": "U00003"})
    assert scrub("мой ник в тг ivan") == "мой ник в тг @U00003"
    assert [l.kind for l in scanner.scan("мой ник в тг ivan")] == ["username"]
    assert not scanner.scan("мой ник в тг @U00003")


def test_a_bare_username_is_replaced_and_flagged():
    scrub, scanner = roster_and_scanner({"ivan_petrov": "U00002", "ivan": "U00003"})
    assert scrub("пишите ivan_petrov") == "пишите @U00002"
    assert [l.kind for l in scanner.scan("пишите ivan_petrov")] == ["username"]
    assert not scanner.scan("пишите @U00002")


def test_a_keep_term_inside_a_username_does_not_keep_the_username():
    """"Northwind" as a keep term is the product, not the person handle it
    is a part of."""
    scrub, scanner = roster_and_scanner({"northwind_ivan": "U00002"}, ("Northwind",))
    assert scrub("пиши northwind_ivan") == "пиши @U00002"
    assert [l.kind for l in scanner.scan("пиши northwind_ivan")] == ["username"]


def test_a_public_chat_handle_that_spells_a_product_word_stays_bare():
    scrub, scanner = roster_and_scanner({"payments": "C01735"}, chat_usernames=frozenset({"payments"}))
    assert scrub("напиши payments") == "напиши payments"      # the API term of the chat
    assert not scanner.scan("напиши payments")
    assert scrub("@payments") == "@C01735"
    assert [l.kind for l in scanner.scan("@payments")] == ["username"]


@pytest.mark.parametrize("keep", ["Ivan_Petrov", "ivan_petrov ", "Ivan_Petrov" + ZWSP, "IVAN_PETROV"])
def test_a_keep_term_keeps_a_bare_username_however_it_is_spelled(keep):
    """Keep terms are compared with ``fold`` everywhere - a stray capital,
    a trailing blank or a pasted zero-width character must not silently turn
    one half of the rule off. The scrubber and the scanner read the same
    table, so neither touches the bare word and neither reports it."""
    scrub, scanner = roster_and_scanner({"ivan_petrov": "U00002"}, (keep,))
    assert scrub("пишите ivan_petrov") == "пишите ivan_petrov"
    assert not scanner.scan("пишите ivan_petrov")


def test_the_scanner_builds_three_username_patterns_and_no_more():
    scanner = LeakScanner(Known(usernames=frozenset({"ivan_petrov"})), regex_rules=False)
    assert len(scanner._username_res) == 3
    assert not LeakScanner(Known(), regex_rules=False)._username_res


# --- one handle and one masked-card shape ---------------------------------------------

def test_every_layer_builds_the_handle_and_masked_card_shapes_from_rules():
    """One shape, read from ``rules``: a length changed in a second copy
    would break the agreement between the scrubber and the layers that have
    to stand back from a handle."""
    from tg_collector.fintech import _ADDRESS_NOISE
    from tg_collector.scrub import _HANDLE, _MASKED_CARD_TRAILER
    assert rules.HANDLE_START in _HANDLE and rules.USERNAME in _HANDLE
    assert _AT_HANDLE.pattern == rules.HANDLE_START + rules.USERNAME
    assert rules.HANDLE_START + rules.USERNAME in _ADDRESS_NOISE.pattern
    assert rules.MASKED_CARD in _ADDRESS_NOISE.pattern
    assert _MASKED_CARD_TRAILER.pattern.startswith(rules.MASKED_CARD)
    assert rules._MASKED_CARD.pattern == rules.MASKED_CARD


@pytest.mark.parametrize("text,expected", [
    ("пиши @oleg_support", "пиши @user"),
    ("password@Qwerty123", "password@<password>"),   # a glued handle is no handle
    ("user@host", "user@host"),
    ("node_modules/@scope", "node_modules/@scope"),
])
def test_the_handle_boundary_is_the_same_on_every_layer(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_a_masked_card_with_an_expiry_and_a_cvv_behind_it_is_still_flagged(scanner):
    leaks = scanner.scan("424242********** 12/27 123")
    assert [l.kind for l in leaks] == ["cvv"]


# --- the writer owns its own layout ---------------------------------------------------

def test_verify_reads_the_writers_layout_from_the_writer():
    assert verify_module.COMPOSED_JSON_KEYS is COMPOSED_JSON_KEYS
    assert verify_module.DISPLAY_NAME_KEY is DISPLAY_NAME_KEY
    assert verify_module.TRANSCRIPT_DIRS is TRANSCRIPT_DIRS
    assert verify_module.CHUNK_INDEX is CHUNK_INDEX
    assert set(COMPOSED_JSON_KEYS) == {"messages.jsonl", "episodes.jsonl", "users.json",
                                       "chats.json", "manifest.json"}


def test_the_writer_uses_the_directory_names_the_audit_classifies(tmp_path):
    ds = Dataset(users={"U00002": AnonUser(vid="U00002", name="Иван", role="client", side="CLIENT")},
                 chats={"C01735": AnonChat(vid="C01735", title="Ромашка", kind=KIND_SUPERGROUP)},
                 messages=[AnonMessage(chat="C01735", seq=1, date=T0, sender="U00002", role="client",
                                       side="CLIENT", text="оплата не прошла")])
    out = tmp_path / "ds"
    write_dataset(ds, out, Output(), {})
    for name in TRANSCRIPT_DIRS:
        assert (out / name).is_dir(), name
    assert (out / CHUNK_INDEX).is_file()


def test_every_free_text_field_of_a_message_is_offered_to_the_self_check():
    """A field the writer does not compose carries whatever the sender typed,
    so it must be hunted for names - the attachment extension included."""
    ds = Dataset(messages=[AnonMessage(chat="C01735", seq=1, date=T0, sender="U00002", role="client",
                                       side="CLIENT", text="счёт",
                                       media={"kind": "document", "name": "Северов.pdf", "ext": "severov"})])
    where = dict((loc, text) for loc, text in ds.texts())
    assert where["C01735#1"] == "счёт"
    assert where["C01735#1:media.name"] == "Северов.pdf"
    assert where["C01735#1:media.ext"] == "severov"
    assert not COMPOSED_JSON_KEYS["messages.jsonl"].fullmatch("media.ext")
    assert COMPOSED_JSON_KEYS["messages.jsonl"].fullmatch("media.kind")


def test_a_surname_in_an_attachment_extension_is_reported(tmp_path):
    store = build_store(tmp_path, ["вот документ"])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), AnonPolicy())
    ds.messages[0] = dataclasses.replace(ds.messages[0], media={"kind": "document", "ext": "severov"})
    out = tmp_path / "ds"
    write_dataset(ds, out, Output(), {})
    report = verify(out, store, AnonPolicy(), tmp_path / "report.json")
    assert any(l.kind == "name" and "media.ext" in l.location for l in report.leaks), report.by_kind()


# --- one Known for the self-check and for verify --------------------------------------

def test_the_vocabulary_hands_out_the_identifiers_both_passes_hunt(tmp_path):
    store = build_store(tmp_path, ["привет"])
    vocab = vocabulary(store, AnonPolicy())
    known = vocab.known()
    assert known.user_ids == frozenset({ME.id, CLIENT.id})
    assert known.chat_ids == vocab.known_ids() - frozenset(vocab.users)
    assert known.usernames == frozenset({"oleg_support", "ivan_petrov", "romashka_support"})
    assert known.chat_usernames == frozenset({"romashka_support"})
    assert known.phones == frozenset({"79161112233"})
    assert known.names == frozenset() and known.keep_terms == frozenset()


def test_usernames_is_the_key_set_of_the_virtual_id_map(tmp_path):
    store = build_store(tmp_path, ["привет"])
    vocab = vocabulary(store, AnonPolicy())
    assert vocab.usernames() == frozenset(vocab.username_vids(lambda _: "", lambda _: ""))


def test_verify_layers_the_fuzzy_vocabulary_on_the_very_same_identifiers(tmp_path):
    policy = AnonPolicy(keep_terms=["Northwind"], card_bins=list(BINS))
    store = build_store(tmp_path, ["привет"])
    vocab = vocabulary(store, policy)
    known = known_from_store(store, policy)
    for field in ("user_ids", "chat_ids", "usernames", "chat_usernames", "phones"):
        assert getattr(known, field) == getattr(vocab.known(), field), field
    assert known.keep_terms == frozenset({"Northwind"}) and known.card_bins == frozenset(BINS)
    assert "Северов" in known.names


def test_a_raw_username_that_survived_scrubbing_still_aborts_the_run(tmp_path, monkeypatch):
    store = build_store(tmp_path, ["пишите @ivan_petrov"])
    monkeypatch.setattr(Scrubber, "scrub", lambda self, text, *a, **kw: text)
    with pytest.raises(anonymize_module.AnonymizationError) as e:
        anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), AnonPolicy())
    assert "raw identifiers survived" in str(e.value)


def test_a_dataset_of_virtual_ids_only_passes_the_self_check(tmp_path):
    """The run completes, the handle is a virtual id and the order number -
    product knowledge - is byte-identical."""
    store = build_store(tmp_path, ["пишите @ivan_petrov", "заказ 3184713454"])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), AnonPolicy())
    handle, order = (m.text for m in ds.messages)
    assert re.fullmatch(r"пишите @U\d{5}", handle), handle
    assert order == "заказ 3184713454"


# --- the quoted-value gate is a function of the body class ----------------------------

@pytest.mark.parametrize("text,expected", [
    ('password: "correct horse battery"', 'password: "<password>"'),
    ('password: "hunter2 is wrong"', 'password: "<password> is wrong"'),
    ("пароль «Мой пароль 2024»", "пароль «<password>»"),
    ('пароль "не менее 8 символов"', 'пароль "не менее 8 символов"'),
])
def test_a_quoted_passphrase_is_taken_whole_unless_it_reads_as_a_message(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


def test_a_quantifier_in_the_gate_keeps_the_pattern_valid():
    """The gate is a function of the body class, not a str.format template:
    a ``{2}`` inside the gate is a quantifier of the pattern and not a
    format field that raises at import time."""
    fragment = _quoted_value(4, 64, gate=lambda body: rf"(?!{body}{{0,3}}[aeiou]{{2}})")
    assert re.compile(fragment).search('"xyzzy"')
    assert not re.compile(fragment).search('"aaqu"')


# --- the env rule judges a quoted passphrase ------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ('API_SECRET="correct horse battery"', 'API_SECRET="<token>"'),
    ('DB_PASSWORD="my secret phrase"', 'DB_PASSWORD="<token>"'),
    ("DB_PASSWORD=Summer#2024", "DB_PASSWORD=<token>"),
    ('ERROR_TEXT="field is required"', 'ERROR_TEXT="field is required"'),
    ('API_SECRET="must be at least 8 characters"', 'API_SECRET="must be at least 8 characters"'),
    ('API_SECRET="хранится в vault"', 'API_SECRET="хранится в vault"'),
])
def test_an_env_value_with_spaces_is_a_passphrase_unless_it_reads_as_prose(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


# --- one ending class for the operation nouns -----------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("ИНН 7700000425", "ИНН <tax-id>"),
    ("заказу 3184713454", "заказу 3184713454"),
    ("заказа 3184713454", "заказа 3184713454"),
    ("тикет №12345", "тикет №12345"),
    ("ИНН по заказу: 7700000425", "ИНН по заказу: <inn>"),
    ("обновите клиента на 8.8.8.8", "обновите клиента на <ip>"),
    ("обновите клиент до 2.14.0.3", "обновите клиент до 2.14.0.3"),
])
def test_an_operation_label_keeps_its_reference_and_a_tax_id_still_goes(scrub, scanner, text, expected):
    check(scrub, scanner, text, expected)


_OLD_NOUN = (
    r"заказ(?:а|у|ом|е|ы|ов|ам|ами|ах)?|тикет(?:а|у|ом|е|ы|ов|ам|ами|ах)?|инвойс(?:а|у|ом|е|ы|ов|ам|ами|ах)?")
_OLD_PLURAL = r"заказ(?:ы|ов|ам|ами|ах)|тикет(?:ы|ов|ам|ами|ах)|инвойс(?:ы|ов|ам|ами|ах)"


def test_the_factored_ending_class_matches_the_same_language():
    """``(?:заказ|тикет|инвойс)<ending>`` for three copies of one ending
    class: the prefixes do not overlap, so the match is the same one."""
    old_label = re.compile(_OLD_NOUN, re.IGNORECASE)
    new_label = re.compile(r"(?:заказ|тикет|инвойс)(?:а|у|ом|е|ы|ов|ам|ами|ах)?", re.IGNORECASE)
    assert _OLD_NOUN.split("|")[0] not in _OPERATION_LABEL.pattern     # the copies are gone
    assert _OLD_PLURAL.split("|")[0] not in _OPERATION_LIST.pattern
    stems = ["заказ", "тикет", "инвойс", "заказы", "инвойсами", "тикетах", "заказчик", "инвойсер"]
    ends = ["", "а", "у", "ом", "е", "ы", "ов", "ам", "ами", "ах", "ик", "ов,"]
    for stem in stems:
        for end in ends:
            probe = stem + end
            a, b = old_label.search(probe), new_label.search(probe)
            assert (a is None) == (b is None) and (a is None or a.span() == b.span()), probe


# --- the changed rules stay linear ----------------------------------------------------

@pytest.mark.parametrize("hostile", [
    "заказ" * 819,
    "заказами, " * 409,
    "тикет id номер " * 273,
    "ivan_petrov " * 341,
], ids=["order-stem", "order-plural-list", "ticket-id-number", "handle-run"])
def test_the_shared_patterns_stay_linear_on_a_hostile_run(hostile):
    text = hostile[:4096]
    scrub, scanner = roster_and_scanner({"ivan_petrov": "U00002", "ivan": "U00003"})
    assert_fast(lambda: scanner.scan(scrub(text)), label=text[:40])
