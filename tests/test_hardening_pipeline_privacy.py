"""Privacy of the pipeline's own outputs: the attachment extension is a tail
of the file name and is scrubbed like one, the abort line and the shareable
manifest carry no raw values, verify refuses to certify a dataset without the
raw export, and an unusable mapping.json is reported instead of crashing.
"""

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tg_collector import cli
from tg_collector import anonymize as anon
from tg_collector.anonymize import AnonymizationError, Mapping, MappingError, anonymize
from tg_collector.config import AnonPolicy, Output, Settings
from tg_collector.dataset import AnonChat, AnonMessage, AnonUser, Dataset, media_label, write_dataset
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, Media, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore
from tg_collector.verify import verify

T0 = datetime(2024, 3, 1, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support", phone="79990000001")
CLIENT = RawUser(id=222333444, first_name="Иван", last_name="Петров", username="ivan_petrov", phone="79991234567")
CHAT_ID = -2001


def store_with(tmp_path: Path, *media: Media, text: str = "вот файл") -> RawStore:
    """A raw store with one message per attachment, from the client."""
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=CHAT_ID, kind=KIND_SUPERGROUP, title="Ромашка / Северов",
                   participant_ids=(ME.id, CLIENT.id))
    store.put_chats([chat])
    store.put_users([ME, CLIENT])
    store.set_me_id(ME.id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=i, date=T0 + timedelta(minutes=i), sender_id=CLIENT.id,
                   sender_kind=SENDER_USER, text=text, media=m)
        for i, m in enumerate(media, 1)
    ])
    return store


def media_of(store: RawStore, tmp_path: Path, policy: AnonPolicy = AnonPolicy()) -> list[dict]:
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    return [m.media for m in ds.messages]


# --- the attachment extension ---------------------------------------------------------

KEPT_EXTENSIONS = ["pdf", "docx", "xlsx", "7z", "001", "mp3", "m4a", "jpeg", "webp", "gz", "heic",
                   "p12", "ovpn", "har", "1c", "log", "json", "torrent", "mp4", "safetensors"]


@pytest.mark.parametrize("ext", KEPT_EXTENSIONS)
def test_a_real_extension_is_kept_verbatim(tmp_path, ext):
    store = store_with(tmp_path, Media(kind="document", ext=ext, file_name=f"report.{ext}"))
    assert media_of(store, tmp_path) == [{"kind": "document", "ext": ext}]


def test_photo_keeps_its_extension(tmp_path):
    store = store_with(tmp_path, Media(kind="photo", ext="jpg"))
    assert media_of(store, tmp_path) == [{"kind": "photo", "ext": "jpg"}]


# A file name whose last dot starts no extension: Telegram hands the tail over
# as "ext", so it carries whatever the sender typed.
NAME_TAILS = [
    (" петров иван", "Счёт 12. Петров Иван"),
    ("петров иван 79991234567", "скан паспорта.Петров Иван 79991234567"),
    ("ivan_petrov", "скан.ivan_petrov"),
    ("+79991234567", "договор.+79991234567"),
    ("9991234567", "договор.9991234567"),
    ("4510 123456", "паспорт.4510 123456"),
    ("222333444", "выписка.222333444"),
    ("petrov", "scan.petrov"),
    ("ромашка", "акт.ромашка"),
    ("в", "Доверенность Петрова И.В"),
    ("2024 ип петров", "Акт сверки 10.01.2024 ИП Петров"),
]


@pytest.mark.parametrize("ext, file_name", NAME_TAILS)
def test_a_name_tail_never_becomes_an_extension(tmp_path, ext, file_name):
    store = store_with(tmp_path, Media(kind="document", ext=ext, file_name=file_name, size=120_000))
    assert media_of(store, tmp_path) == [{"kind": "document", "size": 120_000}]


@pytest.mark.parametrize("ext, file_name", NAME_TAILS)
def test_the_mime_type_supplies_the_extension_the_name_could_not(tmp_path, ext, file_name):
    store = store_with(tmp_path, Media(kind="document", ext=ext, mime="application/pdf",
                                       file_name=file_name, size=120_000))
    assert media_of(store, tmp_path) == [{"kind": "document", "ext": "pdf", "size": 120_000}]


def test_the_transcript_label_of_a_dropped_extension_has_no_digits(tmp_path):
    store = store_with(tmp_path, Media(kind="document", ext="+79991234567",
                                       file_name="договор.+79991234567", size=120_000))
    assert media_label(media_of(store, tmp_path)[0]) == "[document 120 KB]"


def test_a_mime_extension_is_scrubbed_too(tmp_path):
    """The MIME fallback goes through the same gate: a bogus type cannot slip
    a name in either."""
    store = store_with(tmp_path, Media(kind="document", ext="петров", mime="text/petrov"))
    assert media_of(store, tmp_path) == [{"kind": "document"}]


def dataset_with_media(media: dict) -> Dataset:
    ds = Dataset()
    ds.users["U00001"] = AnonUser(vid="U00001", name="", role="client", side="CLIENT")
    ds.chats["C00001"] = AnonChat(vid="C00001", title="C00001", kind=KIND_SUPERGROUP)
    ds.messages.append(AnonMessage(chat="C00001", seq=1, date=T0, sender="U00001", role="client",
                                   side="CLIENT", text="вот файл", media=media))
    return ds


@pytest.mark.parametrize("value", ["+79991234567", "222333444", "@ivan_petrov"])
def test_the_self_check_reads_the_attachment_extension(tmp_path, value):
    """Whatever the scrubber removes, the fail-fast check detects: the field
    is part of the output, so a raw id planted there aborts the run. (A
    username without its ``@`` is left to verify, here as everywhere.)"""
    store = store_with(tmp_path, Media(kind="document", ext="pdf"))
    ds = dataset_with_media({"kind": "document", "ext": value})
    with pytest.raises(AnonymizationError, match=r":media\.ext"):
        anon._self_check(ds, anon.vocabulary(store, AnonPolicy()))


def test_the_self_check_passes_on_a_plain_extension(tmp_path):
    store = store_with(tmp_path, Media(kind="document", ext="pdf"))
    anon._self_check(dataset_with_media({"kind": "document", "ext": "pdf"}), anon.vocabulary(store, AnonPolicy()))


def test_verify_stays_silent_on_the_scrubbed_extensions_and_flags_a_raw_one(tmp_path):
    store = store_with(tmp_path, *(Media(kind="document", ext=ext, file_name=name, mime="application/pdf")
                                   for ext, name in NAME_TAILS))
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), AnonPolicy())
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(), {})
    report = tmp_path / "verify_report.json"
    assert verify(out, store, AnonPolicy(), report).ok
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "x", "media": {"kind": "document", "ext": "ivan_petrov"}}) + "\n")
    leaks = verify(out, store, AnonPolicy(), report).leaks
    assert any(l.kind == "username" and l.location.endswith("media.ext") for l in leaks)


# --- the abort line --------------------------------------------------------------------

def break_the_scrubber(monkeypatch) -> None:
    """Simulate the bug the self-check exists for: nothing is scrubbed."""
    monkeypatch.setattr(anon.Scrubber, "scrub", lambda self, text, entities=(): text)


def test_the_abort_names_kinds_and_locations_but_never_the_value(tmp_path, monkeypatch):
    store = store_with(tmp_path, Media(kind="document", ext="pdf"),
                       text="пишите @ivan_petrov или +79991234567")
    break_the_scrubber(monkeypatch)
    with pytest.raises(AnonymizationError) as excinfo:
        anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), AnonPolicy())
    message = str(excinfo.value)
    assert "username at C" in message and "phone at C" in message
    assert "ivan_petrov" not in message and "79991234567" not in message
    # The raw matches travel on the exception, for a private report only.
    assert {l.kind for l in excinfo.value.leaks} >= {"username", "phone"}
    assert any(l.match == "@ivan_petrov" for l in excinfo.value.leaks)


# --- the CLI ---------------------------------------------------------------------------

@pytest.fixture
def project(tmp_path, monkeypatch):
    """A project directory the CLI can run anonymize and verify in."""
    for var in ("TG_DATA_DIR", "TG_SESSION", "TG_API_ID", "TG_API_HASH", "TG_PHONE"):
        monkeypatch.delenv(var, raising=False)
    (tmp_path / "config.toml").write_text("[anonymize]\nname_mode = \"none\"\n", encoding="utf-8")
    store = RawStore(tmp_path / "data" / "raw")
    chat = RawChat(id=CHAT_ID, kind=KIND_SUPERGROUP, title="Ромашка / Северов",
                   participant_ids=(ME.id, CLIENT.id, 31))
    store.put_chats([chat])
    store.put_users([ME, CLIENT, RawUser(id=31, first_name="Тема")])
    store.set_me_id(ME.id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=1, date=T0, sender_id=CLIENT.id, sender_kind=SENDER_USER,
                   text="пишите @ivan_petrov или +79991234567"),
        RawMessage(chat_id=chat.id, id=2, date=T0 + timedelta(minutes=1), sender_id=31,
                   sender_kind=SENDER_USER, text="тема закрыта, заказ 90829441"),
    ])
    return tmp_path


def settings_of(project: Path) -> Settings:
    return Settings.load(project)


def test_a_clean_run_writes_no_abort_file(project, capsys):
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    assert not (settings_of(project).anon_dir / "anonymize_abort.json").exists()
    assert "ABORTED" not in capsys.readouterr().err


def test_an_abort_keeps_the_raw_matches_out_of_the_console(project, capsys, monkeypatch):
    break_the_scrubber(monkeypatch)
    assert cli.main(["--project", str(project), "anonymize"]) == 3
    err = capsys.readouterr().err
    assert err.startswith("ABORTED:") or "\nABORTED:" in err
    assert "username at C" in err and "phone at C" in err
    assert "ivan_petrov" not in err and "79991234567" not in err
    abort = settings_of(project).anon_dir / "anonymize_abort.json"
    assert abort.exists() and (abort.stat().st_mode & 0o777) == 0o600
    assert "@ivan_petrov" in abort.read_text(encoding="utf-8")


def test_the_operator_still_learns_which_first_names_stay(project, capsys):
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    assert "First names that are ordinary words" in capsys.readouterr().err
    settings = settings_of(project)
    manifest = json.loads((settings.dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "first_names_kept_as_words" not in manifest["notes"]
    assert "Тема" not in json.dumps(manifest, ensure_ascii=False)
    private = json.loads((settings.anon_dir / "anonymize_report.json").read_text(encoding="utf-8"))
    assert private["first_names_kept_as_words"] == ["Тема"]


def test_verify_certifies_only_with_the_raw_export(project, capsys):
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    capsys.readouterr()
    assert cli.main(["--project", str(project), "verify"]) == 0
    assert "OK: no leaks found" in capsys.readouterr().err
    (project / "data" / "raw").rename(project / "data" / "raw.moved")
    assert cli.main(["--project", str(project), "verify"]) == 1
    err = capsys.readouterr().err
    assert "raw export" in err and "OK" not in err


def test_verify_refuses_an_empty_raw_directory(project, capsys):
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    for path in sorted((project / "data" / "raw").rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    capsys.readouterr()
    assert cli.main(["--project", str(project), "verify"]) == 1
    assert "OK" not in capsys.readouterr().err


def test_verify_as_a_library_refuses_to_audit_without_the_raw_export(project, tmp_path):
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    settings = settings_of(project)
    with pytest.raises(FileNotFoundError, match="raw export"):
        verify(settings.dataset_dir, RawStore(tmp_path / "missing"), AnonPolicy(), tmp_path / "r.json")


def test_verify_warns_that_its_matches_quote_raw_data(project, capsys):
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    capsys.readouterr()
    assert cli.main(["--project", str(project), "verify"]) == 0
    assert "do not paste them" not in capsys.readouterr().err
    settings = settings_of(project)
    with open(settings.dataset_dir / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"text": "planted @ivan_petrov"}) + "\n")
    assert cli.main(["--project", str(project), "verify"]) == 4
    assert capsys.readouterr().err.rstrip().endswith("do not paste them into an issue or a chat.")
    assert (settings.anon_dir / "verify_report.json").stat().st_mode & 0o777 == 0o600


# --- an unusable mapping ---------------------------------------------------------------

CORRUPT_MAPPINGS = [
    "{not json",
    "not json at all",
    '{"users": {"123": "U12x"}, "chats": {}}',
    '{"users": {"1": "X1"}, "chats": {}}',
    '{"digits": {"U": 4, "C": 4}, "users": {"1": "U00042"}, "chats": {}}',
    '{"users": {"ivan_petrov": "U00042"}, "chats": {}}',
]


@pytest.mark.parametrize("payload", CORRUPT_MAPPINGS)
def test_an_unusable_mapping_is_reported_without_a_traceback(project, capsys, payload):
    settings = settings_of(project)
    settings.anon_dir.mkdir(parents=True, exist_ok=True)
    settings.mapping_path.write_text(payload, encoding="utf-8")
    assert cli.main(["--project", str(project), "anonymize"]) == 1
    err = capsys.readouterr().err
    assert "Mapping error:" in err and "Traceback" not in err
    assert "ivan_petrov" not in err  # the message never quotes the file's content


def test_a_valid_mapping_keeps_its_virtual_ids(project, capsys):
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    settings = settings_of(project)
    before = json.loads(settings.mapping_path.read_text(encoding="utf-8"))["users"]
    assert cli.main(["--project", str(project), "anonymize"]) == 0
    assert json.loads(settings.mapping_path.read_text(encoding="utf-8"))["users"] == before


def test_an_exhausted_id_space_is_a_mapping_error_not_an_abort(tmp_path):
    mapping = Mapping(tmp_path / "m.json", digits={"U": 1, "C": 1})
    for i in range(1, 10):
        mapping.user(i)
    with pytest.raises(MappingError, match="virtual ids U#"):
        mapping.user(10)


def test_the_self_check_abort_is_not_a_mapping_error(tmp_path, monkeypatch):
    store = store_with(tmp_path, Media(kind="document", ext="pdf"), text="пишите @ivan_petrov")
    break_the_scrubber(monkeypatch)
    with pytest.raises(AnonymizationError) as excinfo:
        anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), AnonPolicy())
    assert not isinstance(excinfo.value, MappingError)


# --- keep_terms suggestions ------------------------------------------------------------

SUGGESTION_TITLES = ["Ромашка / Северов", "Лютик / Северов", "Василёк / Северов"]
PLAIN_TITLES = ["Ромашка support", "Лютик support", "Василёк support"]
SUGGESTION_TEXT = "Олег Северов, ... Северову привет. Северова Олега нет. Oleg Severov, Severovu."


def suggestion_store(root: Path, titles: list[str]) -> RawStore:
    store = RawStore(root)
    chats = [RawChat(id=-3000 - i, kind=KIND_SUPERGROUP, title=title, participant_ids=(ME.id, CLIENT.id))
             for i, title in enumerate(titles)]
    store.put_chats(chats)
    store.put_users([ME, CLIENT])
    store.set_me_id(ME.id)
    for chat in chats:
        store.append_messages(chat.id, [RawMessage(chat_id=chat.id, id=1, date=T0, sender_id=CLIENT.id,
                                                   sender_kind=SENDER_USER, text=SUGGESTION_TEXT)])
    return store


@pytest.mark.parametrize("policy, expected", [
    (AnonPolicy(), []),
    (AnonPolicy(scrub_last_names=False), ["Северов"]),  # pinned: the policy keeps surnames in text anyway
])
def test_a_staff_surname_in_every_title_is_suggested_only_when_the_policy_keeps_surnames(tmp_path, policy, expected):
    store = suggestion_store(tmp_path / "raw", SUGGESTION_TITLES)
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(ME.id), policy)
    assert ds.private["keep_terms_suggested"] == expected


NAME_FORMS = ("Северов", "Северову", "Северова", "Severov", "Severovu")


@pytest.mark.parametrize("policy", [
    AnonPolicy(), AnonPolicy(scrub_last_names=False), AnonPolicy(name_mode="full"), AnonPolicy(name_mode="none"),
])
def test_accepting_every_suggestion_never_exposes_a_name(tmp_path, policy):
    """A suggestion is safe to accept whatever the policy: with the whole list
    in keep_terms, no spelling of the person's name survives that would not
    survive anyway under titles that never mentioned them. Keeping a word
    keeps it only where the policy already did."""
    named = suggestion_store(tmp_path / "named", SUGGESTION_TITLES)
    suggested = anonymize(named, Mapping(tmp_path / "m1.json"), Roles.build(ME.id),
                          policy).private["keep_terms_suggested"]
    accepted = anonymize(named, Mapping(tmp_path / "m2.json"), Roles.build(ME.id),
                         dataclasses.replace(policy, keep_terms=(*policy.keep_terms, *suggested)))
    plain = anonymize(suggestion_store(tmp_path / "plain", PLAIN_TITLES), Mapping(tmp_path / "m3.json"),
                      Roles.build(ME.id), policy)
    assert surviving_forms(accepted) <= surviving_forms(plain)


def surviving_forms(ds) -> set:
    return {form for form in NAME_FORMS if any(form in m.text for m in ds.messages)}


def test_a_kept_staff_surname_is_kept_only_where_the_policy_keeps_surnames(tmp_path):
    """The pinned shape of the suggestion the policy allows: with
    ``scrub_last_names = false`` and the surname in keep_terms, the text is
    exactly what the same policy writes for titles without the name - the
    standalone forms stay, "First Last" still goes."""
    named = suggestion_store(tmp_path / "named", SUGGESTION_TITLES)
    kept = anonymize(named, Mapping(tmp_path / "m1.json"), Roles.build(ME.id),
                     AnonPolicy(scrub_last_names=False, keep_terms=("Северов",)))
    plain = anonymize(suggestion_store(tmp_path / "plain", PLAIN_TITLES), Mapping(tmp_path / "m2.json"),
                      Roles.build(ME.id), AnonPolicy(scrub_last_names=False))
    assert [m.text for m in kept.messages] == [m.text for m in plain.messages]
    assert kept.messages[0].text == "<name>, ... Северову привет. <name> нет. <name>, Severovu."


def test_a_product_word_is_suggested_next_to_people_of_that_name(tmp_path):
    store = RawStore(tmp_path / "raw")
    chats = [RawChat(id=-4000 - i, kind=KIND_SUPERGROUP, title=f"Northwind / {client}",
                     participant_ids=(ME.id, 51, 52))
             for i, client in enumerate(("Ромашка", "Лютик", "Василёк"))]
    store.put_chats(chats)
    store.put_users([ME, RawUser(id=51, first_name="Иван", last_name="Wind"),
                     RawUser(id=52, first_name="Пётр", last_name="Норт")])
    store.set_me_id(ME.id)
    for chat in chats:
        store.append_messages(chat.id, [RawMessage(chat_id=chat.id, id=1, date=T0, sender_id=51,
                                                   sender_kind=SENDER_USER, text="ok")])
    for policy in (AnonPolicy(), AnonPolicy(scrub_last_names=False)):
        ds = anonymize(store, Mapping(tmp_path / f"m{policy.scrub_last_names}.json"), Roles.build(ME.id), policy)
        assert "Northwind" in ds.private["keep_terms_suggested"]
