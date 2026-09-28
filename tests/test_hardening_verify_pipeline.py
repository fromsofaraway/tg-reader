"""verify hunts people's names and chat-title terms only in scrubbed free
text, with exactly the scrubber's exceptions, and every private file the
tool writes is owner-only."""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tg_collector import cli
from tg_collector.anonymize import Mapping, anonymize
from tg_collector.config import AnonPolicy, Output, Settings
from tg_collector.dataset import write_dataset
from tg_collector.model import KIND_SUPERGROUP, SENDER_USER, RawChat, RawMessage, RawUser, Roles
from tg_collector.rawstore import RawStore, restrict_to_owner, write_private_json
from tg_collector.scrub import LeakScanner, Roster, Scrubber
from tg_collector.verify import known_from_store, verify

T0 = datetime(2024, 1, 10, 9, 0, tzinfo=timezone.utc)
ME = RawUser(id=1, first_name="Олег", last_name="Северов", username="oleg_support")
CLIENT = RawUser(id=2, first_name="Иван", last_name="Петров")
BOT = RawUser(id=9, first_name="Notifier", is_bot=True)
KEEP = AnonPolicy(keep_terms=("Northwind",), keep_file_names=True, keep_bot_messages=True)


def make_store(root: Path, title: str, users, texts, forum: bool = False) -> RawStore:
    store = RawStore(root)
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title=title, is_forum=forum,
                   participant_ids=tuple(u.id for u in (ME, *users)))
    store.put_chats([chat])
    store.put_users([ME, *users])
    store.set_me_id(ME.id)
    store.append_messages(chat.id, [
        RawMessage(chat_id=chat.id, id=i, date=T0 + timedelta(minutes=i), sender_id=uid, sender_kind=SENDER_USER,
                   text=text, topic_id=7 if forum else None)
        for i, (uid, text) in enumerate(texts, 1)
    ])
    return store


def build(tmp_path, title, users, texts, policy=KEEP, forum=False, timezone_key="Europe/Berlin", roles=None):
    """Anonymize, write and verify; returns (dataset, dataset dir, store, report)."""
    store = make_store(tmp_path / "raw", title, users, texts, forum)
    ds = anonymize(store, Mapping(tmp_path / "m.json"), roles or Roles.build(ME.id), policy)
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(timezone=timezone_key), {"output": {"timezone": timezone_key}})
    return ds, out, store, verify(out, store, policy, tmp_path / "verify_report.json")


def append_rows(out: Path, *rows) -> None:
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def leaks_of(out, store, policy, tmp_path) -> set[tuple[str, str, str]]:
    report = verify(out, store, policy, tmp_path / "verify_report.json")
    return {(l.kind, l.match, l.location.split(":", 1)[0] + ":" + l.location.rsplit(":", 1)[-1]) for l in report.leaks}


# --- labels and header words the writer composes are not names or titles ----------------

@pytest.mark.parametrize("title, users, texts, forum, timezone_key", [
    ("ООО Формат", [CLIENT], [(2, "привет")], False, "Europe/Berlin"),            # "Line format:" header
    ("Формат-Сервис", [CLIENT], [(2, "привет")], False, "Europe/Berlin"),
    ("Форум Ромашка", [CLIENT], [(2, "привет")], True, "Europe/Berlin"),          # "Forum chat:" header
    ("Бот Ромашка", [CLIENT, BOT], [(2, "привет"), (9, "уведомление")], False, "Europe/Berlin"),  # BOT / (bot)
    ("Период Ромашка", [CLIENT], [(2, "привет")], False, "Europe/Berlin"),        # "Period:" header
    ("Ромашка Алматы", [CLIENT], [(2, "привет")], False, "Asia/Almaty"),          # "times in Asia/Almaty", manifest
    ("Ромашка", [RawUser(id=2, first_name="Anna", last_name="Client")], [(2, "привет")], False, "Europe/Berlin"),
    ("Ромашка", [RawUser(id=2, first_name="Ivan", last_name="Episode")], [(2, "привет")], False, "Europe/Berlin"),
    ("Ромашка", [RawUser(id=2, first_name="Иван", last_name="Форум")], [(2, "привет")], True, "Europe/Berlin"),
    ("Ромашка", [RawUser(id=2, first_name="Иван", last_name="Бот"), BOT], [(2, "Бот ответил"), (9, "x")], False,
     "Europe/Berlin"),
])
def test_writer_words_colliding_with_the_vocabulary_do_not_fail_a_clean_dataset(
        tmp_path, title, users, texts, forum, timezone_key):
    _, _, _, report = build(tmp_path, title, users, texts, forum=forum, timezone_key=timezone_key)
    assert report.ok, report.leaks


@pytest.mark.parametrize("policy", [KEEP, AnonPolicy(keep_terms=("Northwind", "Support", "Sales"))])
def test_vendor_account_split_over_both_name_fields_stays_clean(tmp_path, policy):
    vendor = RawUser(id=1, first_name="Northwind", last_name="Support", username="oleg_support")
    sales = RawUser(id=3, first_name="Anna", last_name="Sales")
    store = RawStore(tmp_path / "raw")
    chat = RawChat(id=-1001, kind=KIND_SUPERGROUP, title="Ромашка / Northwind", participant_ids=(1, 2, 3), is_forum=True)
    store.put_chats([chat])
    store.put_users([vendor, CLIENT, sales])
    store.set_me_id(1)
    text = "Напишите в support, sales team обещали; Support Portal не открывается"
    store.append_messages(chat.id, [RawMessage(chat_id=chat.id, id=1, date=T0, sender_id=2, sender_kind=SENDER_USER,
                                               text=text, topic_id=3)])
    ds = anonymize(store, Mapping(tmp_path / "m.json"), Roles.build(1, sales=(3,)), policy)
    assert ds.messages[0].text == text  # labels are no surnames: product words stay
    out = tmp_path / "dataset"
    write_dataset(ds, out, Output(), {})
    assert verify(out, store, policy, tmp_path / "v.json").ok


def test_surname_that_transliterates_onto_a_label_is_scrubbed_and_the_dataset_verifies(tmp_path):
    users = [RawUser(id=2, first_name="Иван", last_name="Бот"), BOT]
    ds, out, store, report = build(tmp_path, "Ромашка", users, [(2, "Бот ответил, Боту передал"), (9, "уведомление")])
    assert [m.text for m in ds.messages] == ["<name> ответил, <name> передал", "уведомление"]
    assert report.ok, report.leaks
    assert "BOT" in next((out / "transcripts").glob("*.md")).read_text(encoding="utf-8")
    append_rows(out, {"text": "Боту передал"})
    assert ("name", "Боту") in {(k, m) for k, m, _ in leaks_of(out, store, KEEP, tmp_path)}


def test_vocabulary_is_still_hunted_in_every_free_text_field(tmp_path):
    _, out, store, report = build(tmp_path, "ООО Формат", [CLIENT], [(2, "привет")])
    assert report.ok, report.leaks
    append_rows(out,
                {"text": "Северов из Формата", "media": {"kind": "document", "name": "Северов_Формат.pdf"}},
                {"text": "", "media": {"kind": "document", "ext": "severov"}},
                {"text": "ask Petrov about the Format"},
                "Петров передал")  # a row of unexpected shape is free text
    chats = json.loads((out / "chats.json").read_text(encoding="utf-8"))
    chats[next(iter(chats))]["title"] = "Формат"
    (out / "chats.json").write_text(json.dumps(chats, ensure_ascii=False), encoding="utf-8")
    users = json.loads((out / "users.json").read_text(encoding="utf-8"))
    users[next(iter(users))]["name"] = "Формат"
    (out / "users.json").write_text(json.dumps(users, ensure_ascii=False), encoding="utf-8")
    (out / "extra.json").write_text(json.dumps({"note": "Петрову"}, ensure_ascii=False), encoding="utf-8")
    (out / "notes.md").write_text("спросить Петрова\n", encoding="utf-8")
    found = leaks_of(out, store, KEEP, tmp_path)
    assert {("name", "Северов", "messages.jsonl:text"), ("title", "Формата", "messages.jsonl:text"),
            ("name", "Северов", "messages.jsonl:media.name"), ("title", "Формат", "messages.jsonl:media.name"),
            ("name", "severov", "messages.jsonl:media.ext"), ("name", "Petrov", "messages.jsonl:text"),
            ("title", "Format", "messages.jsonl:text"), ("name", "Петров", "messages.jsonl:")} <= found
    assert any(k == "title" and m == "Формат" and loc.startswith("chats.json") for k, m, loc in found)
    assert any(k == "title" and m == "Формат" and loc.startswith("users.json") for k, m, loc in found)
    assert any(k == "name" and m == "Петрову" and loc.startswith("extra.json") for k, m, loc in found)
    assert any(k == "name" and m == "Петрова" and loc.startswith("notes.md") for k, m, loc in found)


def test_composed_fields_and_transcript_lines_are_audited_for_identifiers_only(tmp_path):
    _, out, store, report = build(tmp_path, "Ромашка", [CLIENT], [(2, "привет")])
    assert report.ok, report.leaks
    append_rows(out, {"text": "ok", "side": "CLIENT", "role": "client", "forwarded": "hidden"},
                {"text": "ask Support about the Forum", "side": "Петров", "role": "Ромашка"})
    transcript = next((out / "transcripts").glob("*.md"))
    with open(transcript, "a", encoding="utf-8") as fh:
        fh.write("[2024-01-10 10:30] #98 CLIENT U00002 Иван (client): hi\n")
        fh.write("[2024-01-10 10:31] #99 CLIENT U00002: Петров из Ромашки +79991234567 ivan@romashka.ru @oleg_support\n")
    found = leaks_of(out, store, KEEP, tmp_path)
    transcript_hits = {(k, m) for k, m, loc in found if loc.startswith("transcripts/")}
    assert transcript_hits == {("phone", "+79991234567"), ("email", "ivan@romashka.ru"), ("username", "@oleg_support")}
    assert not any(loc.endswith((":side", ":role", ":forwarded")) for _, _, loc in found)


def test_invalid_json_is_scanned_as_free_text(tmp_path):
    _, out, store, report = build(tmp_path, "Ромашка", [CLIENT], [(2, "привет")])
    assert report.ok, report.leaks
    (out / "users.json").write_text('{"U00001": {"name": "Петров", "role": "client",}', encoding="utf-8")
    with open(out / "messages.jsonl", "a", encoding="utf-8") as fh:
        fh.write('{"text": "Ромашка", "side": "CLIENT",\n')
    found = leaks_of(out, store, KEEP, tmp_path)
    assert ("name", "Петров", "users.json:1") in found
    assert any(k == "title" and m == "Ромашка" and loc.startswith("messages.jsonl") for k, m, loc in found)


# --- exactly the scrubber's exceptions -------------------------------------------------

@pytest.mark.parametrize("given, surname, text, hits", [
    ("Аким", "Ким", "Аким, передайте Киму; Ким ответит", {"Киму", "Ким"}),
    ("Isabella", "Bell", "Isabella, ask Bell please", {"Bell"}),
    ("Богдан", "Дан", "Богдан, Дан ответит", {"Дан"}),
    ("Канат", "Кан", "Канат, передайте Кану", {"Кану"}),
    ("Ханна", "Хан", "Ханна, Хану привет", {"Хану"}),
])
def test_short_surname_inside_a_kept_given_name_is_hunted(tmp_path, given, surname, text, hits):
    users = [RawUser(id=2, first_name=given), RawUser(id=3, first_name="Анна", last_name=surname)]
    store = make_store(tmp_path / "raw", "Ромашка", users, [(2, "ok")])
    known = known_from_store(store, AnonPolicy())
    assert surname in known.names and given not in known.keep_terms
    scanner = LeakScanner(known)
    assert {l.match for l in scanner.scan(text)} == hits
    assert scanner.scan(f"{given} здесь") == []
    scrubbed = Scrubber(AnonPolicy(), Roster(person_terms=(surname,))).scrub(text)
    assert given in scrubbed and not any(h in scrubbed for h in hits)


def test_kept_given_names_are_never_reported(tmp_path):
    users = [RawUser(id=2, first_name="Аким"), RawUser(id=3, first_name="Анна", last_name="Ким"),
             RawUser(id=4, first_name="Isabella"), RawUser(id=5, first_name="Anna", last_name="Bell"),
             RawUser(id=6, first_name="Богдан"), RawUser(id=7, first_name="Ольга", last_name="Дан"),
             RawUser(id=8, first_name="Соня")]
    ds, out, store, report = build(tmp_path, "Ромашка", users, [
        (2, "Аким здесь, передайте Киму лог"), (4, "Isabella here, ask Bell"), (6, "Богдан, Дан ответит"), (8, "Соня тут")])
    assert report.ok, report.leaks
    texts = [m.text for m in ds.messages]
    assert texts == ["Аким здесь, передайте <name> лог", "Isabella here, ask <name>", "Богдан, <name> ответит", "Соня тут"]
    assert LeakScanner(known_from_store(store, KEEP)).scan("Аким, Isabella, Богдан и Соня здесь") == []
    append_rows(out, {"text": "Киму передал, Bell знает, Дану тоже"})
    found = {(k, m) for k, m, _ in leaks_of(out, store, KEEP, tmp_path)}
    assert found == {("name", "Киму"), ("name", "Bell"), ("name", "Дану")}


def test_stem_collision_with_a_kept_name_is_hunted_and_the_dataset_stays_clean(tmp_path):
    users = [RawUser(id=2, first_name="Марина"), RawUser(id=3, first_name="Пётр", last_name="Марин")]
    ds, out, store, report = build(tmp_path, "Ромашка", users, [(2, "добрый день"), (3, "Марину позовите")])
    assert "Марин" in known_from_store(store, KEEP).names
    assert report.ok, report.leaks
    names = json.loads((out / "users.json").read_text(encoding="utf-8"))
    assert "Марина" in {u["name"] for u in names.values()}


def test_latin_kept_name_equal_to_a_transliterated_surname(tmp_path):
    users = [RawUser(id=2, first_name="Kim"), RawUser(id=3, first_name="Виктор", last_name="Ким")]
    _, _, _, report = build(tmp_path, "Ромашка", users, [(2, "hi"), (3, "привет")])
    assert report.ok, report.leaks


@pytest.mark.parametrize("mode", ["first", "full", "none"])
def test_clean_dataset_verifies_in_every_name_mode(tmp_path, mode):
    users = [CLIENT, RawUser(id=3, first_name="Ольга", last_name="Сидорова"),
             RawUser(id=4, first_name="Анна", last_name="Петрова"), RawUser(id=5, first_name="Аким"),
             RawUser(id=6, first_name="Анна", last_name="Ким"), BOT]
    policy = AnonPolicy(name_mode=mode, keep_bot_messages=True)
    ds, out, store, report = build(tmp_path, "ООО Ромашка / Формат", users, [
        (2, "Иван Петров на связи, Ольга тут"), (3, "Анна Петрова, привет; Киму передала"), (5, "Аким здесь"),
        (9, "уведомление")], policy=policy)
    assert report.ok, report.leaks
    known = known_from_store(store, policy)
    assert known.keep_terms == frozenset()
    assert {"Петров", "Ким"} <= known.names
    if mode == "full":
        assert {"Иван Петров", "Петров Иван"} <= known.names
        assert "Иван Петров" in {u.name for u in ds.users.values()}
    append_rows(out, {"text": "это Петров Иван и Киму"})
    assert {m for k, m, _ in leaks_of(out, store, policy, tmp_path) if k == "name"} >= {"Киму"}
    assert any(k == "name" and "Петров" in m for k, m, _ in leaks_of(out, store, policy, tmp_path))


def test_person_keyword_rule_is_audited_next_to_a_kept_first_name(tmp_path):
    users = [RawUser(id=2, first_name="Анна"), RawUser(id=3, first_name="Олег", last_name="Смирнов")]
    _, out, store, report = build(tmp_path, "Ромашка", users, [(2, "добрый день")])
    assert report.ok, report.leaks
    append_rows(out, {"text": "менеджер Анна Смирнова на связи"})
    found = {(k, m) for k, m, _ in leaks_of(out, store, KEEP, tmp_path)}
    assert ("person", "менеджер Анна Смирнова") in found


def test_org_named_shared_account_keeps_the_org_term_hunted(tmp_path):
    users = [RawUser(id=2, first_name="Ромашка Бухгалтерия")]
    ds, out, store, report = build(tmp_path, "ООО Ромашка", users, [(2, "счёт Ромашки")])
    assert ds.users[next(u.vid for u in ds.users.values() if u.role == "client")].name == ""
    assert "Ромашка" in known_from_store(store, KEEP).titles
    assert report.ok, report.leaks
    append_rows(out, {"text": "счёт Ромашки"})
    assert ("title", "Ромашки") in {(k, m) for k, m, _ in leaks_of(out, store, KEEP, tmp_path)}


# --- private files ----------------------------------------------------------------------

def mode_of(path: Path) -> int:
    return path.stat().st_mode & 0o777


@pytest.fixture
def restore_umask():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def cli_settings(tmp_path, **anon) -> Settings:
    root = tmp_path / "data"
    store = RawStore(root / "raw")
    chats = [RawChat(id=-100, kind=KIND_SUPERGROUP, title="ООО Ромашка support", participant_ids=(1, 2)),
             RawChat(id=-101, kind=KIND_SUPERGROUP, title="Beta support", participant_ids=(1, 3))]
    store.put_chats(chats)
    store.put_users([ME, RawUser(id=2, first_name="K"), RawUser(id=3, first_name="O")])
    store.set_me_id(1)
    store.append_messages(-100, [RawMessage(chat_id=-100, id=1, date=T0, sender_id=2, sender_kind=SENDER_USER,
                                            text="https://romashka.ru/x")])
    store.append_messages(-101, [RawMessage(chat_id=-101, id=1, date=T0, sender_id=3, sender_kind=SENDER_USER, text="y")])
    return Settings(project_dir=tmp_path, data_dir=root, anon=AnonPolicy(**anon))


def test_private_files_are_owner_only_and_leave_no_temporary_files(tmp_path, restore_umask):
    settings = cli_settings(tmp_path, url_mode="keep")
    stale = settings.anon_dir / "verify_report.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}")
    os.chmod(stale, 0o644)
    assert cli.cmd_anonymize(settings, argparse.Namespace()) == 0
    # A host that spells a client name under url_mode = "keep" is reported
    # (documented); the dataset stays in place for the operator to judge.
    assert cli.cmd_verify(settings, argparse.Namespace()) == 4
    report = json.loads(stale.read_text(encoding="utf-8"))
    assert any(l["match"].lower() == "romashka" for l in report["leaks"])
    assert (settings.dataset_dir / "manifest.json").exists()
    for path in (settings.mapping_path, settings.anon_dir / "anonymize_report.json", stale,
                 settings.raw_dir / "chats.json", settings.raw_dir / "users.json", settings.raw_dir / "state.json"):
        assert mode_of(path) == 0o600, path
    assert not list(settings.data_dir.rglob("*.tmp"))


def test_mapping_is_never_readable_by_others_while_written(tmp_path, monkeypatch):
    path = tmp_path / "anon" / "mapping.json"
    mapping = Mapping(path)
    mapping.user(123456789)
    mapping.save()
    before = path.read_bytes()
    mapping.user(987654321)
    seen = []
    real_dump = json.dump

    def crashing_dump(payload, fh, **kw):
        seen.append(os.fstat(fh.fileno()).st_mode & 0o777)
        real_dump(payload, fh, **kw)
        fh.flush()
        raise OSError("disk full")

    monkeypatch.setattr(json, "dump", crashing_dump)
    with pytest.raises(OSError):
        mapping.save()
    monkeypatch.undo()
    assert seen == [0o600]
    assert path.read_bytes() == before and mode_of(path) == 0o600
    assert sorted(p.name for p in path.parent.iterdir()) == ["mapping.json"]
    assert not any(b"987654321" in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())


def test_legacy_mapping_temp_and_planted_links_are_removed(tmp_path):
    anon = tmp_path / "anon"
    anon.mkdir()
    legacy = anon / "mapping.tmp"
    legacy.write_text('{"users": {"123456789": "U00001"}}')
    os.chmod(legacy, 0o644)
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (anon / "mapping.json.tmp").symlink_to(victim)
    mapping = Mapping(anon / "mapping.json")
    mapping.user(123456789)
    mapping.save()
    assert sorted(p.name for p in anon.iterdir()) == ["mapping.json"]
    assert victim.read_text() == "untouched"
    assert mode_of(anon / "mapping.json") == 0o600


def test_private_writer_ignores_a_restrictive_or_permissive_umask(tmp_path, restore_umask):
    for mask in (0o000, 0o277):
        os.umask(mask)
        target = tmp_path / f"private-{mask:o}.json"
        write_private_json(target, {"Петров": 1})
        assert mode_of(target) == 0o600
        assert json.loads(target.read_text(encoding="utf-8")) == {"Петров": 1}


def test_cli_makes_new_files_private_and_restricts_the_paths_it_owns(tmp_path, monkeypatch, restore_umask):
    for var in ("TG_DATA_DIR", "TG_SESSION", "TG_API_ID"):
        monkeypatch.delenv(var, raising=False)
    data = tmp_path / "data"
    RawStore(data / "raw").put_users([ME])
    (data / "anon").mkdir(parents=True, exist_ok=True)
    (data / "session").mkdir(parents=True, exist_ok=True)
    (data / "session" / "support.session").write_text("key")
    for loose in (data, data / "raw", data / "anon", data / "session"):
        os.chmod(loose, 0o755)
    os.chmod(data / "session" / "support.session", 0o644)
    assert cli.main(["--project", str(tmp_path), "verify"]) == 1  # no dataset yet
    # Only the tool's own paths are tightened; the directory holding them,
    # which may be the project or the operator's home, keeps its mode.
    assert mode_of(data) == 0o755
    assert mode_of(data / "raw") == 0o700
    assert mode_of(data / "anon") == 0o700
    assert mode_of(data / "session") == 0o700
    assert mode_of(data / "session" / "support.session") == 0o600
    assert os.umask(0o077) == 0o077  # left in place for the rest of the command
    store = RawStore(data / "raw")
    store.append_messages(-100, [RawMessage(chat_id=-100, id=1, date=T0, sender_id=2, sender_kind=SENDER_USER, text="x")])
    assert mode_of(data / "raw" / "messages" / "m100.jsonl") == 0o600
    assert mode_of(data / "raw" / "messages") == 0o700


def test_restrict_to_owner(tmp_path):
    restrict_to_owner(tmp_path / "missing")  # nothing to do
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o750)
    restrict_to_owner(loose)
    assert mode_of(loose) == 0o700
    read_only = tmp_path / "read-only"
    read_only.mkdir()
    os.chmod(read_only, 0o500)
    restrict_to_owner(read_only)
    assert mode_of(read_only) == 0o500
    os.chmod(read_only, 0o700)
