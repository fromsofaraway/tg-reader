"""The tool closes only the paths it owns, never the directory that holds
them, and a misspelled section or setting in config.toml is an error instead
of a silently dropped privacy switch."""

import os
import shutil
import stat
from pathlib import Path

import pytest

from tg_collector import cli
from tg_collector.config import ConfigError, Settings
from tg_collector.rawstore import restrict_file_to_owner, restrict_private_paths, restrict_to_owner

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def mode_of(path: Path) -> int:
    return path.stat().st_mode & 0o777


@pytest.fixture
def loose_umask():
    """Run as a user whose new files would be group- and world-readable."""
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A project directory with no inherited Telegram environment."""
    for var in ("TG_DATA_DIR", "TG_SESSION", "TG_API_ID", "TG_API_HASH", "TG_PHONE"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def run_verify(project_dir: Path) -> int:
    """Any command is enough: the restriction happens before the dispatch."""
    return cli.main(["--project", str(project_dir), "verify"])


def make_session(path: Path, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("authorization key", encoding="utf-8")
    os.chmod(path, mode)
    return path


# --- session files -----------------------------------------------------------

def test_session_outside_the_data_dir_is_restricted(project, tmp_path, loose_umask):
    """TG_DATA_DIR moved away leaves the default session behind; it is the
    account's login key and must stop being world-readable anyway."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (project / ".env").write_text(f"TG_DATA_DIR={elsewhere}\n", encoding="utf-8")
    session = make_session(project / "data" / "session" / "support.session")
    assert run_verify(project) == 1  # no dataset, but the key is safe now
    assert mode_of(session) == 0o600


def test_session_path_written_with_its_suffix_is_restricted_once(project, loose_umask):
    (project / ".env").write_text("TG_SESSION=data/session/support.session\n", encoding="utf-8")
    session = make_session(project / "data" / "session" / "support.session")
    run_verify(project)
    assert mode_of(session) == 0o600
    assert not (project / "data" / "session" / "support.session.session").exists()


def test_absolute_session_leaves_its_directory_alone(project, tmp_path, loose_umask):
    home_like = tmp_path / "home"
    home_like.mkdir()
    os.chmod(home_like, 0o755)
    session = make_session(home_like / "acct.session")
    (project / ".env").write_text(f"TG_SESSION={session}\n", encoding="utf-8")
    run_verify(project)
    assert mode_of(session) == 0o600
    assert mode_of(home_like) == 0o755


def test_sqlite_side_files_of_the_session_are_restricted(project, loose_umask):
    base = project / "data" / "session" / "support"
    make_session(Path(str(base) + ".session"))
    journal = make_session(Path(str(base) + ".session-journal"))
    wal = make_session(Path(str(base) + ".session-wal"))
    run_verify(project)
    assert mode_of(journal) == 0o600 and mode_of(wal) == 0o600


def test_a_missing_or_already_private_session_is_left_alone(project, loose_umask):
    assert run_verify(project) == 1  # no session at all: no error
    session = make_session(project / "data" / "session" / "support.session", 0o600)
    before = session.stat().st_ctime_ns  # a chmod would move it
    run_verify(project)
    assert mode_of(session) == 0o600 and session.stat().st_ctime_ns == before


def test_a_symlinked_session_does_not_redirect_the_chmod(tmp_path):
    target = make_session(tmp_path / "target.session")
    link = tmp_path / "link.session"
    link.symlink_to(target)
    restrict_file_to_owner(link)
    assert mode_of(target) == 0o644


def test_a_fifo_at_the_session_path_is_untouched_and_does_not_block(tmp_path):
    fifo = tmp_path / "support.session"
    os.mkfifo(fifo)
    os.chmod(fifo, 0o644)  # explicit: mkfifo obeys the umask
    restrict_private_paths(session=fifo)  # would hang without O_NONBLOCK
    assert stat.S_ISFIFO(fifo.stat().st_mode) and mode_of(fifo) == 0o644


def test_a_directory_is_not_mistaken_for_a_session_file(tmp_path):
    a_dir = tmp_path / "support.session"
    a_dir.mkdir()
    os.chmod(a_dir, 0o755)
    restrict_file_to_owner(a_dir)
    assert mode_of(a_dir) == 0o755


# --- only the tool's own paths ------------------------------------------------

def test_the_data_dir_itself_keeps_its_mode(project, tmp_path, loose_umask):
    """TG_DATA_DIR may name the project directory or a home directory; the
    tool must not quietly close it to the rest of the machine."""
    home_like = tmp_path / "home"
    public = home_like / "Public"
    public.mkdir(parents=True)
    os.chmod(home_like, 0o755)
    os.chmod(public, 0o755)
    (project / ".env").write_text(f"TG_DATA_DIR={home_like}\n", encoding="utf-8")
    assert run_verify(project) == 1
    assert mode_of(home_like) == 0o755 and mode_of(public) == 0o755


def test_the_project_dir_as_data_dir_keeps_its_mode(project, loose_umask):
    (project / ".env").write_text("TG_DATA_DIR=.\n", encoding="utf-8")
    os.chmod(project, 0o755)
    assert run_verify(project) == 1
    assert mode_of(project) == 0o755


def test_an_old_export_becomes_unreachable_for_other_users(project, loose_umask):
    messages = project / "data" / "raw" / "messages"
    messages.mkdir(parents=True)
    old = messages / "m100.jsonl"
    old.write_text('{"id": 1}\n', encoding="utf-8")
    anon = project / "data" / "anon"
    anon.mkdir(parents=True)
    (anon / "mapping.json").write_text("{}", encoding="utf-8")
    for loose in (project / "data", project / "data" / "raw", anon):
        os.chmod(loose, 0o755)
    os.chmod(old, 0o644)
    assert run_verify(project) == 1
    assert mode_of(project / "data" / "raw") == 0o700  # the file inside is out of reach
    assert mode_of(anon) == 0o700
    assert mode_of(project / "data") == 0o755


# --- an unusable data dir is not a traceback ----------------------------------

def test_a_data_dir_below_a_regular_file_reports_instead_of_crashing(project, capsys):
    a_file = project / "afile"
    a_file.write_text("not a directory", encoding="utf-8")
    (project / ".env").write_text(f"TG_DATA_DIR={a_file / 'data'}\n", encoding="utf-8")
    assert run_verify(project) == 1  # "No dataset in ...", no NotADirectoryError
    assert "No dataset in" in capsys.readouterr().err
    # login never touches the data directory, so it must reach its own check
    assert cli.main(["--project", str(project), "login"]) == 1
    assert "Missing Telegram credentials" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_data_dir_behind_a_closed_parent_reports_instead_of_crashing(project):
    closed = project / "closed"
    closed.mkdir()
    (project / ".env").write_text(f"TG_DATA_DIR={closed / 'data'}\n", encoding="utf-8")
    os.chmod(closed, 0o000)
    try:
        assert run_verify(project) == 1  # no PermissionError traceback
    finally:
        os.chmod(closed, 0o700)


def test_restrict_to_owner_skips_what_is_not_a_directory(tmp_path):
    a_file = tmp_path / "afile"
    a_file.write_text("x", encoding="utf-8")
    os.chmod(a_file, 0o644)
    restrict_to_owner(a_file)
    assert mode_of(a_file) == 0o644
    restrict_to_owner(a_file / "data")  # ENOTDIR, not an exception
    restrict_to_owner(tmp_path / "missing")


# --- unknown sections and settings --------------------------------------------

def load_with_config(tmp_path: Path, toml: str) -> Settings:
    (tmp_path / "config.toml").write_text(toml, encoding="utf-8")
    return Settings.load(tmp_path)


@pytest.mark.parametrize("toml, expected", [
    ('[anonymise]\nkeep_terms = ["Northwind"]\n', "anonymize"),
    ('[anonymize]\nkeep_term = ["Northwind"]\n', "keep_terms"),
    ('[anonymize]\ncustom_term = ["Acme Ltd"]\n', "custom_terms"),
    ('[anonymize]\nscrub_domain = false\n', "scrub_domains"),
    ('[anonymize]\ncard_bin = ["424242"]\n', "card_bins"),
    ('[export]\nwait = 5\n', "wait_time"),
    ('[output]\nname_mode = "none"\n', "[anonymize]"),
    ('[anonymize]\nurl_mode = "keep"\nmax_chars = 0\n', "[output]"),
    ('[staff]\nsuport = ["@oleg_support"]\n', "support"),
    ('wait_time = 5\n', "outside any section"),
])
def test_a_misspelled_name_is_an_error_naming_the_real_one(tmp_path, toml, expected):
    with pytest.raises(ConfigError) as exc:
        load_with_config(tmp_path, toml)
    assert expected in str(exc.value)


def test_a_wrongly_typed_setting_names_its_section_not_itself(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_with_config(tmp_path, '[anonymize]\nkeep_terms = "Northwind"\n')
    assert "[anonymize] keep_terms" in str(exc.value)
    assert "[keep_terms]" not in str(exc.value)


def test_every_documented_setting_still_loads(tmp_path):
    settings = load_with_config(tmp_path, """
[chats]
include_types = ["group", "supergroup"]
include_ids = [-1001]
exclude_ids = [-1002]
exclude_title_regex = ["^\\\\[INT\\\\]"]
include_archived = true
exclude_internal = true
[staff]
support = ["@oleg_support"]
sales = [777]
other = ["@boss"]
[anonymize]
name_mode = "first"
keep_chat_titles = false
keep_service_messages = false
url_mode = "domain"
allow_domains = ["example.com"]
keep_terms = ["Northwind"]
custom_terms = ["Ромашка"]
custom_patterns = ['(?<=КПП )\\d{9}']
scrub_last_names = true
scrub_chat_titles = true
keep_bot_messages = true
keep_file_names = false
card_bins = ["424242", "400000"]
scrub_domains = true
generic_title_share = 0.2
[output]
timezone = "Europe/Berlin"
episode_gap_hours = 6
max_chars = 200000
max_message_chars = 2000
turn_merge_seconds = 120
[export]
wait_time = 3.0
chat_wait = 3.0
participants_wait = 2.0
flood_sleep_threshold = 3600
max_flood_wait = 7200
max_retries = 5
flush_every = 500
takeout = false
""")
    assert settings.anon.keep_terms == ("Northwind",) and settings.anon.card_bins == ("424242", "400000")
    assert settings.output.timezone == "Europe/Berlin" and settings.export.wait_time == 3.0


def test_an_empty_config_and_the_shipped_example_load(tmp_path):
    assert load_with_config(tmp_path, "").anon.name_mode == "first"
    example = tmp_path / "example"
    example.mkdir()
    shutil.copy(PROJECT_ROOT / "config.example.toml", example / "config.toml")
    assert Settings.load(example).anon.scrub_last_names is True


# --- the documented pacing matches the code -----------------------------------

def test_the_readme_claims_a_random_addition_only_where_the_code_adds_one():
    """telegram.py hands wait_time to Telethon, which spaces history pages
    exactly that far apart; only _pause (chat_wait, participants_wait) adds a
    random amount, and the README promises jitter only there."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    pacing = " ".join(readme[readme.index("* Pacing."):readme.index("* `FloodWait`")].split())
    assert "no random addition" in pacing
    promise = pacing.index("random addition of up to half")
    sentence = pacing[pacing.rindex(".", 0, promise) + 1: pacing.index(".", promise)]
    assert "chat_wait" in sentence and "participants_wait" in sentence
    assert "wait_time" not in sentence  # history pages get no jitter
    source = (PROJECT_ROOT / "src" / "tg_collector" / "telegram.py").read_text(encoding="utf-8")
    assert "wait_time=self._tuning.wait_time" in source  # still Telethon's own spacing


def test_the_example_config_documents_the_same_pacing_as_the_readme():
    example = (PROJECT_ROOT / "config.example.toml").read_text(encoding="utf-8")
    comment = example[example.index("wait_time = 1.0"):example.index("chat_wait")]
    assert "no random addition" in comment and "30 s" in comment
