import pytest

from tg_collector.config import ConfigError, Settings
from tg_collector.model import RawUser, Roles


def test_defaults_without_files(tmp_path):
    s = Settings.load(tmp_path)
    assert s.data_dir == tmp_path / "data"
    assert s.telegram.api_id is None
    assert s.chats.include_types == {"group", "supergroup"}
    assert s.anon.name_mode == "first" and s.anon.url_mode == "drop"
    assert s.export.members_cache_hours == 24
    with pytest.raises(ConfigError):
        s.telegram.require()


def test_env_and_toml(tmp_path):
    (tmp_path / ".env").write_text('TG_API_ID=12345\nTG_API_HASH="abc"\n# comment\nTG_PHONE=+79990000000\n')
    (tmp_path / "config.toml").write_text("""
[chats]
include_types = ["supergroup"]
exclude_ids = [-1001, "-1002"]
exclude_title_regex = ["^\\\\[INT\\\\]"]
[staff]
sales = ["@ivan", 777]
other = ["@boss"]
[anonymize]
name_mode = "none"
url_mode = "domain"
allow_domains = ["Docs.Example.com"]
keep_terms = ["Northwind"]
[output]
timezone = "Europe/Berlin"
max_chars = 0
""")
    s = Settings.load(tmp_path)
    assert s.telegram.api_id == 12345 and s.telegram.api_hash == "abc" and s.telegram.phone == "+79990000000"
    assert s.chats.include_types == {"supergroup"}
    assert s.chats.exclude_ids == {-1001, -1002}
    assert s.chats.title_excluded("[INT] sync") and not s.chats.title_excluded("Acme")
    assert s.staff.sales == ("@ivan", 777) and s.staff.other == ("@boss",)
    assert s.anon.name_mode == "none" and s.anon.allow_domains == ("docs.example.com",)
    assert s.output.timezone == "Europe/Berlin" and s.output.max_chars == 0
    snapshot = s.public_snapshot()
    assert "api" not in str(snapshot) and "777" not in str(snapshot)


@pytest.mark.parametrize("toml", [
    '[anonymize]\nname_mode = "weird"',
    '[anonymize]\ncustom_patterns = ["("]',
    "[anonymize]\ncustom_patterns = ['\\d*']",
    '[chats]\nexclude_ids = ["abc"]',
    '[output]\ntimezone = "Mars/Olympus"',
    '[chats]\nexclude_title_regex = ["("]',
    '[export]\nmembers_cache_hours = -1',
])
def test_invalid_config_is_rejected(tmp_path, toml):
    (tmp_path / "config.toml").write_text(toml)
    with pytest.raises(ConfigError):
        Settings.load(tmp_path)


def test_roles():
    roles = Roles.build(1, support=["@Helper"], sales=["ivan", 777], other=["@boss", 888])
    assert roles.of(RawUser(id=888)) == "other" and roles.of(RawUser(id=2, username="BOSS")) == "other"
    assert roles.is_staff(RawUser(id=888))
    from tg_collector.model import side_of
    assert side_of("other") == "STAFF"
    assert roles.of(RawUser(id=1)) == "support"
    assert roles.of(RawUser(id=5, username="helper")) == "support"
    assert roles.of(RawUser(id=6, username="IVAN")) == "sales"
    assert roles.of(RawUser(id=777)) == "sales"
    assert roles.of(RawUser(id=8, usernames=("x", "ivan"))) == "sales"
    assert roles.of(RawUser(id=9, is_bot=True, username="ivan")) == "bot"
    assert roles.of(RawUser(id=10, is_deleted=True)) == "deleted"
    assert roles.of(RawUser(id=11, first_name="Client")) == "client"


def test_card_bins_config(tmp_path):
    (tmp_path / "config.toml").write_text('[anonymize]\ncard_bins = ["424242", 400000]\n')
    assert Settings.load(tmp_path).anon.card_bins == ("424242", "400000")
    (tmp_path / "config.toml").write_text('[anonymize]\ncard_bins = ["47"]\n')
    with pytest.raises(ConfigError):
        Settings.load(tmp_path)
