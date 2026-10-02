import plistlib
import sys
import urllib.error

import pytest

from netscope import geo, paths, privilege, shortcut
from netscope.settings import Settings


# ── settings ─────────────────────────────────────────────────────────────────
def test_settings_default_unset():
    assert Settings().home.is_set is False


def test_settings_roundtrip():
    Settings().set_home(44.98, -93.27, "Home")
    again = Settings().home
    assert (again.lat, again.lon, again.label, again.is_set) == (44.98, -93.27, "Home", True)


def test_settings_env_overrides(monkeypatch):
    Settings().set_home(1, 2)
    monkeypatch.setenv("NETSCOPE_LAT", "10")
    monkeypatch.setenv("NETSCOPE_LON", "20")
    monkeypatch.setenv("NETSCOPE_LABEL", "Env")
    h = Settings().home
    assert (h.lat, h.lon, h.label) == (10, 20, "Env")


def test_settings_bad_env_is_ignored(monkeypatch):
    monkeypatch.setenv("NETSCOPE_LAT", "abc")
    monkeypatch.setenv("NETSCOPE_LON", "1")
    assert Settings().home.is_set is False


def test_settings_reject_out_of_range():
    with pytest.raises(ValueError):
        Settings().set_home(91, 0)


# ── geo ──────────────────────────────────────────────────────────────────────
def test_geo_without_database_returns_none():
    db = geo.GeoDB()
    assert not db.ready and db.lookup("8.8.8.8") is None


def test_dbip_falls_back_to_previous_month(monkeypatch, tmp_path):
    import gzip
    import io

    calls = []

    class Resp(io.BytesIO):
        headers = {"Content-Length": "0"}

    def fake_open(url, timeout=30):
        calls.append(url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(url, 404, "nf", {}, None)
        return Resp(gzip.compress(b"fake-mmdb"))

    monkeypatch.setattr(geo, "_open", fake_open)
    monkeypatch.setattr(geo, "_validate", lambda p: None)
    dest = tmp_path / "db.mmdb"
    geo._fetch_dbip(dest, None)
    assert dest.read_bytes() == b"fake-mmdb"
    assert len(calls) == 2 and calls[0] != calls[1]
    assert list(tmp_path.glob("*.part")) == []


def test_invalid_download_is_discarded(monkeypatch, tmp_path):
    import gzip
    import io

    class Resp(io.BytesIO):
        headers = {}

    monkeypatch.setattr(geo, "_open", lambda url, timeout=30: Resp(gzip.compress(b"garbage")))
    dest = tmp_path / "db.mmdb"
    with pytest.raises((RuntimeError, ValueError, OSError)):  # maxminddb rejects the garbage file
        geo._fetch_dbip(dest, None)
    assert not dest.exists() and list(tmp_path.glob("*.part")) == []


# ── privilege ────────────────────────────────────────────────────────────────
def test_helper_args_contain_port_and_token():
    args = privilege.helper_args(1234, "tok")
    assert args[-5:] == ["--capture-helper", "--port", "1234", "--token", "tok"]


def test_macos_script_is_safely_quoted(monkeypatch):
    monkeypatch.setattr(sys, "executable", '/Users/a b/py"thon')
    script = privilege.macos_script(1234, "tok")
    assert script.startswith("do shell script ")
    assert "with administrator privileges" in script
    # shell-quoted for sh ('...'), then the double quote escaped for the AppleScript string (\")
    assert "'/Users/a b/py\\\"thon'" in script


# ── shortcut ─────────────────────────────────────────────────────────────────
def test_macos_app_bundle(tmp_path):
    app = shortcut.create_macos_app(tmp_path, python="/usr/bin/python3")
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    assert info["CFBundleExecutable"] == "NetScope" and info["CFBundlePackageType"] == "APPL"
    launcher = app / "Contents" / "MacOS" / "NetScope"
    assert launcher.stat().st_mode & 0o100
    assert "-m netscope" in launcher.read_text() and "/usr/bin/python3" in launcher.read_text()


def test_data_dir_honours_override(tmp_path):
    assert paths.data_dir() == tmp_path / "data"


def test_ignore_cidrs_setting_is_forwarded_to_the_helper(monkeypatch):
    monkeypatch.setenv("NETSCOPE_IGNORE_CIDRS", "")
    assert privilege.helper_args(1, "t")[-2:] == ["--ignore-cidrs", ""]
    monkeypatch.delenv("NETSCOPE_IGNORE_CIDRS")
    assert "--ignore-cidrs" not in privilege.helper_args(1, "t")
