import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Every test gets its own data dir so nothing touches the real user's config or database."""
    monkeypatch.setenv("NETSCOPE_DATA_DIR", str(tmp_path / "data"))
    for var in ("NETSCOPE_LAT", "NETSCOPE_LON", "NETSCOPE_LABEL", "MAXMIND_LICENSE_KEY"):
        monkeypatch.delenv(var, raising=False)
