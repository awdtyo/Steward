"""Tests for the steward CLI and incident memory."""

import pytest

from steward import store
from steward.cli import main
from steward.config import load_config


@pytest.fixture
def settings(tmp_path):
    return load_config({"DRY_RUN": "true",
                        "STEWARD_DB": str(tmp_path / "memory.db")})


def test_incident_add_list_search(settings, capsys):
    assert main(["incident", "add", "--symptom", "disk full on media",
                 "--cause", "transcode cache", "--fix", "pruned /tmp",
                 "--service", "jellyfin", "--tags", "disk,cache"],
                settings) == 0
    out = capsys.readouterr().out
    assert "Recorded incident #1" in out

    assert main(["incident", "list"], settings) == 0
    out = capsys.readouterr().out
    assert "disk full on media" in out and "pruned /tmp" in out

    assert main(["incident", "search", "transcode"], settings) == 0
    assert "disk full" in capsys.readouterr().out

    assert main(["incident", "search", "nothing-matches"], settings) == 0
    assert "No incidents" in capsys.readouterr().out


def test_add_requires_symptom(settings):
    conn = store.init_db(":memory:")
    with pytest.raises(ValueError, match="Symptom"):
        store.memory_add(conn, symptom="  ")
    conn.close()


def test_missing_subcommand_exits_nonzero(settings, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["incident", "add", "--cause", "x"], settings)
    assert exc.value.code == 2


def test_search_escapes_like_wildcards(settings, tmp_path):
    conn = store.init_db(str(tmp_path / "like.db"))
    store.memory_add(conn, symptom="100% disk usage", service="host")
    rows = store.memory_search(conn, "100%")
    assert len(rows) == 1 and rows[0]["symptom"] == "100% disk usage"
    assert store.memory_search(conn, "100_") == []
    conn.close()
