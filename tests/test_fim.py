import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fim

KEY = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def fim_key(monkeypatch):
    monkeypatch.setenv("FIM_KEY", KEY)


@pytest.fixture
def tree(tmp_path):
    target = tmp_path / "watched"
    target.mkdir()
    (target / "a.txt").write_text("alpha\n")
    (target / "sub").mkdir()
    (target / "sub" / "b.txt").write_text("bravo\n")
    return target


def create_baseline(tmp_path, target):
    baseline = tmp_path / "baseline.json"
    rc = fim.main(["create", "--baseline", str(baseline), str(target)])
    assert rc == 0
    return baseline


def test_create_then_verify_succeeds(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    rc = fim.main(["verify", "--baseline", str(baseline)])
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_scan_reports_no_changes_on_untouched_tree(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    rc = fim.main(["scan", "--baseline", str(baseline), str(tree)])
    assert rc == 0
    assert "no changes" in capsys.readouterr().out


def test_scan_detects_modified_content(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    (tree / "a.txt").write_text("tampered\n")
    rc = fim.main(["scan", "--baseline", str(baseline), str(tree)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "MODIFIED" in out
    assert "content" in out


def test_scan_detects_added_file(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    (tree / "planted.txt").write_text("new\n")
    rc = fim.main(["scan", "--baseline", str(baseline), str(tree)])
    assert rc == 1
    assert "ADDED" in capsys.readouterr().out


def test_scan_detects_removed_file(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    (tree / "sub" / "b.txt").unlink()
    rc = fim.main(["scan", "--baseline", str(baseline), str(tree)])
    assert rc == 1
    assert "REMOVED" in capsys.readouterr().out


def test_scan_emits_machine_readable_json(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    (tree / "planted.txt").write_text("new\n")
    capsys.readouterr()
    rc = fim.main(["scan", "--baseline", str(baseline), str(tree), "--json"])
    assert rc == 1
    result = json.loads(capsys.readouterr().out)
    assert any(path.endswith("planted.txt") for path in result["added"])


def test_verify_rejects_tampered_baseline(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    document = json.loads(baseline.read_text())
    document["entries"][0]["sha256"] = "0" * 64
    baseline.write_text(json.dumps(document))
    rc = fim.main(["verify", "--baseline", str(baseline)])
    assert rc == 2
    assert "INVALID" in capsys.readouterr().err


def test_scan_refuses_tampered_baseline(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    document = json.loads(baseline.read_text())
    document["entries"] = []
    baseline.write_text(json.dumps(document))
    rc = fim.main(["scan", "--baseline", str(baseline), str(tree)])
    assert rc == 2
    assert "ABORT" in capsys.readouterr().err


def test_verify_fails_with_wrong_key(tmp_path, tree, monkeypatch):
    baseline = create_baseline(tmp_path, tree)
    monkeypatch.setenv("FIM_KEY", "wrong-key-wrong-key-wrong-key")
    rc = fim.main(["verify", "--baseline", str(baseline)])
    assert rc == 2


def test_short_key_is_rejected(tmp_path, tree, monkeypatch):
    monkeypatch.setenv("FIM_KEY", "short")
    with pytest.raises(SystemExit):
        fim.main(["create", "--baseline", str(tmp_path / "b.json"), str(tree)])


def test_missing_key_is_rejected(tmp_path, tree, monkeypatch):
    monkeypatch.delenv("FIM_KEY")
    with pytest.raises(SystemExit):
        fim.main(["create", "--baseline", str(tmp_path / "b.json"), str(tree)])


def test_key_file_overrides_environment(tmp_path, tree, monkeypatch):
    key_file = tmp_path / "fim.key"
    key_file.write_text(KEY + "\n")
    monkeypatch.delenv("FIM_KEY")
    baseline = tmp_path / "baseline.json"
    rc = fim.main(
        ["--key-file", str(key_file), "create", "--baseline", str(baseline), str(tree)]
    )
    assert rc == 0
    rc = fim.main(["--key-file", str(key_file), "verify", "--baseline", str(baseline)])
    assert rc == 0


def test_missing_target_becomes_warning_not_crash(tmp_path, tree, capsys):
    baseline = tmp_path / "baseline.json"
    rc = fim.main(
        ["create", "--baseline", str(baseline), str(tree), str(tmp_path / "ghost")]
    )
    assert rc == 0
    assert "does not exist" in capsys.readouterr().err


def test_hash_file_returns_none_for_unreadable_path(tmp_path):
    assert fim.hash_file(str(tmp_path)) is None


def test_mtime_only_change_is_classified_as_mtime(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    target_file = tree / "a.txt"
    os.utime(target_file, (1000000000, 1000000000))
    rc = fim.main(["scan", "--baseline", str(baseline), str(tree)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "MODIFIED" in out
    assert "mtime" in out


def test_signature_is_stable_across_entry_order():
    entries = [
        {"path": "b", "type": "file"},
        {"path": "a", "type": "file"},
    ]
    assert fim.sign(KEY.encode(), entries) == fim.sign(KEY.encode(), list(reversed(entries)))
