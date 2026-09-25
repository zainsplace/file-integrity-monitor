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


def scan_json(baseline, target, capsys):
    capsys.readouterr()
    rc = fim.main(["scan", "--baseline", str(baseline), str(target), "--json"])
    return rc, json.loads(capsys.readouterr().out)


def modified_classes(result, name):
    matches = [m for m in result["modified"] if m["path"].endswith(name)]
    assert len(matches) == 1
    return matches[0]["classes"]


def make_symlink(target, link):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need extra privileges on this platform")


posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


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


@posix_only
def test_attack2_setuid_chmod_is_flagged_as_permissions_only(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    target_file = tree / "a.txt"
    before = target_file.stat().st_mode
    os.chmod(target_file, 0o4755)
    rc, result = scan_json(baseline, tree, capsys)
    assert rc == 1
    classes = modified_classes(result, "a.txt")
    assert set(classes) == {"permissions"}
    change = classes["permissions"][0]
    assert change["baseline"] == before & 0o7777
    assert change["current"] & 0o4000


def test_attack2_owner_change_is_flagged_as_owner_only():
    baseline = [{"path": "etc/app.conf", "type": "file", "uid": 0, "gid": 0}]
    current = [{"path": "etc/app.conf", "type": "file", "uid": 1000, "gid": 0}]
    result = fim.diff(baseline, current)
    assert set(modified_classes(result, "app.conf")) == {"owner"}


def test_attack2_content_edit_with_mtime_restored_still_shows_content(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    target_file = tree / "a.txt"
    original = target_file.stat()
    target_file.write_text("omega\n")
    os.utime(target_file, ns=(original.st_atime_ns, original.st_mtime_ns))
    rc, result = scan_json(baseline, tree, capsys)
    assert rc == 1
    classes = modified_classes(result, "a.txt")
    assert "content" in classes
    assert "mtime" not in classes


def test_attack3_file_swapped_for_symlink_is_recorded_not_followed(tmp_path, tree, capsys):
    secret = tmp_path / "secret.txt"
    secret.write_text("not part of the baseline\n")
    baseline = create_baseline(tmp_path, tree)
    (tree / "a.txt").unlink()
    make_symlink(secret, tree / "a.txt")
    rc, result = scan_json(baseline, tree, capsys)
    assert rc == 1
    content = modified_classes(result, "a.txt")["content"]
    changes = {c["field"]: c["current"] for c in content}
    assert changes["type"] == "symlink"
    assert changes["target"] == str(secret)
    assert changes["sha256"] is None


def test_attack3_symlinked_directory_is_not_descended(tmp_path, tree):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("keep out\n")
    make_symlink(outside, tree / "linked")
    entries, errors = fim.collect_entries([str(tree)])
    by_name = {Path(e["path"]).name: e for e in entries}
    assert errors == []
    assert by_name["linked"]["type"] == "symlink"
    assert "private.txt" not in by_name


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW unavailable")
def test_attack3_hashing_refuses_to_follow_a_symlink(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("data\n")
    link = tmp_path / "link.txt"
    make_symlink(real, link)
    assert fim.hash_file(str(real)) is not None
    assert fim.hash_file(str(link)) is None


def test_attack3_inode_swap_with_identical_content_is_flagged_as_inode(tmp_path, tree, capsys):
    baseline = create_baseline(tmp_path, tree)
    target_file = tree / "a.txt"
    original = target_file.stat()
    replacement = tree / "replacement.tmp"
    replacement.write_bytes(target_file.read_bytes())
    os.chmod(replacement, original.st_mode & 0o7777)
    os.replace(replacement, target_file)
    os.utime(target_file, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert target_file.stat().st_ino != original.st_ino
    rc, result = scan_json(baseline, tree, capsys)
    assert rc == 1
    assert set(modified_classes(result, "a.txt")) == {"inode"}


def test_signature_is_stable_across_entry_order():
    entries = [
        {"path": "b", "type": "file"},
        {"path": "a", "type": "file"},
    ]
    assert fim.sign(KEY.encode(), entries) == fim.sign(KEY.encode(), list(reversed(entries)))
