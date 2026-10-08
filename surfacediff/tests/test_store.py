import json

import pytest

from surfacediff.normalize import Asset
from surfacediff.store import latest_pair, list_snapshots, load, snap


def make(n=3):
    return [Asset("host", f"host{i}.example.com") for i in range(n)]


def test_snap_writes_pointer_and_meta(tmp_path):
    p = snap(str(tmp_path), "subs", make(), tags={"source": "subfinder"})
    ptr = (tmp_path / "subs" / "current").read_text()
    assert p.name == ptr and ptr.endswith(".jsonl")
    first = json.loads(p.read_text().splitlines()[0])
    assert "_meta" in first and first["_meta"]["tags"]["source"] == "subfinder"
    assert first["_meta"]["format"] == 1


def test_records_sorted_by_key(tmp_path):
    snap(str(tmp_path), "subs", make())
    data = load(str(tmp_path), "subs", "current")
    keys = list(data["records"])
    assert keys == sorted(keys)


def test_load_by_timestamp_prefix(tmp_path):
    p1 = snap(str(tmp_path), "subs", make(1))
    p2 = snap(str(tmp_path), "subs", make(3))
    ref = p2.stem[:15]
    data = load(str(tmp_path), "subs", ref)
    assert len(data["records"]) == 3


def test_latest_pair_uses_two_most_recent(tmp_path):
    snap(str(tmp_path), "subs", make(1))
    snap(str(tmp_path), "subs", make(2))
    snap(str(tmp_path), "subs", make(4))
    old, new = latest_pair(str(tmp_path), "subs", None)
    assert len(old["records"]) == 2 and len(new["records"]) == 4
    assert len(list_snapshots(str(tmp_path), "subs")) == 3


def test_invalid_label_refused(tmp_path):
    with pytest.raises(ValueError):
        snap(str(tmp_path), "../evil", [])
