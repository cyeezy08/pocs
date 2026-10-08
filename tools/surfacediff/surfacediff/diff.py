"""Diff math: added / removed / changed, with field-level attribute deltas."""
from __future__ import annotations

from .normalize import Asset


def _attr_delta(old: dict, new: dict) -> dict:
    added = {k: new[k] for k in new.keys() - old.keys()}
    removed = {k: old[k] for k in old.keys() - new.keys()}
    changed = {k: {"from": old[k], "to": new[k]} for k in old.keys() & new.keys() if old[k] != new[k]}
    return {"added": added, "removed": removed, "changed": changed}


def diff_records(old_records: dict, new_records: dict) -> dict:
    old_keys = set(old_records)
    new_keys = set(new_records)
    added = [new_records[k] for k in sorted(new_keys - old_keys)]
    removed = [old_records[k] for k in sorted(old_keys - new_keys)]
    changed = []
    for k in sorted(old_keys & new_keys):
        o, n = old_records[k], new_records[k]
        if o.get("hash") != n.get("hash") or o.get("attrs") != n.get("attrs"):
            changed.append({"key": k, "kind": n.get("kind", ""),
                            "delta": _attr_delta(o.get("attrs", {}), n.get("attrs", {}))})
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        "has_changes": bool(added or removed or changed),
    }


def diff_assets(old: list[Asset], new: list[Asset]) -> dict:
    old_recs = {a.key: a.to_record() for a in old}
    new_recs = {a.key: a.to_record() for a in new}
    return diff_records(old_recs, new_recs)
