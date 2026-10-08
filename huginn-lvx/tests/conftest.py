"""Shared fixtures: isolated state dir + env scrub."""

from __future__ import annotations

import pytest


@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    monkeypatch.setenv("HUG_STATE_DIR", str(root))
    monkeypatch.delenv("HUG_EVENTS_URL", raising=False)
    return str(root)


@pytest.fixture()
def clean_env(monkeypatch):
    for var in (
        "HUG_GH_USER", "HUG_X_API_KEY", "HUG_X_API_SECRET",
        "HUG_X_ACCESS_TOKEN", "HUG_X_ACCESS_SECRET",
        "HUG_TG_TOKEN", "HUG_TG_CHAT",
    ):
        monkeypatch.delenv(var, raising=False)
