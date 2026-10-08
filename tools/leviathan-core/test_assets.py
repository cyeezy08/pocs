import pytest

from leviathan_core import config
from leviathan_core.assets import InventoryError, load_inventory, inventory_from_httpx


def write(tmp_path, body):
    p = tmp_path / "inv.yaml"
    p.write_text(body)
    return p


VALID = """
attestation: authorized
owner_contact: sec@acme.test
assets:
  - identifier: mail.acme.test
    cpe: cpe:2.3:a:acme:super_server:14.3:*:*:*:*:*:*:*
    keywords: ["super server"]
"""


def test_valid_inventory_loads(tmp_path):
    assets = load_inventory(write(tmp_path, VALID))
    assert len(assets) == 1
    a = assets[0]
    assert a.vendor == "acme" and a.product == "super_server" and a.version == "14.3"


def test_refuses_missing_attestation(tmp_path):
    with pytest.raises(InventoryError, match="attestation"):
        load_inventory(write(tmp_path, VALID.replace("attestation: authorized", "")))


def test_refuses_wrong_attestation(tmp_path):
    with pytest.raises(InventoryError, match="attestation"):
        load_inventory(write(tmp_path, VALID.replace("authorized", "true")))


def test_refuses_empty_assets(tmp_path):
    with pytest.raises(InventoryError, match="non-empty"):
        load_inventory(write(tmp_path, "attestation: authorized\nowner_contact: x\nassets: []"))


def test_refuses_bad_cpe(tmp_path):
    bad = VALID.replace("cpe:2.3:a:acme", "cpe:1.0:a:acme")
    with pytest.raises(InventoryError, match="cpe"):
        load_inventory(write(tmp_path, bad))


def test_httpx_skeleton_carries_attestation():
    inv = inventory_from_httpx("a.acme.test\nb.acme.test\n", "acme.test")
    assert inv["attestation"] == config.REQUIRED_ATTESTATION
    assert len(inv["assets"]) == 2
    # skeleton must survive the same gate it feeds
    loaded = load_inventory_dict(inv)
    assert loaded[0].source == "httpx"


def load_inventory_dict(d):
    import yaml, tempfile, pathlib
    f = pathlib.Path(tempfile.mkdtemp()) / "inv.yaml"
    f.write_text(yaml.safe_dump(d))
    return load_inventory(f)
