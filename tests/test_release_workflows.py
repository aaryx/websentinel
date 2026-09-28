"""Local release automation contracts (remote execution is separate evidence)."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_workflows_are_pinned_and_release_is_manual():
    for file in (ROOT / ".github/workflows").glob("*.yml"):
        document = yaml.safe_load(file.read_text(encoding="utf-8"))
        for job in document["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    # PyYAML's YAML 1.1 parser treats the workflow key 'on' as boolean True.
    assert set(release[True]) == {"workflow_dispatch"}
    job = release["jobs"]["candidate"]
    assert job["environment"] == "release"
    assert job["permissions"]["contents"] == "read"
    assert "refs/tags/v" in job["if"]


def test_release_checksums_match_exact_artifact(tmp_path):
    spec = importlib.util.spec_from_file_location("manifest", ROOT / "scripts/release_manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ValueError, match="No built"):
        module.write_manifest(tmp_path)
    artifact = tmp_path / "example.whl"
    artifact.write_bytes(b"fixture artifact")
    hashes = module.write_manifest(tmp_path)
    assert hashes[artifact.name] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert (tmp_path / "SHA256SUMS").read_text().strip().endswith("  example.whl")
    assert json.loads((tmp_path / "build-environment.json").read_text())["artifacts"] == hashes
