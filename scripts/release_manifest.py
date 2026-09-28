"""Hash the exact built artifacts and record the build environment."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform


def write_manifest(directory: Path):
    artifacts = sorted(directory.glob("*.whl")) + sorted(directory.glob("*.tar.gz"))
    if not artifacts:
        raise ValueError("No built distribution artifacts found")
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}
    (directory / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in hashes.items()), encoding="utf-8")
    environment = {
        "python": platform.python_version(), "platform": platform.platform(),
        "artifacts": hashes,
        "packages": sorted(f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions()),
    }
    (directory / "build-environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
    return hashes


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    print(json.dumps(write_manifest(parser.parse_args().directory), indent=2))
