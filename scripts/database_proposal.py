"""Materialize the reviewed bootstrap in a new temporary copy, never in Database checkout."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROPOSALS = ROOT / "docs/proposals"


def proposed_bootstrap(reference):
    manifest = json.loads((PROPOSALS / "database-v1.1-manifest.json").read_text())
    source = (Path(reference) / manifest["source"]).read_bytes()
    patch = PROPOSALS / manifest["patch"]
    if (
        hashlib.sha256(source).hexdigest() != manifest["source_sha256"]
        or hashlib.sha256(patch.read_bytes()).hexdigest() != manifest["patch_sha256"]
    ):
        raise RuntimeError("Referencia/paquete no coincide con el manifiesto revisado")
    with tempfile.TemporaryDirectory(prefix="vulntrack-bootstrap-review-") as temporary:
        copy = Path(temporary)
        (copy / "sql").mkdir()
        (copy / manifest["source"]).write_bytes(source)
        for arguments in [["--check"], []]:
            subprocess.run(
                ["git", "apply", *arguments, str(patch)], cwd=copy, check=True, capture_output=True
            )
        result = (copy / manifest["source"]).read_bytes()
    if hashlib.sha256(result).hexdigest() != manifest["proposed_sha256"]:
        raise RuntimeError("Resultado del bootstrap no coincide con el manifiesto")
    return result.decode()


def main():
    parser = argparse.ArgumentParser(
        description="Validar/materializar propuesta sin tocar Database"
    )
    parser.add_argument("--database-v1", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="Archivo nuevo; nunca se sobrescribe")
    args = parser.parse_args()
    result = proposed_bootstrap(args.database_v1)
    if args.output:
        with args.output.open("x") as target:
            target.write(result)
    print("Propuesta verificada; SHA256=" + hashlib.sha256(result.encode()).hexdigest())


if __name__ == "__main__":
    main()
