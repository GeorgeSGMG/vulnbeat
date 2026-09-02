import json
import tempfile
from pathlib import Path

from vulnbeat.cli_runner import run_cli
from vulnbeat.models import Component, Ecosystem, Scope

SBOM_MANIFEST_FILENAMES = {
    Ecosystem.PYPI: "requirements.txt",
    Ecosystem.NPM: "package.json",
}

SBOM_LOCKFILE_FILENAMES = {
    Ecosystem.NPM: "package-lock.json",
}

SBOM_OUTPUT_FILENAME = "sbom.json"

SBOM_COMPONENTS_KEY = "components"
SBOM_NAME_KEY = "name"
SBOM_VERSION_KEY = "version"


def generate_sbom(manifest_content: str, ecosystem: Ecosystem, lockfile_content: str | None = None) -> str:
    manifest_filename = SBOM_MANIFEST_FILENAMES[ecosystem]

    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest_path = Path(tmp_dir) / manifest_filename
        manifest_path.write_text(manifest_content, encoding="utf-8")

        if lockfile_content is not None:
            lockfile_filename = SBOM_LOCKFILE_FILENAMES[ecosystem]
            lockfile_path = Path(tmp_dir) / lockfile_filename
            lockfile_path.write_text(lockfile_content, encoding="utf-8")

        sbom_path = Path(tmp_dir) / SBOM_OUTPUT_FILENAME
        run_cli(["syft", f"dir:{tmp_dir}", "-o", f"cyclonedx-json={sbom_path}"])

        return sbom_path.read_text(encoding="utf-8")


def parse_sbom(sbom_json: str, ecosystem: Ecosystem, scopes: dict[str, Scope]) -> dict[str, Component]:
    data = json.loads(sbom_json)

    components = {}
    for entry in data.get(SBOM_COMPONENTS_KEY, []):
        if SBOM_VERSION_KEY not in entry:
            continue

        name = entry[SBOM_NAME_KEY].lower()
        version = entry[SBOM_VERSION_KEY]

        components[name] = Component(
            version=version,
            constraint=version,
            exact=True,
            scope=scopes.get(name, Scope.PRODUCTION),
            ecosystem=ecosystem,
        )
    return components