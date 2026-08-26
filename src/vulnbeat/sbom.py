import json
import tempfile
from pathlib import Path

from vulnbeat.cli_runner import run_cli
from vulnbeat.inventory import extract_scopes
from vulnbeat.models import Component, Ecosystem, Scope

SBOM_MANIFEST_FILENAMES = {
    Ecosystem.PYPI: "requirements.txt",
    Ecosystem.NPM: "package.json",
}

SBOM_OUTPUT_FILENAME = "sbom.json"

SBOM_COMPONENTS_KEY = "components"
SBOM_NAME_KEY = "name"
SBOM_VERSION_KEY = "version"


def _generate_sbom(content: str, ecosystem: Ecosystem) -> str:
    filename = SBOM_MANIFEST_FILENAMES[ecosystem]

    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest_path = Path(tmp_dir) / filename
        manifest_path.write_text(content, encoding="utf-8")

        sbom_path = Path(tmp_dir) / SBOM_OUTPUT_FILENAME
        run_cli(["syft", f"dir:{tmp_dir}", "-o", f"cyclonedx-json={sbom_path}"])

        return sbom_path.read_text(encoding="utf-8")


def _parse_sbom(sbom_json: str, ecosystem: Ecosystem, scopes: dict[str, Scope]) -> dict[str, Component]:
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


def build_components(content: str, ecosystem: Ecosystem, inventory_components: dict[str, Component]) -> dict[str, Component]:
    sbom_json = _generate_sbom(content, ecosystem)
    scopes = extract_scopes(inventory_components)
    return _parse_sbom(sbom_json, ecosystem, scopes)