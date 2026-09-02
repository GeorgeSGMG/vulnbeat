import json
from typing import Callable

from vulnbeat.models import Component, Ecosystem, Scope

PIP_VERSION_OPERATORS = ["==", ">=", "<=", "~=", "!=", ">", "<"]

LOCK_PACKAGES_KEY = "packages"
LOCK_VERSION_KEY = "version"
LOCK_DEV_KEY = "dev"
LOCK_NODE_MODULES_PREFIX = "node_modules/"

# CLI-friendly aliases for --target, mapped to their real Ecosystem.
TARGET_ALIASES = {
    "pip": Ecosystem.PYPI,
    "npm": Ecosystem.NPM,
}


def parse_requirements(manifest_content: str, lockfile_content: str | None = None) -> dict[str, Component]:
    components = {}
    for line in manifest_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        name = line
        version = None
        constraint = None
        exact = False

        for op in PIP_VERSION_OPERATORS:
            if op in line:
                name, rhs = line.split(op, 1)
                constraint = op + rhs
                exact = (op == "==")

                if exact and any(extra_op in rhs for extra_op in PIP_VERSION_OPERATORS):
                    # Malformed: more than one constraint after "==".
                    exact = False

                if exact:
                    version = rhs.strip()

                break

        components[name.strip().lower()] = Component(
            version=version,
            constraint=constraint,
            exact=exact,
            scope=Scope.PRODUCTION,
            ecosystem=Ecosystem.PYPI,
        )
    return components


def parse_package_lock(manifest_content: str, lockfile_content: str | None = None) -> dict[str, Component]:
    assert lockfile_content is not None
    data = json.loads(lockfile_content)

    components = {}
    depths_by_name = {}

    for path, entry in data.get(LOCK_PACKAGES_KEY, {}).items():
        if not path.startswith(LOCK_NODE_MODULES_PREFIX):
            continue

        name = path.rsplit(LOCK_NODE_MODULES_PREFIX, 1)[-1].lower()
        version = entry.get(LOCK_VERSION_KEY)
        if version is None:
            continue

        depth = path.count(LOCK_NODE_MODULES_PREFIX)

        if name in depths_by_name and depth >= depths_by_name[name]:
            continue

        is_dev = entry.get(LOCK_DEV_KEY, False)

        components[name] = Component(
            version=version,
            constraint=version,
            exact=True,
            scope=Scope.DEVELOPMENT if is_dev else Scope.PRODUCTION,
            ecosystem=Ecosystem.NPM,
        )
        depths_by_name[name] = depth

    return components


def extract_scopes(components: dict[str, Component]) -> dict[str, Scope]:
    return dict((name, component.scope) for name, component in components.items())


ComponentParser = Callable[[str, str | None], dict[str, Component]]

# Maps each Ecosystem to the function that parses its dependency data (manifest and/or lockfile).
PARSER_REGISTRY: dict[Ecosystem, ComponentParser] = {
    Ecosystem.PYPI: parse_requirements,
    Ecosystem.NPM: parse_package_lock,
}


if __name__ == "__main__":
    import argparse

    import requests

    parser = argparse.ArgumentParser(description="Manually test inventory parsing against real dependency data.")
    parser.add_argument("target", choices=TARGET_ALIASES.keys(), help="Which parser to exercise.")
    args = parser.parse_args()

    ecosystem = TARGET_ALIASES[args.target]

    if ecosystem == Ecosystem.PYPI:
        url = "https://raw.githubusercontent.com/adeyosemanputra/pygoat/master/requirements.txt"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        components = parse_requirements(response.text)
        print(f"Parsed {len(components)} components from pygoat.")
    else:
        manifest_url = "https://raw.githubusercontent.com/snyk-labs/nodejs-goof/main/package.json"
        lockfile_url = "https://raw.githubusercontent.com/snyk-labs/nodejs-goof/main/package-lock.json"
        manifest_response = requests.get(manifest_url, timeout=30)
        manifest_response.raise_for_status()
        lockfile_response = requests.get(lockfile_url, timeout=30)
        lockfile_response.raise_for_status()
        components = parse_package_lock(manifest_response.text, lockfile_response.text)
        print(f"Parsed {len(components)} components from nodejs-goof.")