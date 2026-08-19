import json

from vulnbeat.models import Component, Ecosystem, Scope

PIP_VERSION_OPERATORS = ["==", ">=", "<=", "~=", "!=", ">", "<"]
NPM_RANGE_INDICATORS = ["^", "~", ">=", "<=", ">", "<", "latest", "*"]

NPM_DEPENDENCIES_KEY = "dependencies"
NPM_DEV_DEPENDENCIES_KEY = "devDependencies"

# CLI-friendly aliases for --target, mapped to their real Ecosystem.
TARGET_ALIASES = {
    "pip": Ecosystem.PYPI,
    "npm": Ecosystem.NPM,
}


def parse_requirements(content: str) -> dict[str, Component]:
    components = {}
    for line in content.splitlines():
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


def _parse_dependency_block(deps: dict[str, str], scope: Scope) -> dict[str, Component]:
    components = {}
    for name, version in deps.items():
        exact = not any(version.startswith(indicator) for indicator in NPM_RANGE_INDICATORS)

        components[name.lower()] = Component(
            version=version if exact else None,
            constraint=version,
            exact=exact,
            scope=scope,
            ecosystem=Ecosystem.NPM,
        )
    return components


def parse_package_json(content: str) -> dict[str, Component]:
    data = json.loads(content)
    components = {}
    components.update(_parse_dependency_block(data.get(NPM_DEPENDENCIES_KEY, {}), Scope.PRODUCTION))
    components.update(_parse_dependency_block(data.get(NPM_DEV_DEPENDENCIES_KEY, {}), Scope.DEVELOPMENT))
    return components


# Maps each Ecosystem to the function that parses its manifest format.
PARSER_REGISTRY = {
    Ecosystem.PYPI: parse_requirements,
    Ecosystem.NPM: parse_package_json,
}


if __name__ == "__main__":
    import argparse

    import requests

    parser = argparse.ArgumentParser(description="Manually test inventory parsing against a real manifest.")
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
        url = "https://raw.githubusercontent.com/snyk-labs/nodejs-goof/main/package.json"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        components = parse_package_json(response.text)
        print(f"Parsed {len(components)} components from nodejs-goof.")