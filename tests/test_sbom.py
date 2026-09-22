import json

from vulnbeat.models import Ecosystem, Scope
from vulnbeat.sbom import SBOM_COMPONENTS_KEY, SBOM_NAME_KEY, SBOM_VERSION_KEY, parse_sbom


def _sbom(components: list[dict]) -> str:
    return json.dumps({SBOM_COMPONENTS_KEY: components})


def test_single_version_component_is_exact():
    sbom_json = _sbom([{SBOM_NAME_KEY: "lodash", SBOM_VERSION_KEY: "4.17.21"}])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert components["lodash"].version == "4.17.21"
    assert components["lodash"].constraint == "4.17.21"
    assert components["lodash"].exact is True
    assert components["lodash"].ecosystem == Ecosystem.NPM


def test_scope_defaults_to_production_when_missing():
    sbom_json = _sbom([{SBOM_NAME_KEY: "lodash", SBOM_VERSION_KEY: "4.17.21"}])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert components["lodash"].scope == Scope.PRODUCTION


def test_scope_is_taken_from_scopes_argument():
    sbom_json = _sbom([{SBOM_NAME_KEY: "eslint", SBOM_VERSION_KEY: "8.0.0"}])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {"eslint": Scope.DEVELOPMENT})
    assert components["eslint"].scope == Scope.DEVELOPMENT


def test_entry_without_version_is_skipped():
    sbom_json = _sbom([{SBOM_NAME_KEY: "broken-package"}])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert "broken-package" not in components


def test_same_name_same_version_twice_stays_exact():
    sbom_json = _sbom([
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.14"},
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.14"},
    ])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert components["handlebars"].version == "4.0.14"
    assert components["handlebars"].constraint == "4.0.14"
    assert components["handlebars"].exact is True


def test_same_name_different_versions_becomes_ambiguous():
    sbom_json = _sbom([
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.11"},
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.14"},
    ])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert components["handlebars"].version is None
    assert components["handlebars"].constraint is None
    assert components["handlebars"].exact is False


def test_ambiguity_preserves_scope_and_ecosystem():
    sbom_json = _sbom([
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.11"},
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.14"},
    ])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {"handlebars": Scope.DEVELOPMENT})
    assert components["handlebars"].scope == Scope.DEVELOPMENT
    assert components["handlebars"].ecosystem == Ecosystem.NPM


def test_third_occurrence_does_not_undo_ambiguity():
    sbom_json = _sbom([
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.11"},
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.14"},
        {SBOM_NAME_KEY: "handlebars", SBOM_VERSION_KEY: "4.0.11"},
    ])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert components["handlebars"].version is None
    assert components["handlebars"].constraint is None
    assert components["handlebars"].exact is False


def test_name_is_lowercased():
    sbom_json = _sbom([{SBOM_NAME_KEY: "Lodash", SBOM_VERSION_KEY: "4.17.21"}])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert "lodash" in components
    assert "Lodash" not in components


def test_empty_components_list_returns_empty_dict():
    sbom_json = _sbom([])
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert components == {}


def test_missing_components_key_returns_empty_dict():
    sbom_json = json.dumps({})
    components = parse_sbom(sbom_json, Ecosystem.NPM, {})
    assert components == {}