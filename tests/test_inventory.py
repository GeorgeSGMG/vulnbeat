import json

from vulnbeat.inventory import (
    LOCK_DEV_KEY,
    LOCK_NODE_MODULES_PREFIX,
    LOCK_PACKAGES_KEY,
    LOCK_VERSION_KEY,
    parse_package_lock,
    parse_requirements,
)
from vulnbeat.models import Scope

# --- parse_requirements ---


def test_line_without_version_has_no_constraint():
    components = parse_requirements("requests")
    assert components["requests"].version is None
    assert components["requests"].constraint is None
    assert components["requests"].exact is False


def test_exact_version_is_captured():
    components = parse_requirements("requests==2.32.0")
    assert components["requests"].version == "2.32.0"
    assert components["requests"].constraint == "==2.32.0"
    assert components["requests"].exact is True


def test_non_exact_constraint_single_operator():
    components = parse_requirements("requests>=2.0")
    assert components["requests"].version is None
    assert components["requests"].constraint == ">=2.0"
    assert components["requests"].exact is False


def test_non_exact_constraint_with_second_operator_is_captured_whole():
    components = parse_requirements("requests>=1.0,<=2.0")
    assert components["requests"].version is None
    assert components["requests"].constraint == ">=1.0,<=2.0"
    assert components["requests"].exact is False


def test_comments_and_blank_lines_are_ignored():
    manifest = "# a comment\n\nrequests==2.32.0"
    components = parse_requirements(manifest)
    assert len(components) == 1
    assert "requests" in components


def test_flag_lines_are_ignored():
    manifest = "-r other.txt\nrequests==2.32.0"
    components = parse_requirements(manifest)
    assert len(components) == 1
    assert "requests" in components


def test_malformed_exact_constraint_with_second_operator_is_not_exact():
    components = parse_requirements("requests==2.32.0,<=3.0")
    assert components["requests"].version is None
    assert components["requests"].constraint == "==2.32.0,<=3.0"
    assert components["requests"].exact is False


# --- parse_package_lock ---


def _lockfile(packages: dict) -> str:
    return json.dumps({LOCK_PACKAGES_KEY: packages})


def test_regular_package_is_parsed():
    lockfile = _lockfile({
        f"{LOCK_NODE_MODULES_PREFIX}lodash": {LOCK_VERSION_KEY: "4.17.21"},
    })
    components = parse_package_lock("", lockfile)
    assert components["lodash"].version == "4.17.21"
    assert components["lodash"].constraint == "4.17.21"
    assert components["lodash"].exact is True
    assert components["lodash"].scope == Scope.PRODUCTION


def test_dev_dependency_has_development_scope():
    lockfile = _lockfile({
        f"{LOCK_NODE_MODULES_PREFIX}eslint": {LOCK_VERSION_KEY: "8.0.0", LOCK_DEV_KEY: True},
    })
    components = parse_package_lock("", lockfile)
    assert components["eslint"].scope == Scope.DEVELOPMENT


def test_shallower_depth_wins_regardless_of_order():
    lockfile = _lockfile({
        f"{LOCK_NODE_MODULES_PREFIX}foo/{LOCK_NODE_MODULES_PREFIX}lodash": {LOCK_VERSION_KEY: "3.0.0"},
        f"{LOCK_NODE_MODULES_PREFIX}lodash": {LOCK_VERSION_KEY: "4.17.21"},
    })
    components = parse_package_lock("", lockfile)
    assert components["lodash"].version == "4.17.21"


def test_entry_without_version_is_skipped():
    lockfile = _lockfile({
        f"{LOCK_NODE_MODULES_PREFIX}broken-package": {},
    })
    components = parse_package_lock("", lockfile)
    assert "broken-package" not in components


def test_root_entry_is_skipped():
    lockfile = _lockfile({
        "": {"name": "root-project", LOCK_VERSION_KEY: "1.0.0"},
        f"{LOCK_NODE_MODULES_PREFIX}lodash": {LOCK_VERSION_KEY: "4.17.21"},
    })
    components = parse_package_lock("", lockfile)
    assert len(components) == 1
    assert "root-project" not in components