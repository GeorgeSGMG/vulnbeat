from dataclasses import dataclass
from enum import Enum


# --- Enums ---


class Scope(str, Enum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"


class Ecosystem(str, Enum):
    PYPI = "PyPI"
    NPM = "npm"


class Source(str, Enum):
    REMOTE = "remote"
    LOCAL = "local"


# --- Monitored apps configuration ---


@dataclass(frozen=True)
class MonitoredApp:
    id: str
    name: str
    ecosystem: Ecosystem
    repo: str
    source: Source
    manifest_url: str | None
    manifest_path: str | None

    def __post_init__(self) -> None:
        if self.source == Source.REMOTE:
            if not self.manifest_url or self.manifest_path is not None:
                raise ValueError(f"{self.id}: source=remote requires manifest_url and no manifest_path")
        elif self.source == Source.LOCAL:
            if not self.manifest_path or self.manifest_url is not None:
                raise ValueError(f"{self.id}: source=local requires manifest_path and no manifest_url")


# --- Components, vulnerabilities, and findings ---


@dataclass(frozen=True)
class Component:
    version: str | None
    constraint: str | None
    exact: bool
    scope: Scope
    ecosystem: Ecosystem


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str


@dataclass(frozen=True)
class Finding:
    app_id: str
    package_name: str
    component: Component
    vulnerability: Vulnerability