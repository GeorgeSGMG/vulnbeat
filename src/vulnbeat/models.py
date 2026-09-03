from dataclasses import dataclass
from enum import Enum

from vulnbeat.shared.localization import LocalizedText


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


class NvdVulnStatus(str, Enum):
    RECEIVED = "Received"
    AWAITING_ANALYSIS = "Awaiting Analysis"
    UNDERGOING_ANALYSIS = "Undergoing Analysis"
    ANALYZED = "Analyzed"
    MODIFIED = "Modified"
    DEFERRED = "Deferred"
    REJECTED = "Rejected"


class PriorityLabel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


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
    lockfile_url: str | None
    lockfile_path: str | None

    def __post_init__(self) -> None:
        self._validate_manifest_source()
        self._validate_lockfile_requirement()

    def _validate_manifest_source(self) -> None:
        if self.source == Source.REMOTE:
            if not self.manifest_url or self.manifest_path is not None:
                raise ValueError(f"{self.id}: source=remote requires manifest_url and no manifest_path")
            if self.lockfile_path is not None:
                raise ValueError(f"{self.id}: source=remote requires no lockfile_path")
        elif self.source == Source.LOCAL:
            if not self.manifest_path or self.manifest_url is not None:
                raise ValueError(f"{self.id}: source=local requires manifest_path and no manifest_url")
            if self.lockfile_url is not None:
                raise ValueError(f"{self.id}: source=local requires no lockfile_url")

    def _validate_lockfile_requirement(self) -> None:
        lockfile = self.lockfile_url if self.source == Source.REMOTE else self.lockfile_path

        if self.ecosystem == Ecosystem.NPM:
            if not lockfile:
                raise ValueError(f"{self.id}: ecosystem=npm requires a lockfile ({'lockfile_url' if self.source == Source.REMOTE else 'lockfile_path'})")
        else:
            if lockfile:
                raise ValueError(f"{self.id}: ecosystem={self.ecosystem.value} must not have a lockfile")


# --- Vulnerability matching pipeline ---


@dataclass(frozen=True)
class Component:
    version: str | None
    constraint: str | None
    exact: bool
    scope: Scope
    ecosystem: Ecosystem


@dataclass(frozen=True)
class ScanMatch:
    cve_id: str
    package_name: str
    fixed_version: str | None


@dataclass(frozen=True)
class ScannedApp:
    app: MonitoredApp
    components: dict[str, Component]
    matches: list[ScanMatch]


@dataclass(frozen=True)
class EpssScore:
    cve_id: str
    epss: float
    percentile: float


@dataclass(frozen=True)
class NvdEnrichment:
    cve_id: str
    vuln_status: NvdVulnStatus
    cvss: float | None
    summary: LocalizedText
    references: list[str]


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    fixed_version: str | None
    cvss: float | None
    epss: float | None
    in_kev: bool
    kev_date_added: str | None
    summary: LocalizedText
    references: list[str]


@dataclass(frozen=True)
class Finding:
    app_id: str
    package_name: str
    component: Component
    vulnerability: Vulnerability


# --- Priority scoring ---


@dataclass(frozen=True)
class PriorityResult:
    score: int
    label: PriorityLabel


@dataclass(frozen=True)
class PrioritizedFinding:
    finding: Finding
    priority: PriorityResult


# --- Publication metadata ---


@dataclass(frozen=True)
class SourceCounts:
    kev: int
    epss: int
    nvd: int