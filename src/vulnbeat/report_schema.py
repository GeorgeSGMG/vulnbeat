from typing import TypedDict


class SourceStatus(TypedDict):
    fetched: bool
    entries: int


class SourcesEntry(TypedDict):
    kev: SourceStatus
    epss: SourceStatus
    nvd: SourceStatus


class AppEntry(TypedDict):
    id: str
    name: str
    ecosystem: str
    repo: str
    dependencies: int


class FindingEntry(TypedDict):
    id: str
    cve: str
    package: str
    ecosystem: str
    installed_version: str | None
    fixed_version: str | None
    app: str
    cvss: float | None
    epss: float | None
    in_kev: bool
    kev_date_added: str | None
    priority_score: int
    priority_label: str
    summary: dict[str, str]
    references: list[str]


class HistoryEntry(TypedDict):
    date: str
    findings_total: int
    critical: int
    high: int


class Report(TypedDict):
    generated_at: str
    sources: SourcesEntry
    apps: list[AppEntry]
    findings: list[FindingEntry]
    history: list[HistoryEntry]