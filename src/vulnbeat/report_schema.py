from typing import TypedDict


class KevSourceEntry(TypedDict):
    entries: int


class SourcesEntry(TypedDict):
    kev: KevSourceEntry


class AppEntry(TypedDict):
    id: str
    name: str
    ecosystem: str
    repo: str
    dependencies: int


class FindingEntry(TypedDict):
    cve: str
    package: str
    ecosystem: str
    installed_version: str | None
    app: str
    in_kev: bool
    kev_date_added: str
    priority_score: int
    priority_label: str
    summary: str


class Report(TypedDict):
    generated_at: str
    sources: SourcesEntry
    apps: list[AppEntry]
    findings: list[FindingEntry]