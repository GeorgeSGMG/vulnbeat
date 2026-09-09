import json
from datetime import datetime, timezone
from pathlib import Path

from vulnbeat.models import MonitoredApp, PriorityLabel, PrioritizedFinding, SourceCounts
from vulnbeat.report_schema import AppEntry, FindingEntry, HistoryEntry, Report

REPORT_HISTORY_KEY = "history"


def _read_previous_history(output_path: str) -> list[HistoryEntry]:
    path = Path(output_path)
    if not path.exists():
        return []

    try:
        with open(path, encoding="utf-8") as f:
            previous_report = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    return previous_report.get(REPORT_HISTORY_KEY, [])


def write_report(
    source_counts: SourceCounts,
    apps: list[MonitoredApp],
    component_counts: dict[str, int],
    prioritized_findings: list[PrioritizedFinding],
    output_path: str,
) -> None:
    generated_at = datetime.now(timezone.utc)

    apps_data: list[AppEntry] = []
    for app in apps:
        apps_data.append({
            "id": app.id,
            "name": app.name,
            "ecosystem": app.ecosystem.value,
            "repo": app.repo,
            "dependencies": component_counts[app.id],
        })

    findings_data: list[FindingEntry] = []
    for prioritized_finding in prioritized_findings:
        finding = prioritized_finding.finding
        priority = prioritized_finding.priority
        vulnerability = finding.vulnerability

        finding_id = f"{finding.app_id}:{vulnerability.cve_id}:{finding.package_name}"

        findings_data.append({
            "id": finding_id,
            "cve": vulnerability.cve_id,
            "package": finding.package_name,
            "ecosystem": finding.component.ecosystem.value,
            "installed_version": finding.component.version,
            "fixed_version": vulnerability.fixed_version,
            "app": finding.app_id,
            "cvss": vulnerability.cvss,
            "epss": vulnerability.epss,
            "in_kev": vulnerability.in_kev,
            "kev_date_added": vulnerability.kev_date_added,
            "priority_score": priority.score,
            "priority_label": priority.label.value,
            "summary": vulnerability.summary.values,
            "references": vulnerability.references,
        })

    report_date = generated_at.date().isoformat()

    history_entry: HistoryEntry = {
        "date": report_date,
        "findings_total": len(findings_data),
        "critical": sum(1 for f in findings_data if f["priority_label"] == PriorityLabel.CRITICAL.value),
        "high": sum(1 for f in findings_data if f["priority_label"] == PriorityLabel.HIGH.value),
    }

    history = [entry for entry in _read_previous_history(output_path) if entry["date"] != report_date]
    history.append(history_entry)

    report: Report = {
        "generated_at": generated_at.isoformat(),
        "sources": {
            "kev": {"fetched": True, "entries": source_counts.kev},
            "epss": {"fetched": True, "entries": source_counts.epss},
            "nvd": {"fetched": True, "entries": source_counts.nvd},
        },
        "apps": apps_data,
        "findings": findings_data,
        "history": history,
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)