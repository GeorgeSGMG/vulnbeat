import json
from datetime import datetime, timezone
from pathlib import Path

from vulnbeat.models import MonitoredApp, PrioritizedFinding
from vulnbeat.report_schema import AppEntry, FindingEntry, Report


def write_report(
    kev_entry_count: int,
    apps: list[MonitoredApp],
    component_counts: dict[str, int],
    prioritized_findings: list[PrioritizedFinding],
    output_path: str,
) -> None:
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

    report: Report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "kev": {"entries": kev_entry_count},
        },
        "apps": apps_data,
        "findings": findings_data,
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)