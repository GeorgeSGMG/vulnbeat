import json
from datetime import datetime, timezone
from pathlib import Path

from vulnbeat.models import Finding, MonitoredApp
from vulnbeat.report_schema import AppEntry, FindingEntry, Report


def write_report(
    kev_entry_count: int,
    apps: list[MonitoredApp],
    component_counts: dict[str, int],
    findings: list[Finding],
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
    for finding in findings:
        findings_data.append({
            "cve": finding.vulnerability.cve_id,
            "package": finding.package_name,
            "ecosystem": finding.component.ecosystem.value,
            "installed_version": finding.component.version,
            "app": finding.app_id,
            "in_kev": True,
            "kev_date_added": finding.vulnerability.date_added,
            "summary": finding.vulnerability.short_description,
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