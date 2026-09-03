import json
import logging
import tempfile
from pathlib import Path

from vulnbeat.cli_runner import run_cli
from vulnbeat.localization import LocalizedText
from vulnbeat.models import Component, EpssScore, Finding, NvdEnrichment, NvdVulnStatus, ScanMatch, Vulnerability

logger = logging.getLogger(__name__)

SCAN_INPUT_FILENAME = "sbom.json"

SCAN_MATCHES_KEY = "matches"
SCAN_VULNERABILITY_KEY = "vulnerability"
SCAN_ID_KEY = "id"
SCAN_ARTIFACT_KEY = "artifact"
SCAN_NAME_KEY = "name"
SCAN_FIX_KEY = "fix"
SCAN_FIX_STATE_KEY = "state"
SCAN_FIX_VERSIONS_KEY = "versions"
SCAN_FIX_STATE_FIXED = "fixed"

CVE_PREFIX = "CVE-"


def scan_sbom(sbom_json: str) -> str:
    with tempfile.TemporaryDirectory() as tmp_dir:
        sbom_path = Path(tmp_dir) / SCAN_INPUT_FILENAME
        sbom_path.write_text(sbom_json, encoding="utf-8")

        return run_cli(["grype", f"sbom:{sbom_path}", "--by-cve", "-o", "json"])


def _extract_fixed_version(vulnerability: dict) -> str | None:
    fix_info = vulnerability.get(SCAN_FIX_KEY, {})
    if fix_info.get(SCAN_FIX_STATE_KEY) != SCAN_FIX_STATE_FIXED:
        return None

    versions = fix_info.get(SCAN_FIX_VERSIONS_KEY, [])
    return versions[0] if versions else None


def extract_scan_matches(scan_json: str) -> list[ScanMatch]:
    data = json.loads(scan_json)

    matches = []
    for match in data.get(SCAN_MATCHES_KEY, []):
        vulnerability = match[SCAN_VULNERABILITY_KEY]
        cve_id = vulnerability[SCAN_ID_KEY]
        if not cve_id.startswith(CVE_PREFIX):
            continue

        matches.append(
            ScanMatch(
                cve_id=cve_id,
                package_name=match[SCAN_ARTIFACT_KEY][SCAN_NAME_KEY],
                fixed_version=_extract_fixed_version(vulnerability),
            )
        )
    return matches


def assemble_findings(
    app_id: str,
    components: dict[str, Component],
    matches: list[ScanMatch],
    nvd_data: dict[str, NvdEnrichment],
    epss_scores: dict[str, EpssScore],
    dates_by_cve: dict[str, str],
) -> list[Finding]:
    findings = []
    for match in matches:
        component = components.get(match.package_name)
        if component is None:
            continue

        enrichment = nvd_data.get(match.cve_id)
        if enrichment is not None and enrichment.vuln_status == NvdVulnStatus.REJECTED:
            logger.warning(f"Skipping {match.cve_id}: rejected by NVD")
            continue

        if enrichment is None:
            logger.warning(f"No NVD enrichment available for {match.cve_id}; publishing without CVSS/summary/references from NVD")
            summary = LocalizedText(values={})
            cvss = None
            references = []
        else:
            summary = enrichment.summary
            cvss = enrichment.cvss
            references = enrichment.references

        epss_score = epss_scores.get(match.cve_id)

        vulnerability = Vulnerability(
            cve_id=match.cve_id,
            fixed_version=match.fixed_version,
            cvss=cvss,
            epss=epss_score.epss if epss_score else None,
            in_kev=match.cve_id in dates_by_cve,
            kev_date_added=dates_by_cve.get(match.cve_id),
            summary=summary,
            references=references,
        )

        findings.append(
            Finding(
                app_id=app_id,
                package_name=match.package_name,
                component=component,
                vulnerability=vulnerability,
            )
        )
    return findings