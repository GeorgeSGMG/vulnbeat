import json

from vulnbeat.crossref import (
    SCAN_ARTIFACT_KEY,
    SCAN_FIX_KEY,
    SCAN_FIX_STATE_FIXED,
    SCAN_FIX_STATE_KEY,
    SCAN_FIX_VERSIONS_KEY,
    SCAN_ID_KEY,
    SCAN_MATCHES_KEY,
    SCAN_NAME_KEY,
    SCAN_VERSION_KEY,
    SCAN_VULNERABILITY_KEY,
    assemble_findings,
    extract_scan_matches,
)
from vulnbeat.models import (
    Component,
    Ecosystem,
    EpssScore,
    NvdEnrichment,
    NvdVulnStatus,
    ScanMatch,
    Scope,
)
from vulnbeat.shared.localization import LocalizedText

# --- extract_scan_matches ---


def _scan(matches: list[dict]) -> str:
    return json.dumps({SCAN_MATCHES_KEY: matches})


def _match_json(cve_id: str = "CVE-2014-0160", name: str = "pkg", version: str = "1.0.0", fix: dict | None = None) -> dict:
    vulnerability: dict[str, object] = {SCAN_ID_KEY: cve_id}
    if fix is not None:
        vulnerability[SCAN_FIX_KEY] = fix
    return {
        SCAN_VULNERABILITY_KEY: vulnerability,
        SCAN_ARTIFACT_KEY: {SCAN_NAME_KEY: name, SCAN_VERSION_KEY: version},
    }


def test_normal_match_with_fixed_version():
    scan_json = _scan([_match_json(
        cve_id="CVE-2014-0160",
        name="pkg",
        version="1.0.0",
        fix={SCAN_FIX_STATE_KEY: SCAN_FIX_STATE_FIXED, SCAN_FIX_VERSIONS_KEY: ["1.0.1"]},
    )])
    matches = extract_scan_matches(scan_json)
    assert len(matches) == 1
    match = matches[0]
    assert match.cve_id == "CVE-2014-0160"
    assert match.package_name == "pkg"
    assert match.installed_version == "1.0.0"
    assert match.fixed_version == "1.0.1"


def test_non_cve_match_is_skipped():
    scan_json = _scan([_match_json(cve_id="GHSA-xxxx-yyyy-zzzz")])
    matches = extract_scan_matches(scan_json)
    assert matches == []


def test_not_fixed_state_has_no_fixed_version():
    scan_json = _scan([_match_json(fix={SCAN_FIX_STATE_KEY: "not-fixed"})])
    matches = extract_scan_matches(scan_json)
    assert matches[0].fixed_version is None


def test_fixed_state_with_empty_versions_has_no_fixed_version():
    scan_json = _scan([_match_json(fix={SCAN_FIX_STATE_KEY: SCAN_FIX_STATE_FIXED, SCAN_FIX_VERSIONS_KEY: []})])
    matches = extract_scan_matches(scan_json)
    assert matches[0].fixed_version is None


def test_missing_fix_key_has_no_fixed_version():
    scan_json = _scan([_match_json(fix=None)])
    matches = extract_scan_matches(scan_json)
    assert matches[0].fixed_version is None


def test_identical_matches_are_deduplicated():
    entry = _match_json()
    scan_json = _scan([entry, entry])
    matches = extract_scan_matches(scan_json)
    assert len(matches) == 1


def test_same_cve_and_package_different_version_are_kept_separately():
    scan_json = _scan([
        _match_json(version="4.0.11"),
        _match_json(version="4.0.14"),
    ])
    matches = extract_scan_matches(scan_json)
    assert len(matches) == 2
    versions = {match.installed_version for match in matches}
    assert versions == {"4.0.11", "4.0.14"}


# --- assemble_findings ---


def _component(
    version: str | None = "1.0.0",
    constraint: str | None = "1.0.0",
    exact: bool = True,
    scope: Scope = Scope.PRODUCTION,
    ecosystem: Ecosystem = Ecosystem.NPM,
) -> Component:
    return Component(version=version, constraint=constraint, exact=exact, scope=scope, ecosystem=ecosystem)


def _scan_match(
    cve_id: str = "CVE-2014-0160",
    package_name: str = "pkg",
    installed_version: str = "1.0.0",
    fixed_version: str | None = "1.0.1",
) -> ScanMatch:
    return ScanMatch(cve_id=cve_id, package_name=package_name, installed_version=installed_version, fixed_version=fixed_version)


def _nvd_enrichment(
    cve_id: str = "CVE-2014-0160",
    status: NvdVulnStatus = NvdVulnStatus.ANALYZED,
    cvss: float | None = 7.5,
    summary: LocalizedText | None = None,
    references: list[str] | None = None,
) -> NvdEnrichment:
    if summary is None:
        summary = LocalizedText(values={"en": "desc"})
    if references is None:
        references = ["http://example.com"]
    return NvdEnrichment(cve_id=cve_id, vuln_status=status, cvss=cvss, summary=summary, references=references)


def _epss_score(cve_id: str = "CVE-2014-0160", epss: float = 0.5, percentile: float = 0.5) -> EpssScore:
    return EpssScore(cve_id=cve_id, epss=epss, percentile=percentile)


def test_finding_is_assembled_with_full_enrichment():
    components = {"pkg": _component()}
    match = _scan_match(cve_id="CVE-2014-0160", package_name="pkg", installed_version="1.0.0", fixed_version="1.0.1")
    nvd_data = {"CVE-2014-0160": _nvd_enrichment(
        cve_id="CVE-2014-0160",
        cvss=7.5,
        summary=LocalizedText(values={"en": "desc"}),
        references=["http://example.com"],
    )}
    epss_scores = {"CVE-2014-0160": _epss_score(epss=0.5)}
    dates_by_cve = {"CVE-2014-0160": "2023-01-01"}

    findings = assemble_findings(
        app_id="app",
        components=components,
        matches=[match],
        nvd_data=nvd_data,
        epss_scores=epss_scores,
        dates_by_cve=dates_by_cve,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.app_id == "app"
    assert finding.package_name == "pkg"
    assert finding.installed_version == "1.0.0"
    assert finding.component is components["pkg"]
    assert finding.vulnerability.fixed_version == "1.0.1"
    assert finding.vulnerability.cvss == 7.5
    assert finding.vulnerability.epss == 0.5
    assert finding.vulnerability.in_kev is True
    assert finding.vulnerability.kev_date_added == "2023-01-01"
    assert finding.vulnerability.summary.values == {"en": "desc"}
    assert finding.vulnerability.references == ["http://example.com"]


def test_match_without_component_is_skipped():
    findings = assemble_findings(
        app_id="app",
        components={},
        matches=[_scan_match()],
        nvd_data={"CVE-2014-0160": _nvd_enrichment()},
        epss_scores={"CVE-2014-0160": _epss_score()},
        dates_by_cve={"CVE-2014-0160": "2023-01-01"},
    )
    assert findings == []


def test_rejected_cve_is_skipped():
    findings = assemble_findings(
        app_id="app",
        components={"pkg": _component()},
        matches=[_scan_match()],
        nvd_data={"CVE-2014-0160": _nvd_enrichment(status=NvdVulnStatus.REJECTED)},
        epss_scores={"CVE-2014-0160": _epss_score()},
        dates_by_cve={"CVE-2014-0160": "2023-01-01"},
    )
    assert findings == []


def test_missing_nvd_enrichment_has_empty_fields():
    findings = assemble_findings(
        app_id="app",
        components={"pkg": _component()},
        matches=[_scan_match()],
        nvd_data={},
        epss_scores={"CVE-2014-0160": _epss_score()},
        dates_by_cve={"CVE-2014-0160": "2023-01-01"},
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.vulnerability.cvss is None
    assert finding.vulnerability.summary.values == {}
    assert finding.vulnerability.references == []


def test_missing_epss_score_is_none():
    findings = assemble_findings(
        app_id="app",
        components={"pkg": _component()},
        matches=[_scan_match()],
        nvd_data={"CVE-2014-0160": _nvd_enrichment()},
        epss_scores={},
        dates_by_cve={"CVE-2014-0160": "2023-01-01"},
    )
    assert findings[0].vulnerability.epss is None


def test_cve_not_in_kev():
    findings = assemble_findings(
        app_id="app",
        components={"pkg": _component()},
        matches=[_scan_match()],
        nvd_data={"CVE-2014-0160": _nvd_enrichment()},
        epss_scores={"CVE-2014-0160": _epss_score()},
        dates_by_cve={},
    )
    finding = findings[0]
    assert finding.vulnerability.in_kev is False
    assert finding.vulnerability.kev_date_added is None