import requests
import yaml

from vulnbeat.crossref import assemble_findings, extract_scan_matches, scan_sbom
from vulnbeat.inventory import PARSER_REGISTRY, extract_scopes
from vulnbeat.models import Ecosystem, MonitoredApp, PrioritizedFinding, ScannedApp, Source, SourceCounts
from vulnbeat.priority import calculate_finding_priority
from vulnbeat.publication import write_report
from vulnbeat.sbom import generate_sbom, parse_sbom
from vulnbeat.settings import Settings
from vulnbeat.shared.resilience import retry
from vulnbeat.sources.epss import fetch_epss
from vulnbeat.sources.kev import fetch_kev
from vulnbeat.sources.nvd import fetch_nvd

APPS_CONFIG_PATH = "apps.yml"
OUTPUT_PATH = "docs/data.json"
APPS_KEY = "apps"
APP_ID_KEY = "id"
APP_NAME_KEY = "name"
APP_ECOSYSTEM_KEY = "ecosystem"
APP_REPO_KEY = "repo"
APP_SOURCE_KEY = "source"
APP_MANIFEST_URL_KEY = "manifest_url"
APP_MANIFEST_PATH_KEY = "manifest_path"
APP_LOCKFILE_URL_KEY = "lockfile_url"
APP_LOCKFILE_PATH_KEY = "lockfile_path"


def load_apps() -> list[MonitoredApp]:
    with open(APPS_CONFIG_PATH, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    apps = []
    for raw_app in config[APPS_KEY]:
        apps.append(
            MonitoredApp(
                id=raw_app[APP_ID_KEY],
                name=raw_app[APP_NAME_KEY],
                ecosystem=Ecosystem(raw_app[APP_ECOSYSTEM_KEY]),
                repo=raw_app[APP_REPO_KEY],
                source=Source(raw_app[APP_SOURCE_KEY]),
                manifest_url=raw_app.get(APP_MANIFEST_URL_KEY),
                manifest_path=raw_app.get(APP_MANIFEST_PATH_KEY),
                lockfile_url=raw_app.get(APP_LOCKFILE_URL_KEY),
                lockfile_path=raw_app.get(APP_LOCKFILE_PATH_KEY),
            )
        )
    return apps


@retry()
def fetch_manifest(app: MonitoredApp) -> str:
    if app.source == Source.REMOTE:
        assert app.manifest_url is not None
        response = requests.get(app.manifest_url, timeout=30)
        response.raise_for_status()
        return response.text
    else:
        assert app.manifest_path is not None
        with open(app.manifest_path, encoding="utf-8") as f:
            return f.read()


@retry()
def fetch_lockfile(app: MonitoredApp) -> str | None:
    if app.source == Source.REMOTE:
        if app.lockfile_url is None:
            return None
        response = requests.get(app.lockfile_url, timeout=30)
        response.raise_for_status()
        return response.text
    else:
        if app.lockfile_path is None:
            return None
        with open(app.lockfile_path, encoding="utf-8") as f:
            return f.read()


def scan_app(app: MonitoredApp) -> ScannedApp:
    manifest_content = fetch_manifest(app)
    lockfile_content = fetch_lockfile(app)

    parser = PARSER_REGISTRY[app.ecosystem]
    inventory_components = parser(manifest_content, lockfile_content)
    scopes = extract_scopes(inventory_components)

    sbom_json = generate_sbom(manifest_content, app.ecosystem, lockfile_content)
    components = parse_sbom(sbom_json, app.ecosystem, scopes)

    scan_json = scan_sbom(sbom_json)
    matches = extract_scan_matches(scan_json)

    return ScannedApp(app=app, components=components, matches=matches)


if __name__ == "__main__":
    settings = Settings.from_env()

    apps = load_apps()
    print(f"Loaded {len(apps)} apps from {APPS_CONFIG_PATH}.")

    scanned_apps = []
    component_counts = {}
    for app in apps:
        scanned_app = scan_app(app)
        scanned_apps.append(scanned_app)
        component_counts[app.id] = len(scanned_app.components)
        print(f"  - {app.id} ({app.ecosystem.value}, {app.source.value}): {len(scanned_app.components)} components, {len(scanned_app.matches)} matches with real CVE")

    all_cve_ids = list(set(
        match.cve_id
        for scanned_app in scanned_apps
        for match in scanned_app.matches
    ))
    print(f"{len(all_cve_ids)} unique CVEs found across all apps.")

    dates_by_cve = fetch_kev()
    print(f"KEV downloaded: {len(dates_by_cve)} known exploited vulnerabilities.")

    nvd_data = fetch_nvd(all_cve_ids, api_key=settings.nvd_api_key)
    print(f"NVD enrichment fetched for {len(nvd_data)} of {len(all_cve_ids)} CVEs.")

    epss_scores = fetch_epss(all_cve_ids)
    print(f"EPSS scores fetched for {len(epss_scores)} of {len(all_cve_ids)} CVEs.")

    prioritized_findings = []
    for scanned_app in scanned_apps:
        findings = assemble_findings(
            app_id=scanned_app.app.id,
            components=scanned_app.components,
            matches=scanned_app.matches,
            nvd_data=nvd_data,
            epss_scores=epss_scores,
            dates_by_cve=dates_by_cve,
        )
        for finding in findings:
            priority = calculate_finding_priority(finding)
            prioritized_findings.append(PrioritizedFinding(finding=finding, priority=priority))

    source_counts = SourceCounts(
        kev=len(dates_by_cve),
        epss=len(epss_scores),
        nvd=len(nvd_data),
    )

    write_report(source_counts, apps, component_counts, prioritized_findings, OUTPUT_PATH)
    print(f"Report written to {OUTPUT_PATH}.")