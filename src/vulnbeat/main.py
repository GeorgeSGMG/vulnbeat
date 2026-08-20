import requests
import yaml

from vulnbeat.inventory import PARSER_REGISTRY
from vulnbeat.matching import match
from vulnbeat.models import Component, Ecosystem, MonitoredApp, Source
from vulnbeat.publisher import write_report
from vulnbeat.sources.kev import fetch_kev

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
            )
        )
    return apps


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


def load_components(app: MonitoredApp) -> dict[str, Component]:
    content = fetch_manifest(app)
    parser = PARSER_REGISTRY[app.ecosystem]
    return parser(content)


if __name__ == "__main__":
    vulnerabilities = fetch_kev()
    print(f"KEV downloaded: {len(vulnerabilities)} known exploited vulnerabilities.")

    apps = load_apps()
    print(f"Loaded {len(apps)} apps from {APPS_CONFIG_PATH}.")

    component_counts = {}
    all_findings = []
    for app in apps:
        components = load_components(app)
        findings = match(app.id, components, vulnerabilities)
        print(f"  - {app.id} ({app.ecosystem.value}, {app.source.value}): {len(components)} components, {len(findings)} findings")

        component_counts[app.id] = len(components)
        all_findings.extend(findings)

    write_report(len(vulnerabilities), apps, component_counts, all_findings, OUTPUT_PATH)
    print(f"Report written to {OUTPUT_PATH}.")