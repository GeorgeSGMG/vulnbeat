import yaml

from vulnbeat.models import Ecosystem, MonitoredApp, Source

APPS_CONFIG_PATH = "apps.yml"
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


if __name__ == "__main__":
    apps = load_apps()
    print(f"Loaded {len(apps)} apps from {APPS_CONFIG_PATH}.")
    for app in apps:
        print(f"  - {app.id} ({app.ecosystem.value}, {app.source.value})")