import requests

from vulnbeat.resilience import retry

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

KEV_VULNERABILITIES_KEY = "vulnerabilities"
KEV_CVE_ID_KEY = "cveID"
KEV_DATE_ADDED_KEY = "dateAdded"


@retry()
def fetch_kev(timeout: int = 30) -> dict[str, str]:
    response = requests.get(KEV_URL, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    dates_by_cve = {}
    for entry in data[KEV_VULNERABILITIES_KEY]:
        cve_id = entry[KEV_CVE_ID_KEY]
        date_added = entry[KEV_DATE_ADDED_KEY]

        if cve_id not in dates_by_cve or date_added < dates_by_cve[cve_id]:
            dates_by_cve[cve_id] = date_added

    return dates_by_cve


if __name__ == "__main__":
    dates_by_cve = fetch_kev()
    print(f"KEV downloaded: {len(dates_by_cve)} known exploited vulnerabilities.")