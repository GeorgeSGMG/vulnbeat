import requests

from vulnbeat.models import Vulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

KEV_VULNERABILITIES_KEY = "vulnerabilities"
KEV_CVE_ID_KEY = "cveID"
KEV_VENDOR_PROJECT_KEY = "vendorProject"
KEV_PRODUCT_KEY = "product"
KEV_VULNERABILITY_NAME_KEY = "vulnerabilityName"
KEV_DATE_ADDED_KEY = "dateAdded"
KEV_SHORT_DESCRIPTION_KEY = "shortDescription"


def fetch_kev(timeout: int = 30) -> list[Vulnerability]:
    response = requests.get(KEV_URL, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    vulnerabilities = []
    for entry in data[KEV_VULNERABILITIES_KEY]:
        vulnerabilities.append(
            Vulnerability(
                cve_id=entry[KEV_CVE_ID_KEY],
                vendor_project=entry[KEV_VENDOR_PROJECT_KEY],
                product=entry[KEV_PRODUCT_KEY],
                vulnerability_name=entry[KEV_VULNERABILITY_NAME_KEY],
                date_added=entry[KEV_DATE_ADDED_KEY],
                short_description=entry[KEV_SHORT_DESCRIPTION_KEY],
            )
        )
    return vulnerabilities


if __name__ == "__main__":
    vulnerabilities = fetch_kev()
    print(f"KEV downloaded: {len(vulnerabilities)} known exploited vulnerabilities.")