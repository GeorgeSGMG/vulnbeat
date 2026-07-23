import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev(timeout: int = 30) -> list[dict]:
    response = requests.get(KEV_URL, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    return data["vulnerabilities"]

if __name__ == "__main__":
    vulnerabilities = fetch_kev()
    print(f"KEV downloaded: {len(vulnerabilities)} known exploited vulnerabilities.")