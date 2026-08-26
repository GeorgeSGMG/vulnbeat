import time

import requests

from vulnbeat.localization import LocalizedText
from vulnbeat.models import NvdEnrichment
from vulnbeat.resilience import retry

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_DELAY_WITH_KEY = 0.6
NVD_DELAY_WITHOUT_KEY = 6.0

NVD_API_KEY_HEADER = "apiKey"
NVD_CVE_ID_PARAM = "cveId"

NVD_VULNERABILITIES_KEY = "vulnerabilities"
NVD_CVE_KEY = "cve"
NVD_DESCRIPTIONS_KEY = "descriptions"
NVD_LANG_KEY = "lang"
NVD_VALUE_KEY = "value"
NVD_METRICS_KEY = "metrics"
NVD_CVSS_DATA_KEY = "cvssData"
NVD_BASE_SCORE_KEY = "baseScore"
NVD_REFERENCES_KEY = "references"
NVD_URL_KEY = "url"

NVD_CVSS_METRIC_KEYS_BY_PREFERENCE = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]


def _extract_summary(descriptions: list[dict[str, str]]) -> LocalizedText:
    values = dict((entry[NVD_LANG_KEY], entry[NVD_VALUE_KEY]) for entry in descriptions)
    return LocalizedText(values=values)


def _extract_cvss(metrics: dict) -> float | None:
    for metric_key in NVD_CVSS_METRIC_KEYS_BY_PREFERENCE:
        if metric_key in metrics:
            return metrics[metric_key][0][NVD_CVSS_DATA_KEY][NVD_BASE_SCORE_KEY]
    return None


@retry()
def _fetch_nvd_entry(cve_id: str, api_key: str | None, timeout: int = 30) -> dict:
    params = {NVD_CVE_ID_PARAM: cve_id}
    headers = {NVD_API_KEY_HEADER: api_key} if api_key else {}
    response = requests.get(NVD_URL, params=params, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.json()


def fetch_nvd(cve_ids: list[str], api_key: str | None = None) -> dict[str, NvdEnrichment]:
    delay = NVD_DELAY_WITH_KEY if api_key else NVD_DELAY_WITHOUT_KEY

    results = {}
    for cve_id in cve_ids:
        data = _fetch_nvd_entry(cve_id, api_key)
        vulnerabilities = data.get(NVD_VULNERABILITIES_KEY, [])
        if not vulnerabilities:
            time.sleep(delay)
            continue

        cve = vulnerabilities[0][NVD_CVE_KEY]
        results[cve_id] = NvdEnrichment(
            cve_id=cve_id,
            cvss=_extract_cvss(cve.get(NVD_METRICS_KEY, {})),
            summary=_extract_summary(cve[NVD_DESCRIPTIONS_KEY]),
            references=list(dict.fromkeys(ref[NVD_URL_KEY] for ref in cve.get(NVD_REFERENCES_KEY, []))),
        )
        time.sleep(delay)

    return results


if __name__ == "__main__":
    import os

    cve_id = "CVE-2014-0160"
    api_key = os.environ.get("NVD_API_KEY")
    results = fetch_nvd([cve_id], api_key=api_key)
    print(results.get(cve_id))