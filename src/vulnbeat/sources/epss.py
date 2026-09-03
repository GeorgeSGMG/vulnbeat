import requests

from vulnbeat.models import EpssScore
from vulnbeat.shared.resilience import retry

EPSS_URL = "https://api.first.org/data/v1/epss"

EPSS_MAX_BATCH_CHARS = 2000
EPSS_MAX_BATCH_SIZE = 100

EPSS_CVE_PARAM = "cve"

EPSS_DATA_KEY = "data"
EPSS_CVE_KEY = "cve"
EPSS_SCORE_KEY = "epss"
EPSS_PERCENTILE_KEY = "percentile"


def _chunk_by_length(cve_ids: list[str], max_chars: int, max_size: int) -> list[list[str]]:
    batches = []
    current_batch = []
    current_length = 0

    for cve_id in cve_ids:
        # +1 accounts for the comma separator joining CVE IDs in the URL.
        added_length = len(cve_id) + (1 if current_batch else 0)
        would_exceed_chars = current_length + added_length > max_chars
        would_exceed_size = len(current_batch) >= max_size

        if would_exceed_chars or would_exceed_size:
            batches.append(current_batch)
            current_batch = []
            current_length = 0
            added_length = len(cve_id)

        current_batch.append(cve_id)
        current_length += added_length

    if current_batch:
        batches.append(current_batch)

    return batches


@retry()
def _fetch_epss_batch(cve_ids: list[str], timeout: int = 30) -> dict[str, EpssScore]:
    params = {EPSS_CVE_PARAM: ",".join(cve_ids)}
    response = requests.get(EPSS_URL, params=params, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    scores = {}
    for entry in data[EPSS_DATA_KEY]:
        scores[entry[EPSS_CVE_KEY]] = EpssScore(
            cve_id=entry[EPSS_CVE_KEY],
            epss=float(entry[EPSS_SCORE_KEY]),
            percentile=float(entry[EPSS_PERCENTILE_KEY]),
        )
    return scores


def fetch_epss(cve_ids: list[str]) -> dict[str, EpssScore]:
    scores = {}
    for batch in _chunk_by_length(cve_ids, EPSS_MAX_BATCH_CHARS, EPSS_MAX_BATCH_SIZE):
        scores.update(_fetch_epss_batch(batch))
    return scores