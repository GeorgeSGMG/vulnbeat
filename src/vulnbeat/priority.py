from vulnbeat.models import EpssScore, Finding, PriorityLabel, PriorityResult

KEV_BASE_SCORE = 80
EPSS_WEIGHT = 0.75
CVSS_WEIGHT = 0.25

CRITICAL_THRESHOLD = 80
HIGH_THRESHOLD = 50
MEDIUM_THRESHOLD = 20


def calculate_priority(in_kev: bool, epss: float | None, cvss: float | None) -> PriorityResult:
    base = KEV_BASE_SCORE if in_kev else 0
    non_kev_points = 100 - base

    epss_points = non_kev_points * EPSS_WEIGHT * (epss or 0)
    cvss_points = non_kev_points * CVSS_WEIGHT * ((cvss or 0) / 10)

    score = round(base + epss_points + cvss_points)

    if score >= CRITICAL_THRESHOLD:
        label = PriorityLabel.CRITICAL
    elif score >= HIGH_THRESHOLD:
        label = PriorityLabel.HIGH
    elif score >= MEDIUM_THRESHOLD:
        label = PriorityLabel.MEDIUM
    else:
        label = PriorityLabel.LOW

    return PriorityResult(score=score, label=label)


def calculate_finding_priority(finding: Finding, epss_scores: dict[str, EpssScore]) -> PriorityResult:
    epss_score = epss_scores.get(finding.vulnerability.cve_id)
    epss = epss_score.epss if epss_score else None
    return calculate_priority(in_kev=True, epss=epss, cvss=None)