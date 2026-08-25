from vulnbeat.priority import calculate_priority
from vulnbeat.models import PriorityLabel


def test_no_data_gives_lowest_priority():
    result = calculate_priority(in_kev=False, epss=None, cvss=None)
    assert result.score == 0
    assert result.label == PriorityLabel.LOW


def test_kev_only_gives_base_score():
    result = calculate_priority(in_kev=True, epss=None, cvss=None)
    assert result.score == 80
    assert result.label == PriorityLabel.CRITICAL


def test_kev_with_high_epss_and_cvss_approaches_max_score():
    result = calculate_priority(in_kev=True, epss=0.94, cvss=9.8)
    assert result.score == 99
    assert result.label == PriorityLabel.CRITICAL


def test_score_exactly_at_critical_threshold_is_critical():
    result = calculate_priority(in_kev=False, epss=1.0, cvss=2.0)
    assert result.score == 80
    assert result.label == PriorityLabel.CRITICAL


def test_score_just_below_critical_threshold_is_high():
    result = calculate_priority(in_kev=False, epss=1.0, cvss=1.6)
    assert result.score == 79
    assert result.label == PriorityLabel.HIGH


def test_score_exactly_at_high_threshold_is_high():
    result = calculate_priority(in_kev=False, epss=0.5, cvss=5.0)
    assert result.score == 50
    assert result.label == PriorityLabel.HIGH


def test_score_just_below_high_threshold_is_medium():
    result = calculate_priority(in_kev=False, epss=0.5, cvss=4.6)
    assert result.score == 49
    assert result.label == PriorityLabel.MEDIUM


def test_score_exactly_at_medium_threshold_is_medium():
    result = calculate_priority(in_kev=False, epss=0.2, cvss=2.0)
    assert result.score == 20
    assert result.label == PriorityLabel.MEDIUM


def test_score_just_below_medium_threshold_is_low():
    result = calculate_priority(in_kev=False, epss=0.2, cvss=1.6)
    assert result.score == 19
    assert result.label == PriorityLabel.LOW