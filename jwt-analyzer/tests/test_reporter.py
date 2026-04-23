import json
from pathlib import Path

from core.reporter import (
	build_report_data,
	calculate_risk_score,
	render_html_report,
	render_json_report,
	render_terminal_report,
	risk_level,
	write_html_report,
	write_json_report,
)


def _finding(finding_id: str, severity: str) -> dict:
	return {
		"id": finding_id,
		"title": "Test finding",
		"severity": severity,
		"category": "Test",
		"description": "Synthetic finding",
		"evidence": {"sample": True},
		"impact": "Synthetic impact",
		"remediation": "Synthetic remediation",
	}


def test_risk_score_zero_for_no_findings() -> None:
	score = calculate_risk_score([])
	assert score == 0.0
	assert risk_level(score) == "NONE"


def test_critical_finding_maps_to_critical_risk_band() -> None:
	findings = [_finding("A", "Critical"), _finding("B", "Medium")]
	score = calculate_risk_score(findings)

	assert score >= 9.0
	assert risk_level(score) == "CRITICAL"


def test_terminal_report_contains_expected_sections() -> None:
	findings = [_finding("A", "High")]
	output = render_terminal_report({"alg": "HS256"}, {"sub": "alice"}, findings)

	assert "JWT SECURITY ANALYSIS REPORT" in output
	assert "OVERALL RISK SCORE" in output
	assert "[HIGH]" in output


def test_html_report_write_round_trip(tmp_path: Path) -> None:
	findings = [_finding("A", "Low")]
	html_report = render_html_report({"alg": "HS256"}, {"sub": "alice"}, findings)

	output_path = tmp_path / "report.html"
	written_path = write_html_report(html_report, output_path)

	assert written_path.exists()
	written_text = written_path.read_text(encoding="utf-8")
	assert "JWT Security Analysis Report" in written_text


def test_build_report_data_has_summary_counts() -> None:
	findings = [_finding("A", "High"), _finding("B", "Low")]
	data = build_report_data({"alg": "HS256"}, {"sub": "alice"}, findings)

	assert data["finding_count"] == 2
	assert data["severity_counts"]["high"] == 1
	assert data["severity_counts"]["low"] == 1


def test_render_json_report_is_valid_json() -> None:
	findings = [_finding("A", "Medium")]
	serialized = render_json_report({"alg": "HS256"}, {"sub": "alice"}, findings)
	parsed = json.loads(serialized)

	assert parsed["header"]["alg"] == "HS256"
	assert parsed["findings"][0]["id"] == "A"


def test_write_json_report_round_trip(tmp_path: Path) -> None:
	data = {
		"risk_score": 5.1,
		"risk_level": "MEDIUM",
		"findings": [],
	}
	output_path = tmp_path / "report.json"
	written_path = write_json_report(data, output_path)

	assert written_path.exists()
	written = json.loads(written_path.read_text(encoding="utf-8"))
	assert written["risk_level"] == "MEDIUM"
