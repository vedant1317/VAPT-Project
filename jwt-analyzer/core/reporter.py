from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import html
import json

try:
	from colorama import Fore, Style, init as colorama_init

	colorama_init(autoreset=True)
except Exception:  # pragma: no cover - optional dependency behavior
	class _FallbackColor:
		RED = ""
		YELLOW = ""
		BLUE = ""
		GREEN = ""
		CYAN = ""

	class _FallbackStyle:
		BRIGHT = ""
		RESET_ALL = ""

	Fore = _FallbackColor()  # type: ignore[assignment]
	Style = _FallbackStyle()  # type: ignore[assignment]


SEVERITY_WEIGHTS = {
	"critical": 10.0,
	"high": 8.0,
	"medium": 5.0,
	"low": 2.0,
}


def _severity_key(value: str) -> str:
	return value.strip().lower() if isinstance(value, str) else "low"


def _severity_weight(value: str) -> float:
	return SEVERITY_WEIGHTS.get(_severity_key(value), 1.0)


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
	return sorted(
		findings,
		key=lambda item: (
			-_severity_weight(str(item.get("severity", "low"))),
			str(item.get("id", "")),
		),
	)


def calculate_risk_score(findings: list[dict[str, Any]]) -> float:
	"""Calculate a 0-10 risk score that emphasizes highest severity and finding volume."""
	if not findings:
		return 0.0

	weights = [_severity_weight(str(item.get("severity", "low"))) for item in findings]
	max_weight = max(weights)
	average_weight = sum(weights) / len(weights)
	density_bonus = min(len(weights), 10) * 0.2
	score = (0.7 * max_weight) + (0.3 * average_weight) + density_bonus
	return round(min(10.0, score), 1)


def risk_level(score: float) -> str:
	if score >= 9.0:
		return "CRITICAL"
	if score >= 7.0:
		return "HIGH"
	if score >= 4.0:
		return "MEDIUM"
	if score > 0:
		return "LOW"
	return "NONE"


def _severity_color(severity: str) -> str:
	key = _severity_key(severity)
	if key == "critical":
		return Fore.RED + Style.BRIGHT
	if key == "high":
		return Fore.YELLOW + Style.BRIGHT
	if key == "medium":
		return Fore.BLUE + Style.BRIGHT
	return Fore.GREEN + Style.BRIGHT


def render_terminal_report(
	header: dict[str, Any],
	payload: dict[str, Any],
	findings: list[dict[str, Any]],
	score: float | None = None,
) -> str:
	score_value = calculate_risk_score(findings) if score is None else score
	band = risk_level(score_value)
	ordered = sort_findings(findings)

	lines: list[str] = []
	lines.append("=" * 62)
	lines.append(" JWT SECURITY ANALYSIS REPORT")
	lines.append("=" * 62)
	lines.append(f"Header : {json.dumps(header, sort_keys=True, default=str)}")
	lines.append(f"Payload: {json.dumps(payload, sort_keys=True, default=str)}")
	lines.append("-" * 62)

	if not ordered:
		lines.append("No findings detected.")
	else:
		for finding in ordered:
			severity = str(finding.get("severity", "Low"))
			color = _severity_color(severity)
			reset = Style.RESET_ALL
			title = str(finding.get("title", "Untitled finding"))
			description = str(finding.get("description", ""))
			remediation = str(finding.get("remediation", ""))

			lines.append(f"{color}[{severity.upper()}] {title}{reset}")
			lines.append(f"  Description: {description}")
			if remediation:
				lines.append(f"  Fix        : {remediation}")
			lines.append("-" * 62)

	lines.append(f"OVERALL RISK SCORE: {score_value:.1f}/10 ({band})")
	lines.append("=" * 62)
	return "\n".join(lines)


def render_html_report(
	header: dict[str, Any],
	payload: dict[str, Any],
	findings: list[dict[str, Any]],
	score: float | None = None,
	generated_at: str | None = None,
) -> str:
	score_value = calculate_risk_score(findings) if score is None else score
	band = risk_level(score_value)
	ordered = sort_findings(findings)
	timestamp = generated_at or datetime.now(timezone.utc).isoformat()

	finding_blocks = []
	for finding in ordered:
		severity = str(finding.get("severity", "Low"))
		sev_class = _severity_key(severity)
		title = html.escape(str(finding.get("title", "Untitled finding")))
		description = html.escape(str(finding.get("description", "")))
		impact = html.escape(str(finding.get("impact", "")))
		remediation = html.escape(str(finding.get("remediation", "")))
		evidence = html.escape(json.dumps(finding.get("evidence", {}), default=str))
		finding_blocks.append(
			"\n".join(
				[
					f'<article class="card {sev_class}">',
					f"  <h3>[{html.escape(severity.upper())}] {title}</h3>",
					f"  <p><strong>Description:</strong> {description}</p>",
					f"  <p><strong>Impact:</strong> {impact}</p>",
					f"  <p><strong>Remediation:</strong> {remediation}</p>",
					f"  <pre>{evidence}</pre>",
					"</article>",
				]
			)
		)

	finding_html = "\n".join(finding_blocks) if finding_blocks else "<p>No findings detected.</p>"
	header_json = html.escape(json.dumps(header, indent=2, sort_keys=True, default=str))
	payload_json = html.escape(json.dumps(payload, indent=2, sort_keys=True, default=str))

	return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>JWT Security Analysis Report</title>
  <style>
	body {{ font-family: Segoe UI, Tahoma, sans-serif; margin: 24px; background: #f4f6f8; color: #111; }}
	.meta {{ margin-bottom: 20px; }}
	.score {{ font-size: 1.2rem; font-weight: 700; margin: 12px 0; }}
	.grid {{ display: grid; gap: 12px; }}
	.card {{ background: #fff; border-radius: 10px; padding: 14px; border-left: 6px solid #8a8a8a; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08); }}
	.critical {{ border-left-color: #b00020; }}
	.high {{ border-left-color: #cc5500; }}
	.medium {{ border-left-color: #1f6feb; }}
	.low {{ border-left-color: #2e7d32; }}
	pre {{ background: #f1f3f5; padding: 10px; border-radius: 8px; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>JWT Security Analysis Report</h1>
  <section class=\"meta\">
	<p><strong>Generated At (UTC):</strong> {html.escape(timestamp)}</p>
	<p class=\"score\"><strong>Overall Risk:</strong> {score_value:.1f}/10 ({html.escape(band)})</p>
  </section>
  <section>
	<h2>Token Header</h2>
	<pre>{header_json}</pre>
  </section>
  <section>
	<h2>Token Payload</h2>
	<pre>{payload_json}</pre>
  </section>
  <section class=\"grid\">
	<h2>Findings</h2>
	{finding_html}
  </section>
</body>
</html>
"""


def build_report_data(
	header: dict[str, Any],
	payload: dict[str, Any],
	findings: list[dict[str, Any]],
	score: float | None = None,
	generated_at: str | None = None,
) -> dict[str, Any]:
	score_value = calculate_risk_score(findings) if score is None else score
	band = risk_level(score_value)
	ordered = sort_findings(findings)
	timestamp = generated_at or datetime.now(timezone.utc).isoformat()

	severity_counts: dict[str, int] = {
		"critical": 0,
		"high": 0,
		"medium": 0,
		"low": 0,
		"other": 0,
	}
	for finding in ordered:
		key = _severity_key(str(finding.get("severity", "low")))
		if key in severity_counts:
			severity_counts[key] += 1
		else:
			severity_counts["other"] += 1

	return {
		"generated_at": timestamp,
		"risk_score": round(float(score_value), 1),
		"risk_level": band,
		"finding_count": len(ordered),
		"severity_counts": severity_counts,
		"header": header,
		"payload": payload,
		"findings": ordered,
	}


def render_json_report(
	header: dict[str, Any],
	payload: dict[str, Any],
	findings: list[dict[str, Any]],
	score: float | None = None,
	generated_at: str | None = None,
	indent: int = 2,
) -> str:
	data = build_report_data(
		header,
		payload,
		findings,
		score=score,
		generated_at=generated_at,
	)
	return json.dumps(data, indent=indent, default=str)


def write_html_report(html_content: str, output_path: str | Path) -> Path:
	path = Path(output_path)
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(html_content, encoding="utf-8")
	return path


def write_json_report(report_data: dict[str, Any], output_path: str | Path, indent: int = 2) -> Path:
	path = Path(output_path)
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(json.dumps(report_data, indent=indent, default=str), encoding="utf-8")
	return path
