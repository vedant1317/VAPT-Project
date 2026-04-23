from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from core.attacks.alg_key_binding_check import run_alg_key_binding_check
from core.attacks.alg_policy_check import run_alg_policy_check
from core.attacks.claim_audit import run_claim_audit
from core.attacks.payload_scan import run_payload_scan
from core.attacks.secret_strength_check import run_secret_strength_check
from core.decoder import JWTDecodeError, decode_token
from core.reporter import (
	calculate_risk_score,
	render_html_report,
	render_terminal_report,
	write_html_report,
)


def _network_finding(
	finding_id: str,
	title: str,
	severity: str,
	description: str,
	evidence: dict[str, Any],
	impact: str,
	remediation: str,
) -> dict[str, Any]:
	return {
		"id": finding_id,
		"title": title,
		"severity": severity,
		"category": "Validation",
		"description": description,
		"evidence": evidence,
		"impact": impact,
		"remediation": remediation,
	}


def _to_timestamp(value: Any) -> float | None:
	if isinstance(value, bool) or value is None:
		return None
	if isinstance(value, (int, float)):
		return float(value)
	if isinstance(value, str) and value.strip():
		try:
			return float(value.strip())
		except ValueError:
			return None
	return None


def run_network_claim_validation(
	url: str, token: str, payload: dict[str, Any], timeout: float
) -> list[dict[str, Any]]:
	"""
	Optionally validate whether a controlled endpoint enforces temporal claims.

	This uses the provided token only and does not attempt exploit token forgery.
	"""
	findings: list[dict[str, Any]] = []

	exp = _to_timestamp(payload.get("exp"))
	nbf = _to_timestamp(payload.get("nbf"))
	if exp is None and nbf is None:
		return findings

	try:
		response = requests.get(
			url,
			headers={"Authorization": f"Bearer {token}"},
			timeout=timeout,
		)
	except requests.RequestException as exc:
		findings.append(
			_network_finding(
				"NETWORK_VALIDATION_SKIPPED",
				"Endpoint Validation Unavailable",
				"Low",
				"Unable to complete endpoint validation request.",
				{"url": url, "error": str(exc)},
				"Online claim-enforcement checks were not completed.",
				"Verify endpoint reachability and rerun with --url.",
			)
		)
		return findings

	if response.status_code >= 400:
		return findings

	now = datetime.now(timezone.utc).timestamp()
	if exp is not None and exp <= now:
		findings.append(
			_network_finding(
				"SERVER_ACCEPTED_EXPIRED_TOKEN",
				"Endpoint Accepted Expired Token",
				"High",
				"Controlled endpoint returned success for a token whose exp is already in the past.",
				{"url": url, "status_code": response.status_code, "exp": exp, "now": now},
				"Server-side expiration checks may be missing or bypassed.",
				"Enforce exp claim verification on all authentication middleware paths.",
			)
		)

	if nbf is not None and nbf > now:
		findings.append(
			_network_finding(
				"SERVER_ACCEPTED_PREMATURE_TOKEN",
				"Endpoint Accepted Not-Yet-Valid Token",
				"High",
				"Controlled endpoint returned success for a token before its nbf timestamp.",
				{"url": url, "status_code": response.status_code, "nbf": nbf, "now": now},
				"Server-side not-before checks may be missing.",
				"Reject tokens where now < nbf except for tightly bounded skew allowances.",
			)
		)

	return findings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
	root = Path(__file__).resolve().parent
	default_wordlist = root / "wordlists" / "weak_secrets.txt"
	default_output = root / "reports" / "report.html"

	parser = argparse.ArgumentParser(
		description="JWT Security Analyzer (defensive assessment mode)"
	)
	parser.add_argument("--token", required=True, help="JWT string to analyze")
	parser.add_argument("--url", help="Optional controlled endpoint for validation checks")
	parser.add_argument("--pubkey", help="Optional public key PEM path for key-binding checks")
	parser.add_argument(
		"--wordlist",
		default=str(default_wordlist),
		help="Weak-secret denylist path",
	)
	parser.add_argument(
		"--known-secret",
		help="Owner-supplied HS secret for defensive strength validation",
	)
	parser.add_argument(
		"--allowed-alg",
		action="append",
		dest="allowed_algs",
		help="Explicitly allowed algorithm (repeatable)",
	)
	parser.add_argument(
		"--timeout",
		type=float,
		default=10.0,
		help="HTTP timeout in seconds for endpoint validation",
	)
	parser.add_argument("--report", action="store_true", help="Generate HTML report")
	parser.add_argument(
		"--output",
		default=str(default_output),
		help="Output path for HTML report",
	)
	parser.add_argument("--verbose", action="store_true", help="Print raw finding JSON")
	return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
	args = parse_args(argv)

	try:
		header, payload, _signature = decode_token(args.token)
	except JWTDecodeError as exc:
		print(f"[ERROR] Invalid JWT: {exc}")
		return 2

	findings: list[dict[str, Any]] = []
	findings.extend(run_alg_policy_check(header, args.allowed_algs))
	findings.extend(run_alg_key_binding_check(header, args.pubkey))
	findings.extend(run_claim_audit(payload))
	findings.extend(run_payload_scan(payload))
	findings.extend(
		run_secret_strength_check(
			header,
			known_secret=args.known_secret,
			weak_list_path=args.wordlist,
		)
	)

	if args.url:
		findings.extend(
			run_network_claim_validation(
				url=args.url,
				token=args.token,
				payload=payload,
				timeout=args.timeout,
			)
		)

	generated_at = datetime.now(timezone.utc).isoformat()
	score = calculate_risk_score(findings)
	print(render_terminal_report(header, payload, findings, score=score))

	if args.verbose:
		print(json.dumps(findings, indent=2, default=str))

	if args.report:
		html_report = render_html_report(
			header,
			payload,
			findings,
			score=score,
			generated_at=generated_at,
		)
		output_path = write_html_report(html_report, args.output)
		print(f"HTML report written to: {output_path}")

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
