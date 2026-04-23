from __future__ import annotations

from typing import Any, Iterable


DEFAULT_ALLOWED_ALGS = {
	"HS256",
	"HS384",
	"HS512",
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384",
	"ES512",
}


def _finding(
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
		"category": "Config",
		"description": description,
		"evidence": evidence,
		"impact": impact,
		"remediation": remediation,
	}


def run_alg_policy_check(
	header: dict[str, Any], allowed_algs: Iterable[str] | None = None
) -> list[dict[str, Any]]:
	"""Validate algorithm policy and basic token-type metadata."""
	findings: list[dict[str, Any]] = []

	active_allowlist = {
		alg.strip()
		for alg in (allowed_algs or DEFAULT_ALLOWED_ALGS)
		if isinstance(alg, str) and alg.strip()
	}

	raw_alg = header.get("alg")
	if not isinstance(raw_alg, str) or not raw_alg.strip():
		findings.append(
			_finding(
				"ALG_MISSING",
				"Missing Algorithm Header",
				"High",
				"Token header is missing a valid 'alg' value.",
				{"alg": raw_alg},
				"Verifier behavior may be undefined or dangerously permissive.",
				"Require explicit algorithm allowlisting and reject tokens missing 'alg'.",
			)
		)
		return findings

	alg = raw_alg.strip()

	if alg.lower() == "none":
		findings.append(
			_finding(
				"ALG_NONE",
				"Insecure Algorithm 'none'",
				"Critical",
				"Token declares 'alg=none', which disables cryptographic signature verification.",
				{"alg": alg},
				"Attackers can tamper with claims and bypass trust checks in weak verifiers.",
				"Disallow 'none' in production and enforce strict algorithm allowlists.",
			)
		)

	if active_allowlist and alg not in active_allowlist:
		findings.append(
			_finding(
				"ALG_NOT_ALLOWED",
				"Algorithm Outside Allowlist",
				"High",
				"Token algorithm is not part of the configured allowlist.",
				{"alg": alg, "allowlist": sorted(active_allowlist)},
				"Unexpected algorithms can trigger unsafe verification paths.",
				"Only accept a strict set of approved algorithms in verifier configuration.",
			)
		)

	token_type = header.get("typ")
	if token_type is None:
		findings.append(
			_finding(
				"TYP_MISSING",
				"Missing Token Type",
				"Low",
				"Token header does not define a 'typ' claim.",
				{"typ": token_type},
				"Interoperability and policy enforcement can become inconsistent.",
				"Set typ='JWT' and validate it where possible.",
			)
		)
	elif isinstance(token_type, str) and token_type.upper() != "JWT":
		findings.append(
			_finding(
				"TYP_UNEXPECTED",
				"Unexpected Token Type",
				"Low",
				"Token 'typ' value is present but not 'JWT'.",
				{"typ": token_type},
				"Unexpected token metadata can indicate parser confusion or inconsistent issuer config.",
				"Standardize typ='JWT' for auth tokens.",
			)
		)

	return findings
