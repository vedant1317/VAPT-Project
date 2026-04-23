from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


DEFAULT_CLOCK_SKEW_SECONDS = 60


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
		"category": "Claims",
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


def run_claim_audit(
	payload: dict[str, Any],
	current_time: float | None = None,
	require_iss: bool = True,
	require_aud: bool = True,
	clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> list[dict[str, Any]]:
	"""Audit temporal and origin-binding claims for JWT safety."""
	now = (
		float(current_time)
		if current_time is not None
		else datetime.now(timezone.utc).timestamp()
	)
	findings: list[dict[str, Any]] = []

	exp_raw = payload.get("exp")
	exp_ts = _to_timestamp(exp_raw)
	if exp_raw is None:
		findings.append(
			_finding(
				"MISSING_EXP",
				"Missing Expiration Claim",
				"Medium",
				"Token does not contain an 'exp' claim.",
				{"exp": exp_raw},
				"Tokens without expiration can stay valid indefinitely.",
				"Add short-lived expiration times for all authentication tokens.",
			)
		)
	elif exp_ts is None:
		findings.append(
			_finding(
				"INVALID_EXP",
				"Invalid Expiration Claim",
				"Medium",
				"Token 'exp' claim is present but not a valid timestamp.",
				{"exp": exp_raw},
				"Invalid claim formats can bypass expected validation logic.",
				"Use NumericDate-compatible values for all temporal claims.",
			)
		)
	elif exp_ts <= now:
		findings.append(
			_finding(
				"TOKEN_EXPIRED",
				"Token Already Expired",
				"High",
				"Token expiration time is in the past.",
				{"exp": exp_ts, "now": now},
				"Expired tokens should be rejected; acceptance would be a severe validation flaw.",
				"Ensure verifier enforces expiration with controlled clock skew.",
			)
		)

	nbf_raw = payload.get("nbf")
	nbf_ts = _to_timestamp(nbf_raw)
	if nbf_raw is not None and nbf_ts is None:
		findings.append(
			_finding(
				"INVALID_NBF",
				"Invalid Not-Before Claim",
				"Medium",
				"Token 'nbf' claim is present but not a valid timestamp.",
				{"nbf": nbf_raw},
				"Malformed not-before constraints can weaken temporal enforcement.",
				"Use NumericDate values and strict claim parsing.",
			)
		)
	elif nbf_ts is not None and nbf_ts > (now + clock_skew_seconds):
		findings.append(
			_finding(
				"TOKEN_NOT_YET_VALID",
				"Token Used Before Not-Before Time",
				"Medium",
				"Token 'nbf' indicates the token is not yet valid.",
				{"nbf": nbf_ts, "now": now, "clock_skew_seconds": clock_skew_seconds},
				"If accepted, verifier might be skipping not-before validation.",
				"Reject tokens before nbf and keep clock skew windows minimal.",
			)
		)

	iat_raw = payload.get("iat")
	iat_ts = _to_timestamp(iat_raw)
	if iat_raw is not None and iat_ts is None:
		findings.append(
			_finding(
				"INVALID_IAT",
				"Invalid Issued-At Claim",
				"Low",
				"Token 'iat' claim is present but malformed.",
				{"iat": iat_raw},
				"Malformed issuance timestamps can break token age policies.",
				"Use NumericDate values for iat and validate claim schema.",
			)
		)
	elif iat_ts is not None and iat_ts > (now + clock_skew_seconds):
		findings.append(
			_finding(
				"IAT_IN_FUTURE",
				"Issued-At Is In The Future",
				"Low",
				"Token appears issued in the future beyond clock skew.",
				{"iat": iat_ts, "now": now, "clock_skew_seconds": clock_skew_seconds},
				"Can indicate issuer clock drift or token tampering.",
				"Sync issuer/verifier clocks and validate issuance time bounds.",
			)
		)

	if exp_ts is not None and nbf_ts is not None and exp_ts <= nbf_ts:
		findings.append(
			_finding(
				"INVALID_TIME_WINDOW",
				"Invalid Token Validity Window",
				"High",
				"Token expiration is not later than its not-before time.",
				{"exp": exp_ts, "nbf": nbf_ts},
				"Invalid windows can signal malformed tokens or broken issuer logic.",
				"Ensure exp > nbf for all generated tokens.",
			)
		)

	if require_iss and not payload.get("iss"):
		findings.append(
			_finding(
				"MISSING_ISS",
				"Missing Issuer Claim",
				"Low",
				"Token does not include an 'iss' claim.",
				{"iss": payload.get("iss")},
				"Missing issuer binding weakens token origin verification.",
				"Populate and validate issuer claim against trusted issuers.",
			)
		)

	if require_aud and not payload.get("aud"):
		findings.append(
			_finding(
				"MISSING_AUD",
				"Missing Audience Claim",
				"Low",
				"Token does not include an 'aud' claim.",
				{"aud": payload.get("aud")},
				"Tokens may be replayed across unintended services.",
				"Set and enforce audience claim per consuming service.",
			)
		)

	return findings
