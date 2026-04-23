from __future__ import annotations

import re
from typing import Any, Iterator


HIGH_RISK_KEYWORDS = {
	"password",
	"passwd",
	"private_key",
	"secret",
	"api_key",
	"access_token",
	"refresh_token",
	"auth_token",
}

MEDIUM_RISK_KEYWORDS = {
	"ssn",
	"sin",
	"credit_card",
	"card_number",
	"dob",
	"email",
	"phone",
}

PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


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
		"category": "Privacy",
		"description": description,
		"evidence": evidence,
		"impact": impact,
		"remediation": remediation,
	}


def _walk_claims(value: Any, path: str = "") -> Iterator[tuple[str, str, Any]]:
	if isinstance(value, dict):
		for key, item in value.items():
			key_name = str(key)
			next_path = f"{path}.{key_name}" if path else key_name
			yield key_name, next_path, item
			yield from _walk_claims(item, next_path)
	elif isinstance(value, list):
		for index, item in enumerate(value):
			next_path = f"{path}[{index}]" if path else f"[{index}]"
			yield "", next_path, item
			yield from _walk_claims(item, next_path)


def _luhn_valid(number: str) -> bool:
	digits = [int(ch) for ch in number]
	parity = len(digits) % 2
	checksum = 0
	for index, digit in enumerate(digits):
		if index % 2 == parity:
			digit *= 2
			if digit > 9:
				digit -= 9
		checksum += digit
	return checksum % 10 == 0


def _looks_like_credit_card(value: str) -> bool:
	stripped = re.sub(r"[^0-9]", "", value)
	if len(stripped) < 13 or len(stripped) > 19:
		return False
	if not stripped.isdigit():
		return False
	return _luhn_valid(stripped)


def run_payload_scan(payload: dict[str, Any]) -> list[dict[str, Any]]:
	"""Inspect payload claims for accidental sensitive data exposure."""
	findings: list[dict[str, Any]] = []
	seen: set[tuple[str, str]] = set()

	for key_name, claim_path, value in _walk_claims(payload):
		key_lc = key_name.lower()

		high_match = any(keyword in key_lc for keyword in HIGH_RISK_KEYWORDS)
		medium_match = any(keyword in key_lc for keyword in MEDIUM_RISK_KEYWORDS)

		if high_match:
			dedupe_key = ("SENSITIVE_CLAIM_KEY", claim_path)
			if dedupe_key not in seen:
				seen.add(dedupe_key)
				findings.append(
					_finding(
						"SENSITIVE_CLAIM_KEY",
						"High-Risk Sensitive Claim Name",
						"High",
						"Payload contains a claim name that indicates secret material.",
						{"claim_path": claim_path, "claim_name": key_name},
						"JWT payloads are base64-encoded and readable by any holder.",
						"Remove secrets from JWT payloads and keep them in secure server-side stores.",
					)
				)

		elif medium_match:
			dedupe_key = ("PII_CLAIM_KEY", claim_path)
			if dedupe_key not in seen:
				seen.add(dedupe_key)
				findings.append(
					_finding(
						"PII_CLAIM_KEY",
						"Potential PII Claim Name",
						"Medium",
						"Payload contains a claim name associated with personal data.",
						{"claim_path": claim_path, "claim_name": key_name},
						"Including PII in JWTs increases data exposure risk in logs and clients.",
						"Minimize claim data and avoid embedding direct personal identifiers.",
					)
				)

		if isinstance(value, str) and value:
			if PRIVATE_KEY_PATTERN.search(value):
				dedupe_key = ("PRIVATE_KEY_IN_PAYLOAD", claim_path)
				if dedupe_key not in seen:
					seen.add(dedupe_key)
					findings.append(
						_finding(
							"PRIVATE_KEY_IN_PAYLOAD",
							"Private Key Material In Payload",
							"High",
							"Payload value appears to contain private key material.",
							{"claim_path": claim_path},
							"Private keys in JWT payloads are immediately exposed to token holders.",
							"Remove key material from tokens and rotate any exposed keys immediately.",
						)
					)

			if _looks_like_credit_card(value):
				dedupe_key = ("CREDIT_CARD_IN_PAYLOAD", claim_path)
				if dedupe_key not in seen:
					seen.add(dedupe_key)
					findings.append(
						_finding(
							"CREDIT_CARD_IN_PAYLOAD",
							"Potential Credit Card Data In Payload",
							"High",
							"Payload value resembles a payment card number.",
							{"claim_path": claim_path},
							"Cardholder data in JWTs can violate compliance controls and increase breach impact.",
							"Tokenize or reference data server-side; never place PAN values in JWT claims.",
						)
					)

	return findings
