from __future__ import annotations

from pathlib import Path
from typing import Any

try:
	from cryptography.hazmat.primitives import serialization
except Exception:  # pragma: no cover - dependency availability is environment-specific
	serialization = None


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
		"category": "Crypto",
		"description": description,
		"evidence": evidence,
		"impact": impact,
		"remediation": remediation,
	}


def _load_key_bytes(pubkey_path: str) -> bytes | None:
	key_path = Path(pubkey_path)
	if not key_path.exists() or not key_path.is_file():
		return None
	return key_path.read_bytes()


def _is_public_key_material(key_bytes: bytes) -> bool:
	if b"BEGIN PUBLIC KEY" in key_bytes or b"BEGIN RSA PUBLIC KEY" in key_bytes:
		return True

	if serialization is None:
		return False

	try:
		serialization.load_pem_public_key(key_bytes)
		return True
	except Exception:
		return False


def run_alg_key_binding_check(
	header: dict[str, Any], pubkey_path: str | None = None
) -> list[dict[str, Any]]:
	"""Validate consistency between algorithm family and key handling expectations."""
	findings: list[dict[str, Any]] = []

	raw_alg = header.get("alg")
	if not isinstance(raw_alg, str) or not raw_alg.strip():
		findings.append(
			_finding(
				"ALG_BINDING_MISSING_ALG",
				"Missing Algorithm For Key Binding",
				"High",
				"Cannot validate key binding policy because 'alg' is missing.",
				{"alg": raw_alg},
				"Verifier may apply fallback logic and unsafe defaults.",
				"Require explicit algorithm and reject tokens without it.",
			)
		)
		return findings

	alg = raw_alg.strip().upper()
	key_reference_headers = [k for k in ("jwk", "jku", "x5u") if k in header]
	if key_reference_headers:
		findings.append(
			_finding(
				"DYNAMIC_KEY_REFERENCE",
				"Dynamic Key Reference In Header",
				"High",
				"Token includes dynamic key reference headers.",
				{"headers": key_reference_headers},
				"Dynamic key resolution can introduce key-substitution risks if not tightly controlled.",
				"Disable untrusted key reference headers or enforce strict allowlisting.",
			)
		)

	if pubkey_path is None and alg.startswith(("RS", "ES")):
		findings.append(
			_finding(
				"MISSING_PUBLIC_KEY_CONTEXT",
				"Missing Public Key Context",
				"Medium",
				"Asymmetric token algorithm detected without a public-key context.",
				{"alg": alg},
				"Misconfigured verifiers may fail open or skip intended signature checks.",
				"Ensure verifier configuration binds RS*/ES* algorithms to trusted public keys.",
			)
		)
		return findings

	if pubkey_path:
		key_bytes = _load_key_bytes(pubkey_path)
		if key_bytes is None:
			findings.append(
				_finding(
					"PUBLIC_KEY_FILE_MISSING",
					"Public Key File Missing",
					"Medium",
					"Provided public key path was not found or unreadable.",
					{"pubkey_path": pubkey_path},
					"Key-binding checks cannot be fully validated.",
					"Provide a valid PEM-formatted public key path.",
				)
			)
			return findings

		looks_public_key = _is_public_key_material(key_bytes)
		evidence = {
			"alg": alg,
			"pubkey_path": pubkey_path,
			"looks_public_key": looks_public_key,
		}

		if alg.startswith("HS") and looks_public_key:
			findings.append(
				_finding(
					"HS_WITH_PUBLIC_KEY_MATERIAL",
					"Public Key Material Used With HS Algorithm",
					"Critical",
					"HS* token context appears to use asymmetric public key material.",
					evidence,
					"Algorithm confusion patterns can allow token forgery in misconfigured verifiers.",
					"Separate symmetric and asymmetric verification paths and enforce strict key type checks.",
				)
			)

		if alg.startswith(("RS", "ES")) and not looks_public_key:
			findings.append(
				_finding(
					"ASYMMETRIC_ALG_INVALID_KEY",
					"Invalid Public Key Material",
					"High",
					"Asymmetric algorithm selected but supplied key does not parse as a public key.",
					evidence,
					"Signature verification may fail or fallback to unsafe behavior.",
					"Use a valid PEM public key and pin allowed algorithms in verifier config.",
				)
			)

	return findings
