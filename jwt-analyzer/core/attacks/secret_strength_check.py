from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import math


DEFAULT_MIN_SECRET_LENGTH = 32
DEFAULT_WEAK_SECRET_VALUES = {
	"secret",
	"password",
	"admin",
	"letmein",
	"changeme",
	"qwerty",
	"123456",
	"password123",
	"jwtsecret",
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
		"category": "Crypto",
		"description": description,
		"evidence": evidence,
		"impact": impact,
		"remediation": remediation,
	}


def load_weak_secret_list(wordlist_path: str | None) -> set[str]:
	if not wordlist_path:
		return set()

	path = Path(wordlist_path)
	if not path.exists() or not path.is_file():
		return set()

	weak_values: set[str] = set()
	for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
		candidate = line.strip()
		if not candidate or candidate.startswith("#"):
			continue
		weak_values.add(candidate.lower())
	return weak_values


def shannon_entropy_per_char(secret: str) -> float:
	if not secret:
		return 0.0

	counts = Counter(secret)
	length = len(secret)
	entropy = 0.0
	for count in counts.values():
		probability = count / length
		entropy -= probability * math.log2(probability)
	return entropy


def run_secret_strength_check(
	header: dict[str, Any],
	known_secret: str | None = None,
	weak_list_path: str | None = None,
	min_length: int = DEFAULT_MIN_SECRET_LENGTH,
) -> list[dict[str, Any]]:
	"""
	Assess HS* secret quality in authorized contexts.

	This check expects an owner-supplied secret and does not attempt active brute force.
	"""
	alg = header.get("alg")
	if not isinstance(alg, str) or not alg.upper().startswith("HS"):
		return []

	findings: list[dict[str, Any]] = []

	if known_secret is None:
		findings.append(
			_finding(
				"HS_SECRET_NOT_PROVIDED",
				"Unable To Assess HS Secret",
				"Low",
				"HS* algorithm detected, but no known secret was provided for strength analysis.",
				{"alg": alg},
				"Weak shared secrets may go undetected.",
				"Provide --known-secret in an authorized environment to run secret quality checks.",
			)
		)
		return findings

	normalized_secret = known_secret.strip()
	if not normalized_secret:
		findings.append(
			_finding(
				"HS_SECRET_EMPTY",
				"Empty Shared Secret",
				"High",
				"Provided HS* secret is empty after trimming whitespace.",
				{"alg": alg, "secret_length": 0},
				"Trivial secrets can be guessed instantly.",
				"Use a randomly generated 256-bit (or stronger) secret value.",
			)
		)
		return findings

	weak_values = set(DEFAULT_WEAK_SECRET_VALUES)
	weak_values.update(load_weak_secret_list(weak_list_path))

	entropy = shannon_entropy_per_char(normalized_secret)
	evidence = {
		"alg": alg,
		"secret_length": len(normalized_secret),
		"entropy_per_char": round(entropy, 2),
	}

	if normalized_secret.lower() in weak_values:
		findings.append(
			_finding(
				"HS_SECRET_COMMON",
				"Known Weak Shared Secret",
				"Critical",
				"Provided secret appears in a weak-secret denylist.",
				evidence,
				"An attacker can guess the secret and forge valid tokens.",
				"Rotate to a high-entropy random secret and remove predictable values from use.",
			)
		)

	if len(normalized_secret) < min_length:
		findings.append(
			_finding(
				"HS_SECRET_SHORT",
				"Shared Secret Too Short",
				"High",
				"Provided shared secret is below the recommended minimum length.",
				{**evidence, "minimum_length": min_length},
				"Short secrets reduce brute-force cost and increase compromise risk.",
				"Use at least 32 random bytes and store in a dedicated secret manager.",
			)
		)

	if entropy < 3.0:
		findings.append(
			_finding(
				"HS_SECRET_LOW_ENTROPY",
				"Low-Entropy Shared Secret",
				"Medium",
				"Secret complexity appears low based on character distribution.",
				evidence,
				"Low entropy makes secrets easier to guess with dictionary-style attempts.",
				"Generate secrets with a cryptographically secure random source.",
			)
		)

	return findings
