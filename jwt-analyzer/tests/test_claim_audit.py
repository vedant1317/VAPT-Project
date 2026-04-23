from core.attacks.claim_audit import run_claim_audit


def _ids(findings: list[dict]) -> set[str]:
	return {str(item.get("id")) for item in findings}


def test_expired_token_flags_temporal_and_origin_claims() -> None:
	findings = run_claim_audit({"exp": 900}, current_time=1_000)
	finding_ids = _ids(findings)

	assert "TOKEN_EXPIRED" in finding_ids
	assert "MISSING_ISS" in finding_ids
	assert "MISSING_AUD" in finding_ids


def test_valid_claims_return_no_findings() -> None:
	payload = {
		"exp": 1_500,
		"nbf": 900,
		"iat": 1_000,
		"iss": "issuer-a",
		"aud": "service-a",
	}

	findings = run_claim_audit(payload, current_time=1_100)
	assert findings == []


def test_invalid_exp_format_is_detected() -> None:
	findings = run_claim_audit(
		{"exp": "tomorrow"},
		current_time=1_000,
		require_iss=False,
		require_aud=False,
	)
	assert "INVALID_EXP" in _ids(findings)
