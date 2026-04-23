from core.attacks.payload_scan import run_payload_scan


def _ids(findings: list[dict]) -> set[str]:
	return {str(item.get("id")) for item in findings}


def test_detects_sensitive_keys_and_private_key_material() -> None:
	payload = {
		"user": {
			"password": "hunter2",
			"profile": {
				"ssn": "123-45-6789",
			},
		},
		"backup": "-----BEGIN PRIVATE KEY-----abc",
	}

	findings = run_payload_scan(payload)
	finding_ids = _ids(findings)

	assert "SENSITIVE_CLAIM_KEY" in finding_ids
	assert "PII_CLAIM_KEY" in finding_ids
	assert "PRIVATE_KEY_IN_PAYLOAD" in finding_ids


def test_clean_payload_returns_no_findings() -> None:
	findings = run_payload_scan({"sub": "alice", "role": "reader"})
	assert findings == []
