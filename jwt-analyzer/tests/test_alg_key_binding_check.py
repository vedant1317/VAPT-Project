from core.attacks.alg_key_binding_check import run_alg_key_binding_check


def _ids(findings: list[dict]) -> set[str]:
	return {str(item.get("id")) for item in findings}


def test_missing_alg_is_detected() -> None:
	findings = run_alg_key_binding_check({})
	assert "ALG_BINDING_MISSING_ALG" in _ids(findings)


def test_rs_without_pubkey_context_is_detected() -> None:
	findings = run_alg_key_binding_check({"alg": "RS256"})
	assert "MISSING_PUBLIC_KEY_CONTEXT" in _ids(findings)


def test_missing_pubkey_file_is_detected() -> None:
	findings = run_alg_key_binding_check({"alg": "RS256"}, "does-not-exist.pem")
	assert "PUBLIC_KEY_FILE_MISSING" in _ids(findings)


def test_hs_with_public_key_material_is_detected(tmp_path) -> None:
	pem_file = tmp_path / "public.pem"
	pem_file.write_text(
		"-----BEGIN PUBLIC KEY-----\n"
		"ZmFrZV9rZXk=\n"
		"-----END PUBLIC KEY-----\n",
		encoding="utf-8",
	)

	findings = run_alg_key_binding_check({"alg": "HS256"}, str(pem_file))
	assert "HS_WITH_PUBLIC_KEY_MATERIAL" in _ids(findings)
