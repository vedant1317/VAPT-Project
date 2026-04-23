import base64
import json

from main import main


def _encode_segment(data: dict) -> str:
	raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
	return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _build_token(header: dict, payload: dict, signature: str = "sig") -> str:
	return f"{_encode_segment(header)}.{_encode_segment(payload)}.{signature}"


def test_main_returns_error_for_invalid_token(capsys) -> None:
	exit_code = main(["--token", "invalid.jwt"])
	captured = capsys.readouterr()

	assert exit_code == 2
	assert "[ERROR] Invalid JWT" in captured.out


def test_main_json_stdout_mode_returns_machine_readable_output(capsys) -> None:
	token = _build_token(
		{"alg": "HS256", "typ": "JWT"},
		{"sub": "alice", "exp": 4_102_444_800, "iss": "issuer", "aud": "api"},
	)

	exit_code = main(["--token", token, "--json"])
	captured = capsys.readouterr()

	assert exit_code == 0
	parsed = json.loads(captured.out)
	assert parsed["header"]["alg"] == "HS256"
	assert parsed["risk_level"] in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	assert "findings" in parsed


def test_main_json_output_writes_file_and_logs_path_to_stderr(tmp_path, capsys) -> None:
	token = _build_token(
		{"alg": "HS256", "typ": "JWT"},
		{"sub": "alice", "exp": 4_102_444_800, "iss": "issuer", "aud": "api"},
	)
	json_output = tmp_path / "analysis.json"

	exit_code = main(
		[
			"--token",
			token,
			"--json",
			"--json-output",
			str(json_output),
		]
	)
	captured = capsys.readouterr()

	assert exit_code == 0
	assert json_output.exists()
	assert "JSON report written to:" in captured.err
	file_payload = json.loads(json_output.read_text(encoding="utf-8"))
	assert "risk_score" in file_payload
