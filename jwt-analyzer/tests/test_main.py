import base64
import json
from pathlib import Path

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


def test_main_outputs_terminal_report_for_valid_token(capsys) -> None:
	token = _build_token(
		{"alg": "HS256", "typ": "JWT"},
		{"sub": "alice", "exp": 4_102_444_800, "iss": "issuer", "aud": "api"},
	)

	exit_code = main(["--token", token])
	captured = capsys.readouterr()

	assert exit_code == 0
	assert "JWT SECURITY ANALYSIS REPORT" in captured.out
	assert "OVERALL RISK SCORE" in captured.out


def test_main_report_mode_writes_html_output(tmp_path: Path, capsys) -> None:
	token = _build_token(
		{"alg": "HS256", "typ": "JWT"},
		{"sub": "alice", "exp": 4_102_444_800, "iss": "issuer", "aud": "api"},
	)
	html_output = tmp_path / "analysis.html"

	exit_code = main(["--token", token, "--report", "--output", str(html_output)])
	captured = capsys.readouterr()

	assert exit_code == 0
	assert html_output.exists()
	assert "HTML report written to:" in captured.out
	html_text = html_output.read_text(encoding="utf-8")
	assert "react.production.min.js" in html_text
	assert "id=\"report-root\"" in html_text
