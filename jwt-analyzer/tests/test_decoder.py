import base64
import json

import pytest

from core.decoder import (
	JWTDecodeError,
	decode_header,
	decode_payload,
	decode_segment,
	get_signing_input,
	split_token,
)


def _encode_segment(data: dict) -> str:
	raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
	return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _build_token(header: dict, payload: dict, signature: str = "signature") -> str:
	return f"{_encode_segment(header)}.{_encode_segment(payload)}.{signature}"


def test_decode_header_and_payload_success() -> None:
	token = _build_token({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"})

	header = decode_header(token)
	payload = decode_payload(token)

	assert header["alg"] == "HS256"
	assert payload["sub"] == "admin"


def test_split_token_rejects_invalid_segments() -> None:
	with pytest.raises(JWTDecodeError):
		split_token("only.two")


def test_decode_segment_rejects_non_json() -> None:
	raw = base64.urlsafe_b64encode(b"not-json").decode("ascii").rstrip("=")

	with pytest.raises(JWTDecodeError):
		decode_segment(raw)


def test_get_signing_input_matches_header_payload_segments() -> None:
	token = _build_token({"alg": "HS256"}, {"sub": "user"}, signature="abc123")
	expected = ".".join(token.split(".")[:2])
	assert get_signing_input(token) == expected
