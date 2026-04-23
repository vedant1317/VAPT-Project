from __future__ import annotations

import base64
import json
from typing import Any


class JWTDecodeError(ValueError):
    """Raised when a JWT cannot be parsed safely."""


def _ensure_non_empty_token(token: str) -> str:
    if not isinstance(token, str):
        raise JWTDecodeError("Token must be a string.")

    stripped = token.strip()
    if not stripped:
        raise JWTDecodeError("Token must not be empty.")

    return stripped


def split_token(token: str) -> tuple[str, str, str]:
    """Split a JWT into header, payload, and signature segments."""
    cleaned_token = _ensure_non_empty_token(token)
    parts = cleaned_token.split(".")

    if len(parts) != 3:
        raise JWTDecodeError("JWT must contain exactly 3 dot-separated segments.")

    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64:
        raise JWTDecodeError("JWT header and payload segments must not be empty.")

    return header_b64, payload_b64, signature_b64


def _decode_base64url(segment: str) -> bytes:
    try:
        segment_bytes = segment.encode("ascii")
    except UnicodeEncodeError as exc:
        raise JWTDecodeError(
            "JWT segments must contain URL-safe base64 ASCII characters."
        ) from exc

    padding = b"=" * (-len(segment_bytes) % 4)

    try:
        return base64.urlsafe_b64decode(segment_bytes + padding)
    except Exception as exc:  # pragma: no cover - exact exception type can vary
        raise JWTDecodeError("Invalid base64url data in JWT segment.") from exc


def decode_segment(segment: str) -> dict[str, Any]:
    """Decode a JWT segment and parse it as a JSON object."""
    raw_bytes = _decode_base64url(segment)

    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JWTDecodeError("JWT segment is not valid UTF-8.") from exc

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise JWTDecodeError("JWT segment does not contain valid JSON.") from exc

    if not isinstance(parsed, dict):
        raise JWTDecodeError("JWT segment must decode to a JSON object.")

    return parsed


def decode_header(token: str) -> dict[str, Any]:
    header_b64, _, _ = split_token(token)
    return decode_segment(header_b64)


def decode_payload(token: str) -> dict[str, Any]:
    _, payload_b64, _ = split_token(token)
    return decode_segment(payload_b64)


def get_signature(token: str) -> str:
    _, _, signature_b64 = split_token(token)
    return signature_b64


def get_signing_input(token: str) -> str:
    header_b64, payload_b64, _ = split_token(token)
    return f"{header_b64}.{payload_b64}"


def get_algorithm(header: dict[str, Any]) -> str:
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg.strip():
        raise JWTDecodeError("JWT header must include a non-empty 'alg' value.")
    return alg.strip()


def decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Decode a complete token into header, payload, and raw signature segment."""
    header = decode_header(token)
    payload = decode_payload(token)
    signature = get_signature(token)
    return header, payload, signature


def encode_segment(data: dict[str, Any]) -> str:
    """Encode a JSON object to a Base64URL segment without padding."""
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
