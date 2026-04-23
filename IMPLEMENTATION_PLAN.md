# JWT Security Analyzer - Implementation Plan

## 1) Purpose and Scope

Build a lightweight JWT security analyzer that helps developers and security teams detect insecure token design and verification gaps before deployment.

This plan is strictly for authorized security testing and defensive hardening. The tool should prioritize:
- Offline analysis of token structure and claims
- Configuration and policy validation
- Risk scoring and remediation guidance
- Clear reporting for engineering teams

Out of scope:
- Automated exploit generation against third-party systems
- Credential cracking workflows designed for unauthorized access

## 2) Goals

- Analyze a JWT and surface high-impact security findings quickly
- Support both local analysis and optional controlled endpoint validation
- Produce a terminal summary and an HTML report
- Assign severity and an overall risk score for triage

## 3) Proposed Project Structure

```text
jwt-analyzer/
|
|-- main.py
|-- core/
|   |-- decoder.py
|   |-- attacks/
|   |   |-- alg_policy_check.py
|   |   |-- secret_strength_check.py
|   |   |-- alg_key_binding_check.py
|   |   |-- claim_audit.py
|   |   \-- payload_scan.py
|   \-- reporter.py
|
|-- wordlists/
|   \-- weak_secrets.txt
|
|-- reports/
|   \-- report.html
|
\-- tests/
    |-- test_decoder.py
    |-- test_claim_audit.py
    |-- test_payload_scan.py
    \-- test_reporter.py
```

## 4) Module-by-Module Plan

### 4.1 `core/decoder.py`
Responsibilities:
- Split token into header, payload, signature
- Base64URL decode safely with padding handling
- Parse JSON and return normalized dictionaries
- Validate token format and raise actionable errors

Key functions:
- `split_token(token: str) -> tuple[str, str, str]`
- `decode_segment(segment: str) -> dict`
- `decode_header(token: str) -> dict`
- `decode_payload(token: str) -> dict`
- `get_algorithm(header: dict) -> str`

### 4.2 `core/attacks/alg_policy_check.py`
Responsibilities:
- Detect insecure or unexpected algorithms in token header
- Flag `alg` values outside an allowlist
- Flag `alg=none` as critical policy misconfiguration risk

Output example fields:
- finding id
- severity
- evidence (`alg` observed)
- remediation steps

### 4.3 `core/attacks/secret_strength_check.py`
Responsibilities:
- For HS* tokens, assess secret quality using:
  - denylist comparison against known weak values
  - minimum length checks
  - optional entropy estimate
- Avoid brute-force workflows by default

Input:
- Optional candidate secret if supplied by owner in an authorized environment

### 4.4 `core/attacks/alg_key_binding_check.py`
Responsibilities:
- Ensure algorithm-family and key-type consistency in config
- Detect risk indicators for RSA/HMAC confusion
- Validate that verifier policy binds key type to expected alg

Expected checks:
- RS*/ES* tokens should not be verified via HMAC paths
- HS* tokens should not use asymmetric key material as secret

### 4.5 `core/attacks/payload_scan.py`
Responsibilities:
- Scan payload keys for sensitive data patterns
- Flag claims like `password`, `ssn`, `credit_card`, `private_key`, `secret`, `token`
- Add contextual severity:
  - Medium: generic sensitive indicator
  - High: clear secret/PII exposure

### 4.6 `core/attacks/claim_audit.py`
Responsibilities:
- Validate presence and basic logic for:
  - `exp`
  - `nbf`
  - `iat`
  - `iss`
  - `aud`
- Detect:
  - missing expiration
  - already expired token
  - invalid not-before usage windows
  - missing issuer/audience binding

### 4.7 `core/reporter.py`
Responsibilities:
- Aggregate findings into a single result model
- Compute weighted risk score (0-10)
- Render:
  - terminal output
  - HTML report

Severity mapping (recommended):
- Critical: 9.0-10.0
- High: 7.0-8.9
- Medium: 4.0-6.9
- Low: 1.0-3.9

## 5) CLI Contract (`main.py`)

Recommended arguments:
- `--token` required JWT string
- `--url` optional endpoint for controlled validation checks
- `--wordlist` optional weak-secret denylist path
- `--report` enable HTML output
- `--output` report file path (default: `reports/report.html`)
- `--timeout` network timeout for endpoint checks
- `--verbose` extended diagnostics

Execution flow:
1. Parse args and validate input
2. Decode header/payload/signature
3. Run checks in sequence:
   - algorithm policy
   - key binding policy
   - claim audit
   - payload sensitivity scan
   - optional secret quality checks
4. Aggregate and score
5. Print terminal report
6. Write HTML if requested

## 6) Data Model for Findings

Use a unified finding schema:
- `id`: stable identifier (for dedup and filtering)
- `title`: short finding title
- `severity`: Critical/High/Medium/Low
- `category`: Crypto/Claims/Privacy/Config
- `description`: what was detected
- `evidence`: concrete values seen
- `impact`: security consequence
- `remediation`: precise fix recommendation

## 7) Reporting Requirements

Terminal report should include:
- Token metadata summary (`alg`, `typ`, claim keys)
- Findings grouped by severity
- Overall risk score and risk band
- Quick remediation checklist

HTML report should include:
- Timestamp and run parameters
- Structured finding cards
- Severity colors and score visualization
- Export-friendly layout for audits

## 8) Implementation Timeline (3 Hours)

### Phase 1 (0:00-0:20)
- Scaffold directories and files
- Implement `decoder.py`
- Add robust parse/error handling

### Phase 2 (0:20-0:50)
- Implement `alg_policy_check.py`
- Implement `secret_strength_check.py`

### Phase 3 (0:50-1:20)
- Implement `claim_audit.py`
- Implement `payload_scan.py`

### Phase 4 (1:20-1:50)
- Implement `alg_key_binding_check.py`
- Add optional controlled endpoint validation helpers

### Phase 5 (1:50-2:20)
- Wire modules in `main.py`
- Add CLI validation and error messages

### Phase 6 (2:20-2:50)
- Build `reporter.py`
- Implement terminal formatting and HTML generation

### Phase 7 (2:50-3:00)
- Run sample tests
- Fix edge cases
- Finalize docs

## 9) Testing Strategy

Unit tests:
- Token parsing for malformed and valid inputs
- Claim validation boundary cases (expired, missing, future `nbf`)
- Payload scanner matching accuracy
- Score computation correctness

Integration tests:
- End-to-end run from CLI with sample JWTs
- Report generation path and HTML content assertions

Negative tests:
- Invalid token format
- Non-JSON segments
- Missing required CLI arguments
- Unreadable wordlist/report output path

## 10) Security and Compliance Guardrails

- Run checks only in authorized environments
- Keep logs sanitized (do not print full secrets)
- Mask sensitive values in reports by default
- Add explicit legal/ethical banner in CLI help text

## 11) Dependencies

Install minimal dependencies:
- `pyjwt`
- `requests`
- `cryptography`
- `colorama`

Optional for tests:
- `pytest`

## 12) Deliverables

- Working CLI tool
- Modular check engine under `core/attacks`
- Colorized terminal report
- HTML report output
- Unit tests for critical modules
- README usage and remediation guidance

## 13) Acceptance Criteria

- Tool parses and analyzes valid JWTs without crash
- Tool handles malformed JWTs with clear errors
- At least five security check modules return structured findings
- Risk score and severity mapping are consistent
- HTML report is generated when requested
- Baseline tests pass

## 14) Recommended Next Steps

1. Implement file scaffolding and decoder first.
2. Add check modules with shared finding schema.
3. Wire reporter and risk scoring.
4. Add tests before integrating optional endpoint mode.
5. Run a dry-run review with sample tokens and tune severities.
