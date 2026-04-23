# JWT Security Analyzer

JWT Security Analyzer is a defensive security assessment CLI for JSON Web Tokens. It helps engineering and AppSec teams identify risky token configuration, weak claim hygiene, and data exposure patterns before deployment.

## Scope

This project is for authorized security testing and hardening only.

Allowed use:
- Your own applications and infrastructure
- Explicitly authorized client environments
- Controlled test and staging systems

Not allowed:
- Unauthorized testing against third-party systems
- Any activity that violates laws, contracts, or policy

## Current Checks

1. Algorithm policy checks
- Detects missing or unexpected algorithm declarations
- Flags alg=none as critical policy risk

2. Key-binding checks
- Validates algorithm family versus key material expectations
- Flags dynamic key-reference headers (jwk, jku, x5u)
- Detects HS and public-key material mismatch indicators

3. Claim audit
- Audits exp, nbf, iat, iss, aud
- Flags missing/invalid/expired temporal claims and missing issuer/audience binding

4. Payload sensitivity scan
- Detects sensitive claim names and likely PII indicators
- Flags private-key material and payment-card-like payload values

5. HS secret quality analysis (owner-supplied secret)
- Weak denylist checks
- Length and entropy checks

## Project Layout

```text
jwt-analyzer/
|-- main.py
|-- README.md
|-- core/
|   |-- decoder.py
|   |-- reporter.py
|   \-- attacks/
|       |-- alg_policy_check.py
|       |-- alg_key_binding_check.py
|       |-- claim_audit.py
|       |-- payload_scan.py
|       \-- secret_strength_check.py
|-- wordlists/
|   \-- weak_secrets.txt
|-- reports/
|   \-- report.html
\-- tests/
    |-- test_decoder.py
  |-- test_main.py
  |-- test_alg_key_binding_check.py
    |-- test_claim_audit.py
    |-- test_payload_scan.py
    \-- test_reporter.py
```

## Requirements

- Python 3.11+
- Packages:
  - pyjwt
  - requests
  - cryptography
  - colorama
  - pytest (for tests)

## Installation

From the project root:

```powershell
pip install pyjwt requests cryptography colorama pytest
```

## Usage

### 1) Basic offline analysis

```powershell
python main.py --token <JWT>
```

### 2) Controlled endpoint validation

```powershell
python main.py --token <JWT> --url https://your-controlled-endpoint/api/profile
```

### 3) Key-binding context with public key

```powershell
python main.py --token <JWT> --pubkey public.pem
```

### 4) Owner-supplied HS secret quality analysis

```powershell
python main.py --token <JWT> --known-secret "your-secret-value"
```

### 5) Custom weak-secret denylist

```powershell
python main.py --token <JWT> --known-secret "your-secret-value" --wordlist wordlists/weak_secrets.txt
```

### 6) Generate HTML report

```powershell
python main.py --token <JWT> --report --output reports/report.html
```

### 7) Emit JSON to stdout (CI friendly)

```powershell
python main.py --token <JWT> --json
```

### 8) Write JSON report file

```powershell
python main.py --token <JWT> --json --json-output reports/report.json
```

## Output Model

Each finding includes:
- id
- title
- severity
- category
- description
- evidence
- impact
- remediation

Risk score range is 0.0 to 10.0 with bands:
- NONE
- LOW
- MEDIUM
- HIGH
- CRITICAL

## Testing

Run tests from the jwt-analyzer directory:

```powershell
python -m pytest -q
```

## Guardrails for Contributors

- Keep the tool defensive and remediation-first.
- Do not add automated unauthorized attack workflows.
- Mask sensitive values in logs and reports where possible.
- Keep checks deterministic and test-covered.
