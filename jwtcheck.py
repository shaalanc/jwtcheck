#!/usr/bin/env python3
"""
jwtcheck - JWT decoder + weakness checker.

Pure decode-and-analyze tool: operates only on a token string you supply,
no network requests, no target, no authorization question, unlike the
recon wrapper or the directory brute-forcer.

Checks for the classic JWT weaknesses:
  - alg=none acceptance (the token needs no valid signature at all)
  - brute-forceable HMAC secrets (HS256/384/512 only, RSA/EC can't be
    attacked this way, wrong tool for that)
  - missing or expired claims

Also includes a --generate-test-token mode, since there's no live
server anywhere handing out deliberately weak tokens to test against.

Usage:
    python jwtcheck.py "eyJhbGciOi..."
    python jwtcheck.py --file token.txt
    python jwtcheck.py "eyJ..." --wordlist secrets.txt
    python jwtcheck.py --generate-test-token --secret secret --claims '{"user":"admin","role":"admin"}'
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time

COMMON_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt_secret",
    "your-256-bit-secret", "supersecret", "secretkey", "key",
    "admin", "test", "letmein", "qwerty", "jwtsecret", "mysecret",
    "s3cr3t", "development", "production", "staging", "1234567890",
    "topsecret", "hunter2", "abc123", "default", "changethis",
]

HASH_FUNCS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode_jwt(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) != 3:
        print(f"[!] Not a valid JWT structure, expected 3 dot-separated parts, got {len(parts)}", file=sys.stderr)
        sys.exit(1)

    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception as e:
        print(f"[!] Couldn't decode/parse header or payload: {e}", file=sys.stderr)
        sys.exit(1)

    return {
        "header": header,
        "payload": payload,
        "signature_b64": signature_b64,
        "signing_input": f"{header_b64}.{payload_b64}",
    }


def check_alg_none(header: dict) -> dict | None:
    if header.get("alg", "").lower() == "none":
        return {
            "severity": "critical",
            "finding": "alg=none accepted means the token needs no valid signature at all. "
            "If whatever verifies this token accepts 'none', anyone can forge any claims.",
        }
    return None


def brute_force_hmac_secret(signing_input: str, signature_b64: str, wordlist: list[str], alg: str) -> str | None:
    hash_fn = HASH_FUNCS.get(alg)
    if not hash_fn:
        return None  # RS/ES algorithms can't be brute-forced this way

    target_sig = b64url_decode(signature_b64)
    for secret in wordlist:
        computed = hmac.new(secret.encode(), signing_input.encode(), hash_fn).digest()
        if hmac.compare_digest(computed, target_sig):
            return secret
    return None


def check_claims(payload: dict) -> list[dict]:
    findings = []
    now = int(time.time())

    if "exp" not in payload:
        findings.append({"severity": "medium", "finding": "No 'exp' claim, this token never expires."})
    elif payload["exp"] < now:
        findings.append({"severity": "info", "finding": f"Token is expired (exp={payload['exp']})."})

    if "iat" not in payload:
        findings.append({"severity": "low", "finding": "No 'iat' claim, can't tell when this was issued."})

    return findings


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return COMMON_SECRETS
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def generate_test_token(secret: str, alg: str, claims_json: str) -> str:
    header = {"alg": alg, "typ": "JWT"}
    payload = json.loads(claims_json)
    payload.setdefault("iat", int(time.time()))

    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    hash_fn = HASH_FUNCS[alg]
    signature = hmac.new(secret.encode(), signing_input.encode(), hash_fn).digest()
    signature_b64 = b64url_encode(signature)

    return f"{signing_input}.{signature_b64}"


def print_report(decoded: dict, findings: list[dict], cracked_secret: str | None):
    print("\n== Header ==")
    print(json.dumps(decoded["header"], indent=2))
    print("\n== Payload ==")
    print(json.dumps(decoded["payload"], indent=2))

    print("\n== Findings ==")
    if not findings and not cracked_secret:
        print("  No issues detected by this tool's checks.")
    for f in findings:
        print(f"  [{f['severity']}] {f['finding']}")
    if cracked_secret:
        print(f"  [critical] HMAC secret cracked: '{cracked_secret}', anyone with this can forge valid tokens.")
    print()


def main():
    parser = argparse.ArgumentParser(description="JWT decoder + weakness checker")
    parser.add_argument("token", nargs="?", help="JWT string to decode")
    parser.add_argument("--file", help="read the JWT from a file instead of the command line")
    parser.add_argument("--wordlist", help="custom wordlist for HMAC secret brute-forcing (default: small built-in list)")
    parser.add_argument("--json", action="store_true")

    parser.add_argument("--generate-test-token", action="store_true", help="generate a signed test JWT instead of decoding one")
    parser.add_argument("--secret", default="secret", help="secret to sign the generated token with (default: 'secret', deliberately weak)")
    parser.add_argument("--alg", default="HS256", choices=list(HASH_FUNCS.keys()))
    parser.add_argument("--claims", default='{"user": "testuser", "role": "user"}', help="JSON claims for the generated token")
    args = parser.parse_args()

    if args.generate_test_token:
        token = generate_test_token(args.secret, args.alg, args.claims)
        print(f"\n{token}\n")
        return

    if args.file:
        with open(args.file) as f:
            token = f.read().strip()
    elif args.token:
        token = args.token
    else:
        parser.error("provide a JWT string, --file, or --generate-test-token")

    decoded = decode_jwt(token)
    header, payload = decoded["header"], decoded["payload"]

    findings = check_claims(payload)
    alg_none = check_alg_none(header)
    if alg_none:
        findings.insert(0, alg_none)

    cracked_secret = None
    alg = header.get("alg", "").upper()
    if alg.startswith("HS"):
        wordlist = load_wordlist(args.wordlist)
        cracked_secret = brute_force_hmac_secret(decoded["signing_input"], decoded["signature_b64"], wordlist, alg)

    if args.json:
        print(json.dumps({"header": header, "payload": payload, "findings": findings, "cracked_secret": cracked_secret}, indent=2))
    else:
        print_report(decoded, findings, cracked_secret)


if __name__ == "__main__":
    main()