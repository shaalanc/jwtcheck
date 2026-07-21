# jwtcheck

jwtcheck is a simple local JWT decoder and weakness checker written in Python. It decodes a JWT, shows the header and payload, and checks for common issues such as:

- `alg=none` tokens that require no signature
- weak HMAC secrets for `HS256`/`HS384`/`HS512` tokens
- missing or expired claims like `exp` and `iat`

The script does not make network requests and only analyzes a token you provide.

## Requirements

- Python 3.10+

## Usage

Decode a JWT from the command line:

```bash
python jwtcheck.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3ODQ2NDcyMDF9.EVqGHdCBCL4DGliWtAXLzUICHuHCGvPqIHXaVqkcMAg"
```

Read a JWT from a file:

```bash
python jwtcheck.py --file token.txt
```

Use a custom wordlist for HMAC secret guessing:

```bash
python jwtcheck.py "<jwt>" --wordlist secrets.txt
```

Generate a test token for local experimentation:

```bash
python jwtcheck.py --generate-test-token --secret secret --claims '{"user":"admin","role":"admin"}'
```

Output JSON instead of the human-readable report:

```bash
python jwtcheck.py "<jwt>" --json
```

## Notes

- This tool is intended for authorized security testing and education.
- Only test tokens you own or are explicitly permitted to assess.
- The built-in wordlist is intentionally small and should be replaced with a stronger list for real-world testing.
