# testssl_problems_only.py

A tiny Python CLI that reads a folder of **testssl** JSON files and prints a **problems‑only** summary for each affected host:port. It is optimized for large scans — compact, ANSI‑coloured, and focused on exactly what’s *not OK*.

---

## Features

- **Problems‑only output**: shows only deprecated/weak/invalid findings.
- **ANSI colours** (on by default; disable with `--no-color`).
- **Ports shown** explicitly (e.g., `example.com:8443`).
- Flags:
  - `--validity-threshold <days>` (default: 60) — warn if certificate validity is below threshold.
  - `--glob <pattern>` — restrict file glob in the input folder (default: `*.json`).
  - `--no-color` — ASCII output for CI.
- Resilient to wording differences across testssl versions (pattern‑based parsing of `id` and `finding`).

---

## What it detects as **NOT OK**

### Protocols
- **TLS 1.0** and **TLS 1.1** *offered* → flagged as deprecated exposures.
  - Background: IETF **RFC 8996** formally deprecates TLS 1.0/1.1 (Best Current Practice).  
    References: [RFC 8996 (datatracker)](https://datatracker.ietf.org/doc/html/rfc8996), [RFC 8996 (IETF)](https://www.ietf.org/rfc/rfc8996.pdf).

### Ciphers
- **RC4 offered** → NOT OK.
- **3DES offered** → NOT OK (SWEET32 risk).
- **CBC ciphers offered** → NOT OK (for TLS ≤ 1.2; CBC is not used in TLS 1.3).
- **Weak DH parameters** (e.g., small groups) → NOT OK.
  - Background: testssl ships checks for weak cipher categories and key exchange issues.  
    References: [testssl.sh repo](https://github.com/testssl/testssl.sh), [testssl manpage](https://manpages.ubuntu.com/manpages/bionic/man1/testssl.1.html).

### Certificate & Chain
- **Validity below threshold** (default 60 days) → shows as `validity XX days`.
- **Chain of trust NOT OK** → self‑signed, untrusted root, incomplete/broken chain, etc.
  - Background: certificate/chain details appear in testssl’s “server defaults” section and in JSON outputs.  
    References: [JSON Output notes](https://deepwiki.com/testssl/testssl.sh/4.2.1-json-output-format), [testssl doc](https://testssl.sh/2.9.5/doc/testssl.1.md).

### Vulnerabilities
- Surfaces common vulns if reported vulnerable: **Heartbleed**, **ROBOT**, **POODLE**, **SWEET32**, **FREAK**, **DROWN**, **LOGJAM**, **BEAST**, **CRIME/BREACH**, **CCS/Ticketbleed**, **LUCKY13**, **WINSHOCK**.
  - Background: testssl’s default run includes these checks.  
    References: [Examples & features](https://djangocas.dev/blog/security/testssl-command-line-tool-check-server-tls-ssl-ciphers-vulnerabilities/), [testssl.sh repo](https://github.com/testssl/testssl.sh).

---

## Installation

```bash
# Copy the script into your project
curl -O https://example.com/path/to/testssl_problems_only.py  # or save locally
chmod +x testssl_problems_only.py
```

*(You can also place it anywhere on your PATH and invoke it directly.)*

---

## Usage

```bash
# Basic run (scan folder of testssl JSON files)
python3 parserSSL.py ./results

# Warn if certs have < 45 days remaining
python3 parserSSL.py ./results --validity-threshold 45

# Disable colours (CI-friendly)
python3 parserSSL.py ./results --no-color

# Only parse files matching a pattern
python3 parserSSL.py ./results --glob 'scan_*_*.json'
```

### Example output

```
2026-01-06  203.0.113.10  api.example.com  rdns=api-10.example.com :8443
NOT OK:
- Protocols: TLS1.0 offered, TLS1.1 offered   [deprecated]
- Ciphers: RC4 offered, 3DES offered (SWEET32), CBC offered, weak DH params
- Certificate: validity 45 days [CN=api.example.com, wildcard=No]; chain of trust = NOT OK (self-signed)
- Vulnerabilities: SWEET32
------------------------------------------------------------
```

---

## How it groups and prints

- The CLI groups findings by **(domain, ip, port)** using the `ip` field (often `hostname/IP`) and `port` from testssl JSON.
- The **date** comes from the **file modification time** of each JSON file (newest seen per host:port).
- It prints a host only if at least **one** NOT OK item exists.

---

## Limitations & Notes

- Wording varies across testssl versions; this CLI uses **pattern matching** on `id`/`finding`, not strict strings.
- **CBC** detection is broad and flags any CBC suite found as *offered*. If you only care about CBC in TLS ≤ 1.2, adjust logic to verify protocol context.
- Windows consoles may need VT sequence support; otherwise use `--no-color`.

---
