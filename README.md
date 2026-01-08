
# parserSSL

`parserSSL` is a lightweight Python parser for `testssl.sh` JSON outputs.  
It scans a folder of JSON result files, extracts the most relevant TLS/SSL findings, and prints a concise summary.

A key feature is **multi-IP domain handling**: if a domain resolves to multiple IPs, `parserSSL` groups hosts by the same **certificate SHA256 fingerprint set** and prints issues **once**, with an **"Applies to hosts"** line—reducing noisy duplicate output.

---

## Features

- Reads **multiple `.json` files** from a folder (`results/`)
- Extracts and prints:
  - Host(s) + port
  - Outdated protocols: `SSLv2`, `SSLv3`, `TLS1`, `TLS1_1`
  - Outdated ciphers containing: `CBC`, `RC4`, `3DES`
  - Wildcard certificate detection (`cert_commonName` starts with `*`)
  - Chain of trust errors (`cert_chain_of_trust*` where severity != OK)
  - Certificate expiration status / days remaining (`cert_expirationStatus`)
  - Vulnerabilities (findings containing `cve` and severity not in `OK`, `INFO`)
- **Multi-IP grouping by certificate fingerprints**
  - Collects `cert_fingerprintSHA256*` per host
  - Groups hosts with identical fingerprint sets
  - Prints issues once per group
  - Deduplicates repeated issue IDs (e.g. avoids `LUCKY13, LUCKY13`)

---

## Input: testssl.sh JSON

Generate JSON output with `testssl.sh`, for example:

```bash
./testssl.sh --jsonfile results/example.com.json example.com
