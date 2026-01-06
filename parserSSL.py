
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
testssl_problems_only.py
Reads a folder of testssl JSON files and prints a compact "problems-only" summary.
- ANSI colours on by default (disable with --no-color)
- Includes deprecated protocols (TLS1.0/1.1), weak ciphers (RC4/3DES/CBC), weak DH,
  certificate near-expiry + broken trust, and known vulnerabilities.
- Prints ip, domain, rdns, and port for each affected host.

Notes:
- Designed to be resilient to wording differences across testssl versions.
- We look for IDs and key substrings in `id` or `finding` fields rather than exact phrases.
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

# ---------------- ANSI helpers ----------------
class Ansi:
    RED = "\x1b[31m"
    YELLOW = "\x1b[33m"
    CYAN = "\x1b[36m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RESET = "\x1b[0m"

def colorize(enabled: bool, text: str, col: str) -> str:
    return f"{col}{text}{Ansi.RESET}" if enabled else text

# ---------------- Parsing helpers ----------------
VULN_IDS = {
    # Common testssl vulnerability IDs (case-insensitive match; we'll substring-match)
    "HEARTBLEED", "ROBOT", "POODLE", "SWEET32", "FREAK", "DROWN",
    "LOGJAM", "BEAST", "CRIME", "BREACH", "CCS", "TICKETBLEED",
    "WINSHOCK", "LUCKY13"
}

RE_DAYS = re.compile(r"(\d+)\s*day", re.IGNORECASE)

def parse_ip_and_domain(ip_field: str) -> Tuple[Optional[str], Optional[str]]:
    """
    testssl often encodes as 'hostname/IP'. We try to split that.
    Returns (domain, ip). Either may be None if not present/parsable.
    """
    if not ip_field:
        return (None, None)
    if "/" in ip_field:
        left, right = ip_field.split("/", 1)
        # Heuristic: left is usually DNS name, right is IP
        domain = left.strip() or None
        ip = right.strip() or None
        return (domain, ip)
    # Otherwise we just have an IP or a host name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_field) or ":" in ip_field:
        return (None, ip_field.strip())
    return (ip_field.strip(), None)

def looks_offered(text: str) -> bool:
    """Return True if a finding suggests 'offered' (and not 'not offered')."""
    t = text.lower()
    return ("offered" in t or "supported" in t) and ("not offered" not in t and "is not offered" not in t and "not supported" not in t)

def looks_not_offered(text: str) -> bool:
    t = text.lower()
    return ("not offered" in t) or ("is not offered" in t) or ("not supported" in t)

def finding_mentions(text: str, *words: str) -> bool:
    t = text.upper()
    return all(w.upper() in t for w in words)

def extract_cn_and_wildcard(finding: str) -> Tuple[Optional[str], Optional[bool]]:
    """
    Attempt to grab Common Name and wildcard.
    This is heuristic; testssl's JSON wording can vary.
    """
    # Try CN=... pattern
    m = re.search(r"\bCN\s*=\s*([^\s,;/]+)", finding, flags=re.IGNORECASE)
    if m:
        cn = m.group(1).strip()
        return (cn, cn.startswith("*."))
    # Try "Common Name" style
    m = re.search(r"Common Name.*?:\s*([^\s,;/]+)", finding, flags=re.IGNORECASE)
    if m:
        cn = m.group(1).strip()
        return (cn, cn.startswith("*."))
    return (None, None)

def extract_rdns(finding: str) -> Optional[str]:
    # Look for reverse DNS / PTR mentions
    m = re.search(r"\br?dns\b[:=]\s*([A-Za-z0-9\.\-\_]+)", finding, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"\bPTR\b.*?:\s*([A-Za-z0-9\.\-\_]+)", finding, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"reverse lookup.*?:\s*([A-Za-z0-9\.\-\_]+)", finding, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None

def extract_validity_days(finding: str) -> Optional[int]:
    # Look for "... 45 days ..." etc.
    m = RE_DAYS.search(finding)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    return None

def chain_not_ok(finding: str) -> Optional[str]:
    t = finding.lower()
    keywords = [
        "self-signed", "self signed", "untrusted", "not trusted", "unknown ca",
        "missing intermediate", "incomplete chain", "chain issues", "broken chain"
    ]
    for k in keywords:
        if k in t:
            return k
    return None

def is_cbc_cipher(finding_or_id: str) -> bool:
    return "CBC" in finding_or_id.upper()

def is_rc4(finding_or_id: str) -> bool:
    return "RC4" in finding_or_id.upper()

def is_3des(finding_or_id: str) -> bool:
    up = finding_or_id.upper()
    return "3DES" in up or "DES-CBC3" in up or "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in up

def is_weak_dh(finding: str) -> bool:
    t = finding.lower()
    return ("dh" in t and ("weak" in t or "bits" in t and any(x in t for x in ["512", "768", "1024"])))

def is_vulnerable_entry(vuln_id: str, finding: str, severity: str) -> bool:
    # Consider not OK if severity is not OK/INFO, or if finding explicitly says "vulnerable"
    t = finding.lower()
    if "not vulnerable" in t or "no vulnerability" in t:
        return False
    # Many testssl vulns mark vulnerable with 'VULNERABLE' or 'VULNERABLE (something)'
    if "vulnerable" in t:
        return True
    # Fallback: if severity is HIGH/CRITICAL/MEDIUM/LOW for a known vuln ID
    sev = severity.upper()
    if vuln_id and any(v in vuln_id.upper() for v in VULN_IDS) and sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN"}:
        return True
    return False

# ---------------- Aggregation ----------------
class HostAgg:
    def __init__(self):
        self.domain: Optional[str] = None
        self.ip: Optional[str] = None
        self.port: Optional[str] = None
        self.rdns: Optional[str] = None

        # Problems
        self.bad_protocols: List[str] = []          # e.g., ["TLS1.0 offered", "TLS1.1 offered"]
        self.bad_ciphers: List[str] = []            # e.g., ["RC4 offered", "3DES offered (SWEET32)", "CBC offered", "weak DH params"]
        self.cert_issues: List[str] = []            # e.g., ["validity 45 days", "chain of trust = NOT OK (self-signed)"]
        self.vulns: List[str] = []                  # e.g., ["SWEET32 vulnerable"]

        # Hint fields
        self.cn: Optional[str] = None
        self.wildcard: Optional[bool] = None
        self.min_validity_days: Optional[int] = None
        self.chain_detail: Optional[str] = None

    def any_problem(self) -> bool:
        return any([self.bad_protocols, self.bad_ciphers, self.cert_issues, self.vulns])

def summarize_host(findings: List[dict], validity_threshold: int) -> HostAgg:
    agg = HostAgg()

    # Track cipher weakness booleans so we don't duplicate
    has_rc4 = has_3des = has_cbc = has_weakdh = False
    offered_tls10 = offered_tls11 = False
    chain_issue_key: Optional[str] = None
    min_days: Optional[int] = None

    # Heuristic scan
    for f in findings:
        id_ = str(f.get("id", "") or "")
        finding = str(f.get("finding", "") or "")
        severity = str(f.get("severity", "") or "")

        # Host meta
        if agg.port is None and f.get("port"):
            agg.port = str(f["port"])
        if agg.domain is None or agg.ip is None:
            d, ip = parse_ip_and_domain(str(f.get("ip", "") or ""))
            agg.domain = agg.domain or d
            agg.ip = agg.ip or ip

        # rdns
        if agg.rdns is None:
            rd = extract_rdns(finding)
            if rd:
                agg.rdns = rd

        # Protocols: flag TLS1.0/1.1 if "offered"
        if id_.upper() in {"TLS1", "TLS1_1"}:
            if looks_offered(finding):
                if id_.upper() == "TLS1":
                    offered_tls10 = True
                else:
                    offered_tls11 = True

        # Ciphers: weak families
        id_plus = f"{id_} {finding}"
        if not has_rc4 and is_rc4(id_plus) and looks_offered(finding):
            has_rc4 = True
        if not has_3des and is_3des(id_plus) and looks_offered(finding):
            has_3des = True
        if not has_cbc and is_cbc_cipher(id_plus) and looks_offered(finding):
            has_cbc = True
        if not has_weakdh and is_weak_dh(finding):
            has_weakdh = True

        # Certificate hints: CN / wildcard
        if agg.cn is None or agg.wildcard is None:
            cn, wc = extract_cn_and_wildcard(finding)
            if cn:
                agg.cn = cn
                agg.wildcard = wc

        # Certificate validity (min days encountered)
        days = extract_validity_days(finding)
        if days is not None:
            if min_days is None or days < min_days:
                min_days = days

        # Chain of trust problems
        bad = chain_not_ok(finding)
        if bad and chain_issue_key is None:
            chain_issue_key = bad

        # Vulnerabilities
        if any(v in id_.upper() for v in VULN_IDS) or any(v in finding.upper() for v in VULN_IDS):
            # Use the ID as the vuln label
            label = next((v for v in VULN_IDS if v in id_.upper() or v in finding.upper()), None)
            if label and is_vulnerable_entry(label, finding, severity):
                if label not in agg.vulns:
                    agg.vulns.append(label)

    # Finalize protocol issues (RFC 8996 deprecation)
    if offered_tls10:
        agg.bad_protocols.append("TLS1.0 offered")
    if offered_tls11:
        agg.bad_protocols.append("TLS1.1 offered")

    # Finalize cipher issues
    if has_rc4:
        agg.bad_ciphers.append("RC4 offered")
    if has_3des:
        agg.bad_ciphers.append("3DES offered (SWEET32)")
    if has_cbc:
        agg.bad_ciphers.append("CBC offered")
    if has_weakdh:
        agg.bad_ciphers.append("weak DH params")

    # Finalize certificate issues
    if min_days is not None:
        agg.min_validity_days = min_days
        if min_days < validity_threshold:
            agg.cert_issues.append(f"validity {min_days} days")
    if chain_issue_key:
        agg.chain_detail = chain_issue_key
        agg.cert_issues.append(f"chain of trust = NOT OK ({chain_issue_key})")

    return agg

def load_json_file(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    # Some users might concatenate arrays; tolerate dicts (unlikely) by normalizing
    if isinstance(data, dict):
        # Try common key names; otherwise wrap
        items = data.get("scanResult") or data.get("findings") or []
        if isinstance(items, list):
            return items
        return [data]
    elif isinstance(data, list):
        return data
    else:
        return []

def main():
    ap = argparse.ArgumentParser(description="Print problems-only summary from testssl JSON folder.")
    ap.add_argument("folder", help="Folder containing one or more testssl JSON files")
    ap.add_argument("--validity-threshold", type=int, default=60, help="Warn if certificate validity is below this many days (default: 60)")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    ap.add_argument("--glob", default="*.json", help="Filename glob to include (default: *.json)")
    args = ap.parse_args()

    use_color = not args.no_color

    # Collect findings per host (key = (domain, ip, port))
    per_host: Dict[Tuple[Optional[str], Optional[str], Optional[str]], List[dict]] = defaultdict(list)
    file_dates: Dict[Tuple[Optional[str], Optional[str], Optional[str]], datetime] = {}

    import glob
    pattern = os.path.join(args.folder, args.glob)
    files = sorted(glob.glob(pattern))
    if not files:
        print("No JSON files found.")
        sys.exit(1)

    for fp in files:
        try:
            findings = load_json_file(fp)
        except Exception as e:
            print(colorize(use_color, f"[!] Failed to parse {fp}: {e}", Ansi.RED), file=sys.stderr)
            continue
        # Determine file time as scan date fallback
        dt = datetime.fromtimestamp(os.path.getmtime(fp), tz=timezone.utc)

        # Group by host tuple
        # We may see multiple hosts in one file; collect first pass,
        # then we’ll repartition by the values encountered.
        temp_groups: Dict[Tuple[Optional[str], Optional[str], Optional[str]], List[dict]] = defaultdict(list)
        for f in findings:
            d, ip = parse_ip_and_domain(str(f.get("ip", "") or ""))
            port = str(f.get("port", "") or "") or None
            key = (d, ip, port)
            temp_groups[key].append(f)

        for key, lst in temp_groups.items():
            per_host[key].extend(lst)
            # Keep the newest date across files for the same key
            if key not in file_dates or dt > file_dates[key]:
                file_dates[key] = dt

    # Print problems-only view
    for (domain, ip, port), lst in sorted(per_host.items(), key=lambda kv: (kv[0][1] or "", kv[0][0] or "", kv[0][2] or "")):
        agg = summarize_host(lst, args.validity_threshold)
        if not agg.any_problem():
            continue

        # Header
        dt = file_dates.get((domain, ip, port)) or datetime.now(tz=timezone.utc)
        datestr = dt.strftime("%Y-%m-%d")
        ip_s = ip or "-"
        domain_s = domain or "-"
        rdns_s = agg.rdns or "-"
        port_s = port or "-"
        header = f"{datestr}  {ip_s}  {domain_s}  rdns={rdns_s} :{port_s}"
        print(colorize(use_color, header, Ansi.CYAN))

        # NOT OK sections
        print(colorize(use_color, "NOT OK:", Ansi.BOLD))

        if agg.bad_protocols:
            proto_line = ", ".join(sorted(set(agg.bad_protocols), key=str.lower))
            # Emphasize deprecated status
            proto_line += "   [deprecated]"
            print(f"- Protocols: {colorize(use_color, proto_line, Ansi.RED)}")

        if agg.bad_ciphers:
            cipher_line = ", ".join(sorted(set(agg.bad_ciphers), key=str.lower))
            print(f"- Ciphers: {colorize(use_color, cipher_line, Ansi.RED)}")

        if agg.cert_issues:
            cert_line = ", ".join(agg.cert_issues)
            # Append CN/wildcard context if known
            ctx = []
            if agg.cn:
                ctx.append(f"CN={agg.cn}")
            if agg.wildcard is not None:
                ctx.append(f"wildcard={'Yes' if agg.wildcard else 'No'}")
            if ctx:
                cert_line += " [" + ", ".join(ctx) + "]"
            print(f"- Certificate: {colorize(use_color, cert_line, Ansi.YELLOW)}")

        if agg.vulns:
            vuln_line = ", ".join(sorted(set(agg.vulns), key=str.lower))
            print(f"- Vulnerabilities: {colorize(use_color, vuln_line, Ansi.RED)}")

        print(colorize(use_color, "-"*60, Ansi.DIM))

if __name__ == "__main__":
    main()
