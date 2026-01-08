
import os
import glob
import json
from typing import Dict, List, Optional, Tuple, Union
from collections import defaultdict

# -- Dictionary of List initialisation

def initialise_sructure():
    results = {
        "host": [],
        "outdated_protocols": [],
        "outdated_ciphers": [],
        "wildcard": [],
        "chain_of_trust": [],
        "vulnerability": [],
        "days": [],
        "problem": [],
        "fingerprint": []
    }
    return results


def get_host(id_: str, finding: str, results):
    if id_.startswith("service"):
        results["host"].append(finding)
    return results

def get_outdated_protocol(id_: str, finding: str, results):
    outdated_protocol = ["SSLv2", "SSLv3", "TLS1", "TLS1_1"]
    if id_ in outdated_protocol and "offered (" in finding["finding"]:
        results["outdated_protocols"].append(finding)
    return results

def get_ciphers(id_:str, finding:str, results):
    ciphers_terms = ["CBC", "RC4", "3DES"]
    if id_.startswith("cipher-") and any(term in finding["finding"] for term in ciphers_terms):
        results["outdated_ciphers"].append(finding)
    return results

def wildcard_issue(id_: str, finding: str, results):
    if "cert_commonName" == id_ and finding["finding"].startswith("*"):
        results["wildcard"].append(finding)
    return results

def chain_of_trust(id_: str, finding: str, results):
    if id_.startswith("cert_chain_of_trust") and finding["severity"] != "OK":
        results["chain_of_trust"].append(finding)
    return results

def get_expiration_date(id_: str, finding: str, results):
    if len(results["days"]) == 0:
        if id_.startswith("cert_expirationStatus"):
            results["days"].append(finding)
        return results

def get_vunerability(id_: str, finding: str, results):

    if "cve" in finding and finding["severity"] not in {"OK", "INFO"}:
        results["vulnerability"].append(finding)
    return results

def get_problem(id_: str, finding: str, results):
    if id_ == "scanProblem" :
        results["problem"].append(finding)
    return results

def get_fingerpint(id_: str, finding: str, results):
    if id_.startswith("cert_fingerprintSHA256"):
        results["fingerprint"].append(finding)
    return results

def extract_information(id_: str, f: str, results):
    get_host(id_, f, results)
    get_outdated_protocol(id_, f, results)
    get_ciphers(id_, f, results)
    wildcard_issue(id_, f, results)
    chain_of_trust(id_, f, results)
    get_expiration_date(id_, f, results)
    get_vunerability(id_, f, results)
    get_problem(id_, f, results)
    get_fingerpint(id_, f, results)

    return results

"""
UNDERSTAND THE FINGERPRINTS ON CERT. WHY DO I HAVE 4? SAME FINGERS == SAME CERT // ONE ISSUE PRINT
These are actually two. #cert1 and #cert 2 are not refererring to the diif cert. Check ip and sha256
"""


def check_fingerptints(results):
    """
    Group hosts that share the same SHA256 fingerprint set.
    Returns: signature_to_hosts dict[tuple[fps], list[ip_field]]
    """
    hosts = results.get("host", [])
    fps = results.get("fingerprint", [])

    # host_ip_field -> set of sha256 fingerprints
    host_to_fps = defaultdict(set)

    # collect ip fields from service entries
    host_ip_fields = []
    for h in hosts:
        if isinstance(h, dict):
            ip_field = (h.get("ip") or "").strip()
            if ip_field:
                host_ip_fields.append(ip_field)

    # map fingerprints to their host via same ip_field
    for fp in fps:
        if not isinstance(fp, dict):
            continue
        fp_ip_field = (fp.get("ip") or "").strip()
        fp_value = (fp.get("finding") or "").strip()
        if fp_ip_field and fp_value:
            host_to_fps[fp_ip_field].add(fp_value)

    # group hosts by fingerprint signature
    signature_to_hosts = defaultdict(list)
    for ip_field in host_ip_fields:
        signature = tuple(sorted(host_to_fps.get(ip_field, set())))
        signature_to_hosts[signature].append(ip_field)

    # print fingerprint grouping (test output)
    for signature, grouped_hosts in signature_to_hosts.items():
        if not signature:
            print(f"[WARN] No fingerprints found for: {grouped_hosts}")
            continue

        if len(grouped_hosts) > 1:
            #print(f"[OK] Same fingerprints for ALL these hosts ({len(grouped_hosts)}):")
            for h in grouped_hosts:
                #print("   -", h)
                continue
        else:
            print(f"[INFO] Fingerprints only for host: {grouped_hosts[0]}")

    return signature_to_hosts


def _unique_keep_order(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def check_issues(results):

    # Check the sanity of the file
    if len(results["problem"]) == 0:

        # --- MULTI HOST CASE (same domain, multiple IPs) ---
        if len(results["host"]) > 1:
            #print("Found multiple IPs for the same domain")
            # Group hosts by fingerprint signature
            signature_to_hosts = check_fingerptints(results)

            # Map ip_field -> port (from service entries)
            host_port = {}
            for h in results["host"]:
                if isinstance(h, dict):
                    ip_field = h.get("ip", "Unknown")
                    port = h.get("port", "Unknown")
                    host_port[ip_field] = port

            # If more than 1 signature, hosts differ in cert chain
            if len(signature_to_hosts) > 1:
                print("[WARN] Different fingerprint sets detected across hosts; printing issues per fingerprint-group.")

            # Helper: filter findings by a set of host ip_fields
            def _filter_by_hosts(items, host_set):
                return [it for it in items if isinstance(it, dict) and it.get("ip") in host_set]

            # Print issues ONCE per fingerprint-group
            for signature, hosts_in_group in signature_to_hosts.items():
                host_set = set(hosts_in_group)

                # Header: applies to all hosts in this group
                print("## Applies to hosts:",
                      ", ".join(f"{ip}:{host_port.get(ip, 'Unknown')}" for ip in hosts_in_group))

                # Filter each issue list to this host group
                outdated_protocols = _filter_by_hosts(results["outdated_protocols"], host_set)
                vulnerability = _filter_by_hosts(results["vulnerability"], host_set)
                outdated_ciphers = _filter_by_hosts(results["outdated_ciphers"], host_set)
                wildcard = _filter_by_hosts(results["wildcard"], host_set)
                chain = _filter_by_hosts(results["chain_of_trust"], host_set)
                days = _filter_by_hosts(results["days"], host_set)

            if len(outdated_protocols) > 0:
                protos = _unique_keep_order([item.get("id", "Unknown") for item in outdated_protocols])
                print("Protocols Outdated:", ", ".join(protos))

            if len(vulnerability) > 0:
                vulns = _unique_keep_order([item.get("id", "Unknown") for item in vulnerability])
                print("Detected Vulnerabilities:", ", ".join(vulns))

            if len(outdated_ciphers) > 0:
                ciphers = _unique_keep_order([
                    (item.get("finding", "").split() or [""])[-1]
                    for item in outdated_ciphers
                ])
                print("Outdated Ciphers detected:", ", ".join(ciphers))

            if len(wildcard) > 0:
                wilds = _unique_keep_order([item.get("finding", "Unknown") for item in wildcard])
                print("Wildcard detected:", ", ".join(wilds))

            if len(chain) > 0:
                chains = _unique_keep_order([item.get("finding", "Unknown") for item in chain])
                print("Detected chain not trusted:", ", ".join(chains))

            if len(days) > 0:
                ds = _unique_keep_order([item.get("finding", "Unknown") for item in days])
                print("Days remaining:", ", ".join(ds))


                print("----------")

            return  # IMPORTANT: end here for multi-host case

        # --- SINGLE HOST CASE (unchanged) ---
        print("## Host:", ", ".join(
            f'{item.get("ip", "Unknown")}:{item.get("port", "Unknown")}' for item in results["host"]
        ))

        if len(results["outdated_protocols"]) > 0:
            print("Protocols Outdated:", ", ".join(item.get("id", "Unknown") for item in results["outdated_protocols"]))

        if len(results["vulnerability"]) > 0:
            print("Detected Vulnerabilities:", ", ".join(item.get("id", "Unknown") for item in results["vulnerability"]))

        if len(results["outdated_ciphers"]) > 0:
            print("Outdated Ciphers detected:", ", ".join(
                (item.get("finding", "").split() or [""])[-1] for item in results["outdated_ciphers"]
            ))

        if len(results["wildcard"]) > 0:
            print("Wildcard detected:", ", ".join(item.get("finding", "Unknown") for item in results["wildcard"]))

        if len(results["chain_of_trust"]) > 0:
            print("Detected chain not trusted:", ", ".join(item.get("finding", "Unknown") for item in results["chain_of_trust"]))

        if len(results["days"]) > 0:
            print("Days remaining:", ", ".join(item.get("finding", "Unknown") for item in results["days"]))

        print("----------")


def summarize_host(findings: List[dict]) -> None:
    """
    Print a simple summary of each finding.
    Expects a list of dicts with keys: id, finding, severity.
    """
    results = initialise_sructure()

    if not findings:
        print("  No findings.")
        return

    for f in findings:
        if not isinstance(f, dict):
            print(f"  Warning: finding entry is not a dict: {type(f).__name__}")
            continue
        id_ = str(f.get("id", "") or "")
        finding = str(f.get("finding", "") or "")
        severity = str(f.get("severity", "") or "")
        results = extract_information(id_, f, results)

    check_issues(results)

def extract_findings(data: Union[Dict, List]) -> Tuple[Optional[Dict], List[dict]]:
    """
    Normalize parsed JSON into (header, findings_list).
    - If data is a dict and contains 'findings', use that.
    - If data is a dict without 'findings' but looks like a list under another key, try to detect.
    - If data is a list, assume it's the findings list.
    """
    header = None
    findings: List[dict] = []

    if isinstance(data, dict):
        header = get_header_file(data)
        if "findings" in data and isinstance(data["findings"], list):
            findings = data["findings"]
        else:
            # Try to infer: maybe the dict only contains one list value that's the findings
            list_like_keys = [k for k, v in data.items() if isinstance(v, list)]
            if len(list_like_keys) == 1:
                findings = data[list_like_keys[0]]
            else:
                print("  Warning: Could not locate a 'findings' list in dict JSON.")
    elif isinstance(data, list):
        # Root is a list: treat as findings list
        findings = data
    else:
        print(f"  Warning: Unexpected JSON root type: {type(data).__name__}")

    return header, findings


def read_json_files(folder_path: str) -> None:
    # Pattern to match all JSON files in the folder (non-recursive)
    pattern = os.path.join(folder_path, "*.json")
    files = sorted(glob.glob(pattern))

    if not files:
        print("No JSON files found.")
        return

    for file_path in files:
        #print(f"\n--- File: {file_path} ---")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            header, findings = extract_findings(data)
            if header:
                print("Header:", header)

            if not isinstance(findings, list):
                print("  Warning: findings is not a list; skipping.")
                continue

            summarize_host(findings)

        except json.JSONDecodeError:
            print(f"Error: {file_path} is not a valid JSON file.")
        except Exception as e:
            print(f"Error reading {file_path}: {e}")


def main() -> None:
    folder = "results"  # Replace with your folder path
    read_json_files(folder)


if __name__ == "__main__":
    main()
