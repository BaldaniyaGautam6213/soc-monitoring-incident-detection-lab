"""
ioc_extractor.py — IOC extraction and enrichment for SOC Lab
Extracts Indicators of Compromise from log events and alerts.
"""

import re
import json
from typing import List, Dict, Any


# ─── Regex patterns ──────────────────────────────────────────────────────────

IP_PATTERN     = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
MD5_PATTERN    = re.compile(r'\b[0-9a-fA-F]{32}\b')
SHA256_PATTERN = re.compile(r'\b[0-9a-fA-F]{64}\b')
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+(?:ru|xyz|net|com|org|info|tk|io|cc|biz|top|club|online|site)\b'
)
URL_PATTERN    = re.compile(r'https?://[^\s\'"]+')
EMAIL_PATTERN  = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
USER_PATTERN   = re.compile(r'(?:Account|User|SubjectUserName|account_name)[=:\s]+([a-zA-Z0-9._\\-]+)', re.IGNORECASE)

# Known suspicious domains & IP ranges for enrichment
KNOWN_MALICIOUS_DOMAINS = {
    "malware-c2.ru": "Known C2 server (Threat Intel Feed)",
    "update-security-patch.xyz": "Phishing/malware distribution domain",
    "cdn-analytics-track.net": "Trojan download domain",
    "windows-update-srv.com": "Spoofed Windows Update domain",
    "auth.google-login-verify.tk": "Credential harvesting phishing site",
}

SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe", "pwdump.exe",
    "cobaltstrike", "meterpreter", "empire", "lazagne.exe",
    "svchost32.exe", "svhost.exe", "winlogon32.exe",
]

SENSITIVE_REGISTRY_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
]

SUSPICIOUS_PRIVILEGES = [
    "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege", "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
]


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract IOCs from a raw text string."""
    if not text:
        return {}
    return {
        "ip_addresses": list(set(IP_PATTERN.findall(text))),
        "md5_hashes":   list(set(MD5_PATTERN.findall(text))),
        "sha256_hashes": list(set(SHA256_PATTERN.findall(text))),
        "domains":      list(set(DOMAIN_PATTERN.findall(text))),
        "urls":         list(set(URL_PATTERN.findall(text))),
        "emails":       list(set(EMAIL_PATTERN.findall(text))),
    }


def enrich_iocs(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract and enrich IOCs from a list of log events.
    Returns a structured IOC report with threat intel annotations.
    """
    all_ips         = set()
    all_hashes      = set()
    all_domains     = set()
    all_urls        = set()
    all_users       = set()
    all_processes   = set()
    all_hostnames   = set()
    all_reg_keys    = set()
    all_privs       = set()

    for event in events:
        # Direct fields
        if event.get("source_ip") and event["source_ip"] not in ("N/A", ""):
            all_ips.add(event["source_ip"])
        if event.get("dest_ip"):
            all_ips.add(event["dest_ip"])
        if event.get("user") and event["user"] not in ("N/A", ""):
            all_users.add(event["user"])
        if event.get("hostname"):
            all_hostnames.add(event["hostname"])
        if event.get("process_name") and event["process_name"] not in ("N/A", ""):
            all_processes.add(event["process_name"])
        if event.get("file_hash"):
            all_hashes.add(event["file_hash"])
        if event.get("dest_domain"):
            all_domains.add(event["dest_domain"])
        if event.get("registry_key"):
            all_reg_keys.add(event["registry_key"])
        if event.get("privileges"):
            for priv in event["privileges"].split(","):
                priv = priv.strip()
                if priv in SUSPICIOUS_PRIVILEGES:
                    all_privs.add(priv)

        # Raw log text extraction
        raw = event.get("raw_log", "")
        extracted = extract_iocs_from_text(raw)
        all_ips.update(extracted.get("ip_addresses", []))
        all_hashes.update(extracted.get("md5_hashes", []))
        all_hashes.update(extracted.get("sha256_hashes", []))
        all_domains.update(extracted.get("domains", []))
        all_urls.update(extracted.get("urls", []))

    # Filter internal IPs
    external_ips = [ip for ip in all_ips if not (
        ip.startswith("192.168.") or ip.startswith("10.") or
        ip.startswith("172.16.") or ip.startswith("127.")
    )]
    internal_ips = [ip for ip in all_ips if ip not in external_ips]

    # Enrich domains
    domain_enrichment = {}
    for domain in all_domains:
        if domain in KNOWN_MALICIOUS_DOMAINS:
            domain_enrichment[domain] = {
                "verdict": "MALICIOUS",
                "reason": KNOWN_MALICIOUS_DOMAINS[domain],
                "risk_score": 95,
            }
        else:
            domain_enrichment[domain] = {
                "verdict": "SUSPICIOUS",
                "reason": "Not in whitelist — requires investigation",
                "risk_score": 60,
            }

    # Flag suspicious processes
    flagged_processes = {}
    for proc in all_processes:
        if any(sus in proc.lower() for sus in SUSPICIOUS_PROCESS_NAMES):
            flagged_processes[proc] = "KNOWN MALICIOUS TOOL"
        elif proc.lower() in ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "cscript.exe"):
            flagged_processes[proc] = "HIGH-RISK LOLBIN (Living off the Land Binary)"

    return {
        "external_ips":          sorted(external_ips),
        "internal_ips":          sorted(internal_ips),
        "file_hashes":           sorted(all_hashes),
        "domains":               domain_enrichment,
        "urls":                  sorted(all_urls),
        "usernames":             sorted(all_users),
        "hostnames":             sorted(all_hostnames),
        "processes":             sorted(all_processes),        # was a set — now list
        "flagged_processes":     flagged_processes,
        "registry_keys":         sorted(all_reg_keys),
        "suspicious_privileges": sorted(all_privs),
        "total_ioc_count":       len(external_ips) + len(all_hashes) + len(all_domains) + len(all_users),
    }


def ioc_summary_text(ioc_report: Dict[str, Any]) -> str:
    """Generate a human-readable IOC summary for incident reports."""
    lines = []

    if ioc_report.get("external_ips"):
        lines.append(f"External IPs: {', '.join(ioc_report['external_ips'])}")
    if ioc_report.get("usernames"):
        lines.append(f"Affected Users: {', '.join(ioc_report['usernames'])}")
    if ioc_report.get("file_hashes"):
        lines.append(f"File Hashes: {', '.join(ioc_report['file_hashes'][:3])}")
    if ioc_report.get("domains"):
        for domain, info in ioc_report["domains"].items():
            lines.append(f"Domain [{info['verdict']}]: {domain} — {info['reason']}")
    if ioc_report.get("flagged_processes"):
        for proc, reason in ioc_report["flagged_processes"].items():
            lines.append(f"Process [{reason}]: {proc}")
    if ioc_report.get("registry_keys"):
        lines.append(f"Registry Keys Modified: {', '.join(ioc_report['registry_keys'])}")
    if ioc_report.get("suspicious_privileges"):
        lines.append(f"Suspicious Privileges: {', '.join(ioc_report['suspicious_privileges'])}")

    return "\n".join(lines) if lines else "No high-confidence IOCs extracted."


if __name__ == "__main__":
    # Quick test
    test_events = [
        {"source_ip": "45.33.32.156", "user": "john.smith", "hostname": "DESKTOP-WIN10-01",
         "process_name": "powershell.exe", "dest_domain": "malware-c2.ru",
         "raw_log": "EventID=1 | powershell.exe -EncodedCommand | MD5=d41d8cd98f00b204e9800998ecf8427e"},
    ]
    report = enrich_iocs(test_events)
    print(json.dumps(report, indent=2))
    print("\n--- IOC SUMMARY ---")
    print(ioc_summary_text(report))
