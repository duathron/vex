"""MITRE ATT&CK mapping dictionary.

Maps VirusTotal sandbox behavior keywords, tags, and file characteristics
to ATT&CK technique IDs.  This is a best-effort, curated mapping — not
exhaustive, but covers the most common techniques observed in VT reports.
"""

from __future__ import annotations

# Format:  keyword/pattern  →  (technique_id, technique_name, tactic)
# Keywords are matched case-insensitively against VT sandbox fields.

BEHAVIOR_MAP: dict[str, tuple[str, str, str]] = {
    # --- Execution ---
    "powershell": ("T1059.001", "PowerShell", "Execution"),
    "cmd.exe": ("T1059.003", "Windows Command Shell", "Execution"),
    "wscript": ("T1059.005", "Visual Basic", "Execution"),
    "cscript": ("T1059.005", "Visual Basic", "Execution"),
    "mshta": ("T1218.005", "Mshta", "Defense Evasion"),
    "rundll32": ("T1218.011", "Rundll32", "Defense Evasion"),
    "regsvr32": ("T1218.010", "Regsvr32", "Defense Evasion"),
    "schtasks": ("T1053.005", "Scheduled Task", "Execution"),
    "at.exe": ("T1053.002", "At", "Execution"),
    "wmic": ("T1047", "Windows Management Instrumentation", "Execution"),
    "certutil": ("T1140", "Deobfuscate/Decode Files", "Defense Evasion"),

    # --- Persistence ---
    "\\currentversion\\run": ("T1547.001", "Registry Run Keys", "Persistence"),
    "\\run\\": ("T1547.001", "Registry Run Keys", "Persistence"),
    "\\runonce\\": ("T1547.001", "Registry Run Keys", "Persistence"),
    "startup": ("T1547.001", "Registry Run Keys", "Persistence"),
    "task scheduler": ("T1053.005", "Scheduled Task", "Persistence"),
    "\\services\\": ("T1543.003", "Windows Service", "Persistence"),
    "sc.exe": ("T1543.003", "Windows Service", "Persistence"),

    # --- Privilege Escalation ---
    "runas": ("T1134", "Access Token Manipulation", "Privilege Escalation"),
    "token": ("T1134", "Access Token Manipulation", "Privilege Escalation"),

    # --- Defense Evasion ---
    "process hollowing": ("T1055.012", "Process Hollowing", "Defense Evasion"),
    "injection": ("T1055", "Process Injection", "Defense Evasion"),
    "createremotethread": ("T1055.001", "DLL Injection", "Defense Evasion"),
    "ntwritevirtualmemory": ("T1055", "Process Injection", "Defense Evasion"),
    "virtualalloc": ("T1055", "Process Injection", "Defense Evasion"),
    "amsi": ("T1562.001", "Disable or Modify Tools", "Defense Evasion"),
    "uac": ("T1548.002", "Bypass User Account Control", "Privilege Escalation"),
    "defender": ("T1562.001", "Disable or Modify Tools", "Defense Evasion"),
    "exclusion": ("T1562.001", "Disable or Modify Tools", "Defense Evasion"),
    "obfuscated": ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    "packed": ("T1027.002", "Software Packing", "Defense Evasion"),
    "packer": ("T1027.002", "Software Packing", "Defense Evasion"),
    "upx": ("T1027.002", "Software Packing", "Defense Evasion"),
    "base64": ("T1140", "Deobfuscate/Decode Files", "Defense Evasion"),

    # --- Credential Access ---
    "mimikatz": ("T1003.001", "LSASS Memory", "Credential Access"),
    "lsass": ("T1003.001", "LSASS Memory", "Credential Access"),
    "credentials": ("T1555", "Credentials from Password Stores", "Credential Access"),
    "keylog": ("T1056.001", "Keylogging", "Collection"),
    "\\login data": ("T1555.003", "Credentials from Web Browsers", "Credential Access"),
    "\\cookies\\": ("T1539", "Steal Web Session Cookie", "Credential Access"),
    "wallet": ("T1005", "Data from Local System", "Collection"),

    # --- Discovery ---
    "systeminfo": ("T1082", "System Information Discovery", "Discovery"),
    "ipconfig": ("T1016", "System Network Configuration Discovery", "Discovery"),
    "netstat": ("T1049", "System Network Connections Discovery", "Discovery"),
    "tasklist": ("T1057", "Process Discovery", "Discovery"),
    "whoami": ("T1033", "System Owner/User Discovery", "Discovery"),
    "net view": ("T1135", "Network Share Discovery", "Discovery"),
    "net user": ("T1087.001", "Local Account", "Discovery"),
    "query reg": ("T1012", "Query Registry", "Discovery"),
    "reg query": ("T1012", "Query Registry", "Discovery"),

    # --- Lateral Movement ---
    "psexec": ("T1569.002", "Service Execution", "Lateral Movement"),
    "wmi": ("T1047", "Windows Management Instrumentation", "Lateral Movement"),

    # --- Collection ---
    "screenshot": ("T1113", "Screen Capture", "Collection"),
    "clipboard": ("T1115", "Clipboard Data", "Collection"),
    "microphone": ("T1123", "Audio Capture", "Collection"),
    "webcam": ("T1125", "Video Capture", "Collection"),

    # --- Command and Control ---
    "tor": ("T1090.003", "Multi-hop Proxy", "Command and Control"),
    "dns tunnel": ("T1071.004", "DNS", "Command and Control"),
    "irc": ("T1071.001", "Web Protocols", "Command and Control"),
    "http": ("T1071.001", "Web Protocols", "Command and Control"),
    "https": ("T1071.001", "Web Protocols", "Command and Control"),
    "cobaltstrike": ("T1071.001", "Web Protocols", "Command and Control"),
    "beacon": ("T1071.001", "Web Protocols", "Command and Control"),
    "c2": ("T1071", "Application Layer Protocol", "Command and Control"),

    # --- Exfiltration ---
    "ftp": ("T1048.003", "Exfiltration Over Unencrypted Protocol", "Exfiltration"),
    "smtp": ("T1048.003", "Exfiltration Over Unencrypted Protocol", "Exfiltration"),
    "telegram": ("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration"),
    "discord": ("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration"),

    # --- Impact ---
    "encrypt": ("T1486", "Data Encrypted for Impact", "Impact"),
    "ransom": ("T1486", "Data Encrypted for Impact", "Impact"),
    "wiper": ("T1485", "Data Destruction", "Impact"),
    "vssadmin": ("T1490", "Inhibit System Recovery", "Impact"),
    "bcdedit": ("T1490", "Inhibit System Recovery", "Impact"),
    "shadow": ("T1490", "Inhibit System Recovery", "Impact"),
}


# Tags commonly seen in VT that map to ATT&CK techniques
TAG_MAP: dict[str, tuple[str, str, str]] = {
    "exploit": ("T1203", "Exploitation for Client Execution", "Execution"),
    "dropper": ("T1204.002", "Malicious File", "Execution"),
    "downloader": ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "backdoor": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "trojan": ("T1204.002", "Malicious File", "Execution"),
    "ransomware": ("T1486", "Data Encrypted for Impact", "Impact"),
    "cryptominer": ("T1496", "Resource Hijacking", "Impact"),
    "miner": ("T1496", "Resource Hijacking", "Impact"),
    "stealer": ("T1555", "Credentials from Password Stores", "Credential Access"),
    "infostealer": ("T1555", "Credentials from Password Stores", "Credential Access"),
    "rat": ("T1219", "Remote Access Software", "Command and Control"),
    "botnet": ("T1583.005", "Botnet", "Resource Development"),
    "rootkit": ("T1014", "Rootkit", "Defense Evasion"),
    "keylogger": ("T1056.001", "Keylogging", "Collection"),
    "spyware": ("T1005", "Data from Local System", "Collection"),
    "worm": ("T1080", "Taint Shared Content", "Lateral Movement"),
    "phishing": ("T1566", "Phishing", "Initial Access"),
    "macro": ("T1059.005", "Visual Basic", "Execution"),
    "adware": ("T1583.001", "Domains", "Resource Development"),
}
