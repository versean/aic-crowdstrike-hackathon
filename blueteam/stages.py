"""Shared kill-chain stage labels and ATT&CK hints used by the UI and pipeline."""

PHASE_TO_STAGE = {
    "network_scans": "Reconnaissance",
    "service_scans": "Reconnaissance",
    "wpscan": "Web discovery",
    "dirb": "Web discovery",
    "webshell": "Initial access (webshell upload)",
    "cracking": "Credential access",
    "reverse_shell": "Execution (reverse shell)",
    "privilege_escalation": "Privilege escalation",
    "service_stop": "Impact / exfiltration",
    "dnsteal": "Impact / exfiltration",
}

STAGE_ORDER = [
    "Reconnaissance",
    "Web discovery",
    "Initial access (webshell upload)",
    "Credential access",
    "Execution (reverse shell)",
    "Privilege escalation",
    "Impact / exfiltration",
]

STAGE_MITRE = {
    "Reconnaissance": "TA0043 Reconnaissance / T1595 Active Scanning",
    "Web discovery": "T1595.003 Wordlist Scanning",
    "Initial access (webshell upload)": "T1190 Exploit Public-Facing App / T1505.003 Web Shell",
    "Credential access": "T1110.002 Password Cracking",
    "Execution (reverse shell)": "T1059 Command and Scripting Interpreter",
    "Privilege escalation": "T1548.003 Sudo and Sudo Caching",
    "Impact / exfiltration": "T1048 Exfiltration Over Alternative Protocol / T1489 Service Stop",
}
