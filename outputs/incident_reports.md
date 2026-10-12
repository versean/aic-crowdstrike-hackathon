# AlertLens incident reports

## fox — incident #1 (risk 5.73)
*2022-01-18 12:17 → 12:39 UTC · 51 meta-alerts · 420,085 raw alerts · stages: Reconnaissance → Web discovery → Initial access (webshell upload)*

### Verdict
**TRUE POSITIVE** (high confidence) - Multiple sensors (Wazuh, Suricata, AMiner) detected coordinated reconnaissance, web discovery, and initial access via webshell upload from IP `172.17.130.196`, with rare rules firing across the network and suspicious log entries indicating a potential attack.

### What happened
- **01-18 12:17:15 UTC - Reconnaissance**: Multiple hosts reported insecure SSH connection attempts from IP `172.17.130.196`, with rare rules firing across the network and simultaneous alerts from 16 hosts.
- **01-18 12:17:50 UTC - Web discovery**: AMiner detected a new request method in Apache logs from `172.17.130.196` using the WPScan tool, indicating targeted WordPress scanning.
- **01-18 12:38:25 UTC - Initial access (webshell upload)**: AMiner flagged high entropy in Apache access logs, suggesting a potential webshell upload attempt with a suspicious `.php` file containing encoded parameters.

### Affected assets & IOCs
- **Hosts**: `10.35.32.1`, `10.35.33.111`, `10.35.35.206`, `172.17.129.140`, `172.17.130.196`, `172.17.130.37`, `172.17.131.81`, `192.168.128.170`, `cloud-share`, `inet-firewall`, `internal-share`, `intranet-server`
- **Source IPs**: `10.9.0.18`, `172.17.130.196`, `172.17.131.81`, `192.168.128.4`, `192.168.130.77`
- **URLs**: `/nmaplowercheck1642508249`, `/wp-content/debug.log`, `/.wp-config.swp`, `/_mem_bin`, `/wp-content/uploads/2022/01/yqagisjaqe-1642509481.8663.php?wp_meta=WyJteXNxbCIsICItdSIsICJ3b3JkcHJlc3MiLCAiLXB0YWlub294M2FlZGVl`

### MITRE ATT&CK
- **TA0043 Reconnaissance / T1595 Active Scanning**: Multiple SSH scans and Nmap user-agent detection.
- **T1595.003 Wordlist Scanning**: WPScan tool used to scan WordPress sites.
- **T1190 Exploit Public-Facing App / T1505.003 Web Shell**: Suspicious `.php` file with encoded parameters suggests a webshell upload attempt.

### Recommended response
1. **Isolate the source IP `172.17.130.196`** and block it at the firewall (`inet-firewall`) to prevent further network access.
2. **Investigate the webserver `10.35.35.206`** for signs of webshell presence, focusing on the suspicious `.php` file and encoded parameters.
3. **Scan all affected hosts** for malware or unauthorized changes, especially those with Apache logs showing 400 errors or forbidden file access.
4. **Review and harden WordPress configurations** on `intranet-server` and other web servers, ensuring that sensitive files like `wp-config.php` are not accessible.
5. **Audit and update firewall and IDS rules** to detect similar patterns in the future, especially for rare rules and high-entropy traffic.

## fox — incident #2 (risk 1.83)
*2022-01-19 13:09 → 14:00 UTC · 4 meta-alerts · 4 raw alerts · stages: Impact / exfiltration*

### Verdict
TRUE POSITIVE (high confidence) - Evidence shows exfiltration of large files via HTTP GET requests with suspicious download secrets, indicating data theft.

### What happened
- **01-19 13:09:04 UTC** - **Impact / Exfiltration** - A GET request was made to download a file (`Photos (2)`) from `cloud.dmz.price.fox.org` with a suspicious `downloadStartSecret` parameter, indicating potential data exfiltration.
- **01-19 13:09:04 UTC** - **Impact / Exfiltration** - A similar GET request was made from `172.17.130.37` to download the same file, with the same suspicious secret, suggesting coordinated exfiltration activity.
- **01-19 14:00:31 UTC** - **Impact / Exfiltration** - A large file (`ownCloud Manual (2).pdf`) was exfiltrated from `cloud.dmz.price.fox.org` using a unique `downloadStartSecret`, indicating continued data theft.

### Affected assets & IOCs
- **Hosts**: `172.17.129.140`, `172.17.130.37`
- **Source IPs**: `10.35.33.116`, `172.17.130.196` (indirectly involved)
- **URLs**: 
  - `https://cloud.dmz.price.fox.org/index.php/apps/files/ajax/download.php?dir=%2F&files=Photos%20(2)&downloadStartSecret=uq2iq8qsxrk`
  - `https://cloud.dmz.price.fox.org/remote.php/webdav/ownCloud%20Manual%20(2).pdf?downloadStartSecret=6syynp9uz9c`
- **IOCs**: 
  - `downloadStartSecret=uq2iq8qsxrk`
  - `downloadStartSecret=6syynp9uz9c`
  - Large file transfers (6MB+)

### MITRE ATT&CK
- **T1048** - Exfiltration Over Alternative Protocol (HTTP GET requests used for data exfiltration)
- **T1489** - Service Stop (potential service disruption or manipulation to cover tracks)

### Recommended response
1. **Isolate affected hosts** (`172.17.129.140`, `172.17.130.37`) and investigate for unauthorized access or lateral movement.
2. **Block the source IPs** (`10.35.33.116`, `172.17.130.196`) and monitor for further suspicious activity.
3. **Review logs** for the suspicious `downloadStartSecret` values and trace the origin of the exfiltrated files.
4. **Audit user accounts** on the affected hosts for unauthorized access or privilege escalation.
5. **Implement additional monitoring** for large file transfers and unusual HTTP GET requests with secret parameters.

## harrison — incident #1 (risk 6.77)
*2022-02-08 07:16 → 08:37 UTC · 47 meta-alerts · 424,951 raw alerts · stages: Reconnaissance → Web discovery → Credential access → Execution (reverse shell) → Privilege escalation*

### Verdict
TRUE POSITIVE (high confidence) - Multiple high-risk alerts from AMiner, Wazuh, and Suricata indicate a multi-stage attack with reconnaissance, web discovery, credential access, execution, and privilege escalation.

### What happened
- **02-08 07:16:20 UTC - Reconnaissance**: AMiner and Suricata detect rare and suspicious activity, including failed SSH connections and Nmap-like scanning behavior from IP `10.237.1.238`.
- **02-08 07:28:41 UTC - Web discovery**: Wazuh and AMiner detect numerous 400/500 errors, forbidden file access attempts, and WPScan tool usage from `10.237.1.238`, indicating targeted web application scanning.
- **02-08 08:36:28 UTC - Execution & Privilege escalation**: AMiner detects a high-entropy request with a suspicious PHP file, followed by Wazuh and AMiner detecting successful `su` and `sudo` commands, indicating privilege escalation to root by user `jward`.

### Affected assets & IOCs
- **Hosts**: `192.168.131.215`, `intranet-server`, `192.168.128.1`, `inet-firewall`, `10.237.0.166`
- **Source IPs**: `10.237.1.238`, `172.28.192.242`, `172.28.192.4`, `10.237.2.255`
- **Accounts**: `www-data`, `jward`, `root`
- **URLs**: `/wp-content/uploads/2022/02/yumzrshbwn-1644306962.5811.php`, `/aa04078.html`, `/_mem_bin`, `/.wp-config.swp`, `/wp-content/themes/go/`, `/wp-content/plugins/301-redirects/`
- **Tools**: WPScan v3.8.20, Nmap

### MITRE ATT&CK
- **TA0043 Reconnaissance**: T1595 Active Scanning
- **T1595.003 Wordlist Scanning** (Web discovery)
- **T1110.002 Password Cracking** (Credential access)
- **T1059 Command and Scripting Interpreter** (Execution)
- **T1548.003 Sudo and Sudo Caching** (Privilege escalation)

### Recommended response
1. **Isolate affected hosts** (`192.168.131.215`, `intranet-server`) and block source IPs (`10.237.1.238`, `172.28.192.242`, `172.28.192.4`) at the firewall.
2. **Investigate user `jward`** and audit all sudo/root access logs for suspicious activity.
3. **Contain and remediate** the compromised web server (`192.168.131.215`) and ensure no malicious files (e.g., `yumzrshbwn-1644306962.5811.php`) remain on the system.
4. **Perform a full network scan** to identify any other compromised systems or lateral movement.
5. **Review and update** web server configurations to block suspicious request methods and file paths.

## harrison — incident #2 (risk 0.46)
*2022-02-04 06:16 → 06:21 UTC · 1 meta-alerts · 108 raw alerts · stages: Reconnaissance*

### Verdict
TRUE POSITIVE (high confidence) - Unusual outbound traffic from 172.28.192.4 to 192.168.128.1 with a rare rule firing multiple times, indicating potential reconnaissance activity.

### What happened
- **02-04 06:16:25 UTC** - **Reconnaissance** - Suricata detected 108 alerts from IP `172.28.192.4` to host `192.168.128.1` using a rare rule related to GNU/Linux APT User-Agent, suggesting scanning or probing behavior.
- **02-04 06:16:25 - 06:21:52 UTC** - **Reconnaissance** - Multiple detections across the network within a 10-minute window, with 5 rarely-seen alerts, indicating potential active scanning.
- **02-04 06:21:52 UTC** - **Reconnaissance** - Attack indicators found in raw logs, pointing to potential malicious activity attempting to map the network or identify vulnerable systems.

### Affected assets & IOCs
- **Hosts**: `192.168.128.1`
- **Source IPs**: `172.28.192.4`
- **URLs/Paths**: `/ubuntu/pool/main/s/shadow/login_4.5-1ubuntu2.2_amd64.deb`
- **Rule ID**: Suricata: Alert - ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management

### MITRE ATT&CK
- **TA0043** - Reconnaissance
- **T1595** - Active Scanning

### Recommended response
1. **Isolate and investigate the source IP** `172.28.192.4` to determine if it is a legitimate system or a compromised host.
2. **Review logs** from `192.168.128.1` for any unusual activity around the time of the alerts.
3. **Block or restrict traffic** from `172.28.192.4` if no legitimate reason for the activity is found.
4. **Correlate with other sensors** (e.g., Wazuh or AMiner) to check for additional signs of reconnaissance or exploitation.
5. **Update Suricata rules** and ensure the rare rule is reviewed for accuracy and potential false positives.

## russellmitchell — incident #1 (risk 8.28)
*2022-01-24 03:56 → 04:38 UTC · 77 meta-alerts · 11,228 raw alerts · stages: Reconnaissance → Web discovery → Initial access (webshell upload) → Credential access → Execution (reverse shell) → Privilege escalation*

### Verdict
**TRUE POSITIVE** (high confidence) - Multiple sensors (Wazuh, Suricata, AMiner) detect coordinated reconnaissance, web discovery, initial access via webshell, credential access, execution, and privilege escalation activities with high-risk scores and rare rule firings across the network.

### What happened
- **01-24 03:56:53 UTC - Reconnaissance**: Multiple hosts (e.g., 172.19.130.68, 192.168.231.164) trigger Wazuh alerts for 400 errors and forbidden file access from IP `192.168.230.122`, indicating initial scanning and probing.
- **01-24 03:57:01 UTC - Web discovery**: Suricata and Wazuh detect Nmap-like scanning behavior (`ET SCAN Possible Nmap User-Agent Observed`) and unusual Apache access patterns, suggesting enumeration of web assets.
- **01-24 04:37:25 UTC - Execution & Privilege escalation**: AMiner detects high-entropy and unusual Apache requests pointing to a webshell (`ekmkimzkps-1642996700.9285.php`), followed by successful `sudo` to root and UID changes, indicating full system compromise.

### Affected assets & IOCs
- **Hosts**:  
  - 10.143.0.103, 10.143.2.4, 172.19.128.1, 172.19.130.106, 172.19.130.4, 172.19.130.68, 172.19.131.174, 192.168.231.164, 192.168.231.254, 192.168.231.56, `intranet-server`, `davey-mail`, `cloud-share`
- **Source IPs**:  
  - 10.9.0.10, 172.19.130.4, 172.19.131.174, 192.168.230.122, 192.168.230.4
- **Accounts**:  
  - `www-data`, `jhall`, `root`
- **URLs**:  
  - `https://intranet.smith.russellmitchell.com`, `/wp-content/uploads/2022/01/ekmkimzkps-1642996700.9285.php`

### MITRE ATT&CK
- **TA0043 Reconnaissance**: T1595 Active Scanning (Nmap-like scanning detected by Suricata)
- **T1595.003 Wordlist Scanning**: Unusual Apache access patterns and WPScan user-agent suggest web enumeration
- **T1190 Exploit Public-Facing App / T1505.003 Web Shell**: Webshell uploaded and accessed via `/wp-content/uploads/2022/01/ekmkimzkps-1642996700.9285.php`
- **T1110.002 Password Cracking**: High entropy in Apache logs suggests credential access attempts
- **T1059 Command and Scripting Interpreter**: Webshell used for execution
- **T1548.003 Sudo and Sudo Caching**: Successful `sudo` to root and UID changes indicate privilege escalation

### Recommended response
1. **Isolate affected hosts**: Immediately isolate `172.19.131.174`, `10.143.2.4`, and `intranet-server` from the network to prevent further lateral movement.
2. **Investigate and remove webshell**: Analyze the uploaded webshell (`ekmkimzkps-1642996700.9285.php`) and remove it from the server. Check for any additional malicious files.
3. **Audit user accounts and privileges**: Investigate the `jhall` account, verify its legitimacy, and ensure no unauthorized access or privilege escalation has occurred.
4. **Perform forensic analysis**: Collect logs from affected hosts and sensors (Wazuh, Suricata, AMiner) for deeper analysis and to identify the origin of the attack.
5. **Patch and harden systems**: Ensure all web applications (e.g., WordPress) are up to date and secure, and review firewall and access control rules to prevent future exploitation.

## santos — incident #1 (risk 7.81)
*2022-01-17 11:21 → 11:58 UTC · 60 meta-alerts · 11,218 raw alerts · stages: Reconnaissance → Web discovery → Initial access (webshell upload) → Credential access → Execution (reverse shell) → Privilege escalation*

### Verdict
TRUE POSITIVE (high confidence) - Multiple sensors detected a coordinated attack with clear signs of reconnaissance, web discovery, initial access via webshell, credential access, execution, and privilege escalation.

### What happened
- **01-17 11:21:32 UTC - Reconnaissance**: Multiple SSH connection attempts from `172.21.128.119` to various hosts (`cloud-share`, `mail`, `intranet-server`, `internal-share`) were flagged as insecure scans by Wazuh and AMiner.
- **01-17 11:21:46 UTC - Web discovery**: Nmap-like scanning detected via Suricata and Wazuh, with URLs such as `/nmaplowercheck1642418506` and `/sdk` being probed, indicating active enumeration of web services.
- **01-17 11:58:04 UTC - Execution (reverse shell)**: A high-entropy request was detected by AMiner, suggesting a webshell was uploaded and executed, with a suspicious PHP file (`yvmuplzucm-1642418578.1653.php`) being accessed.

### Affected assets & IOCs
- **Hosts**: `192.168.104.155`, `172.21.128.119`, `intranet-server`, `172.21.128.54`, `172.21.131.50`, `cloud-share`, `internal-share`, `mail`
- **Source IPs**: `172.21.128.119`, `172.21.131.50`
- **Accounts**: `www-data`, `gmorgan`
- **URLs**: `/nmaplowercheck1642418506`, `/sdk`, `/~test`, `/wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php`, `/var/www/intranet.smith.santos.com/.h`

### MITRE ATT&CK
- **TA0043 Reconnaissance**: T1595 Active Scanning (via Nmap-like scanning)
- **T1595.003 Wordlist Scanning**: Probing of URLs and directories
- **T1190 Exploit Public-Facing App / T1505.003 Web Shell**: Webshell uploaded and accessed
- **T1110.002 Password Cracking**: High entropy in request suggests credential access
- **T1059 Command and Scripting Interpreter**: Execution of reverse shell
- **T1548.003 Sudo and Sudo Caching**: Privilege escalation via `sudo` and `su` commands

### Recommended response
1. **Isolate affected hosts**: Immediately isolate `192.168.104.155` and `172.21.128.119` from the network to prevent further lateral movement.
2. **Investigate and remove webshell**: Analyze the suspicious PHP file (`yvmuplzucm-1642418578.1653.php`) and remove it from the server.
3. **Audit user privileges**: Investigate the `gmorgan` account and the use of `sudo` and `su` commands, ensuring no unauthorized access or privilege escalation has occurred.
4. **Change compromised credentials**: Reset passwords for `www-data` and `gmorgan`, and enforce multi-factor authentication where possible.
5. **Review and update firewall rules**: Block traffic from `172.21.128.119` and `172.21.131.50`, and review all SSH and web server access logs for further anomalies.

## santos — incident #2 (risk 1.54)
*2022-01-16 08:23 → 08:27 UTC · 3 meta-alerts · 9 raw alerts · stages: Privilege escalation*

### Verdict
**TRUE POSITIVE** (high confidence) – Unusual PAM activity, followed by a first-time sudo usage by a non-root user, with multiple rare rules firing in a short time window, suggesting a privilege escalation attempt.

### What happened
- **01-16 08:23:08 UTC** – **Privilege escalation attempt initiation**: PAM rule "Login session opened" triggered for user `gmorgan`, with a rare rule firing and multiple detections across the network in the same 10-minute window.
- **01-16 08:24:08 UTC** – **Session closure**: PAM rule "Login session closed" triggered for the same user, with continued rare rule activity and high number of distinct rules firing.
- **01-16 08:27:38 UTC** – **Privilege escalation attempt confirmed**: First-time sudo usage by `gmorgan` to execute `tail /var/log/syslog` as `root`, with a rule never seen before in the network.

### Affected assets & IOCs
- **Hosts**: `mail`
- **Source IPs**: None explicitly listed (local user activity)
- **Accounts**: `gmorgan`, `root`
- **Commands**: `sudo /usr/bin/tail /var/log/syslog`
- **Files**: `/var/log/syslog`
- **Processes**: `sshd`, `sudo`

### MITRE ATT&CK
- **T1548.003** – **Sudo and Sudo Caching**: Exploiting sudo to gain elevated privileges without authentication.

### Recommended response
1. **Investigate the user `gmorgan`** – Check for unauthorized access, account compromise, or lateral movement from this user.
2. **Review sudo usage logs** – Look for other sudo commands executed by `gmorgan` or other users, especially those with elevated privileges.
3. **Audit PAM and SSH logs** – Investigate the login session for anomalies, such as unexpected login times, locations, or authentication methods.
4. **Enable sudo logging and monitoring** – Ensure that all sudo commands are logged and monitored for suspicious activity.
5. **Consider account lockout or revocation** – If `gmorgan` is found to be compromised, lock the account and initiate a forensic investigation.

## santos — incident #3 (risk 1.07)
*2022-01-14 05:24 → 05:24 UTC · 2 meta-alerts · 3 raw alerts · stages: Privilege escalation*

### Verdict
**TRUE POSITIVE** (high confidence) - Unusual authentication failures on a mail server during a short time window, combined with rare rule firings and privilege escalation stage prediction, indicate a potential attack attempt.

### What happened
- **01-14 05:24:18 UTC** - **Initial access attempt**: Failed PAM authentication for user `danny.jarvis` from IP `172.21.131.50` on the mail server, flagged by Wazuh due to a new and rare rule.
- **01-14 05:24:22 UTC** - **Privilege escalation attempt**: A second failed authentication attempt for the same user was recorded in HORDE logs, indicating a possible escalation attempt.
- **01-14 05:24:18–05:24:22 UTC** - **Rule anomaly**: 24 distinct rare rules fired across the network within a 10-minute window, suggesting coordinated or automated attack behavior.

### Affected assets & IOCs
- **Hosts**: `mail`
- **Source IPs**: `172.21.131.50`
- **Accounts**: `danny.jarvis`
- **URLs**: `172.21.129.224` (Horde login endpoint)

### MITRE ATT&CK
- **T1548.003** - Sudo and Sudo Caching: Suggests an attempt to exploit sudo configuration for privilege escalation.

### Recommended response
1. **Isolate the mail server** and investigate the source IP `172.21.131.50` for potential compromise or malicious activity.
2. **Review sudo configurations** on the mail server for any misconfigurations or unauthorized entries.
3. **Audit user accounts** for `danny.jarvis`, including password history, access rights, and login activity.
4. **Correlate with other sensors** (e.g., Suricata, AMiner) to determine if this is part of a larger attack pattern.
5. **Implement multi-factor authentication** for administrative and privileged accounts to mitigate future escalation attempts.

## shaw — incident #1 (risk 5.77)
*2022-01-29 14:38 → 15:21 UTC · 26 meta-alerts · 6,046 raw alerts · stages: Reconnaissance → Web discovery → Credential access → Execution (reverse shell) → Privilege escalation*

### Verdict
**TRUE POSITIVE** (high confidence) - Multiple high-risk alerts from AMiner and Wazuh indicate a coordinated attack involving reconnaissance, web discovery, credential access, execution, and privilege escalation, with clear attacker indicators and rare rule firings.

### What happened
- **01-29 14:38:38 UTC - Reconnaissance**: AMiner detected a rare event type with multiple detections across the network in a short time window, suggesting initial scanning or probing.
- **01-29 14:38:52 UTC - Web discovery**: WPScan was used to probe the web server, leading to multiple 400, 403, and 500 error codes, indicating an attempt to map the web application and find vulnerabilities.
- **01-29 15:20:39 UTC - Execution (reverse shell)**: A high-entropy request was detected, suggesting the exploitation of a vulnerability to execute a reverse shell, followed by privilege escalation via `su` and `sudo` to gain root access.

### Affected assets & IOCs
- **Hosts**: `172.27.183.254`, `192.168.188.179`, `intranet-server`
- **Source IPs**: `172.24.249.224`
- **Accounts**: `www-data`, `gmarsh`, `root`
- **URLs**: 
  - `https://intranet.thomasmurray.shaw.info`
  - `/wp-content/uploads/2022/01/zrhrldsngi-1643467181.254.php`
  - `/.wp-config.php.swp`
  - `/wp-content/uploads/`
  - `/wp-content/themes/go/`
  - `/_mem_bin`
- **Files**: `searchreplacedb2.php`, `wp-config-sample.php~`

### MITRE ATT&CK
- **TA0043 Reconnaissance** / **T1595 Active Scanning**
- **T1595.003 Wordlist Scanning** (WPScan used for web discovery)
- **T1110.002 Password Cracking** (high entropy in requests suggests credential access)
- **T1059 Command and Scripting Interpreter** (execution of reverse shell)
- **T1548.003 Sudo and Sudo Caching** (privilege escalation via `su` and `sudo`)

### Recommended response
1. **Isolate the affected host (`192.168.188.179`) and `intranet-server`** to prevent further lateral movement and data exfiltration.
2. **Investigate the source IP (`172.24.249.224`) and block it at the network perimeter** to prevent reconnection.
3. **Perform a full forensic analysis of the compromised systems**, focusing on the `/var/www/intranet.thomasmurray.shaw.info/wp-content/uploads/2022/01/` directory and any uploaded files.
4. **Reset all compromised user credentials**, including `gmarsh` and `root`, and enforce multi-factor authentication (MFA) for administrative accounts.
5. **Patch the WordPress instance and review web server logs** for any other suspicious activity or potential vulnerabilities exploited.

## wardbeck — incident #1 (risk 5.94)
*2022-01-23 12:11 → 12:55 UTC · 40 meta-alerts · 6,197 raw alerts · stages: Reconnaissance → Web discovery → Credential access → Privilege escalation*

### Verdict
TRUE POSITIVE (high confidence) - Multiple sensors detect coordinated reconnaissance, web discovery, credential access, and privilege escalation activities, including WPScan and sudo exploitation.

### What happened
- **01-23 12:11:01 UTC** - **Reconnaissance**: Multiple rare and never-before-seen rules trigger across the network, including SSH connection attempts and Nmap user-agent detection from IP `10.132.56.81`.
- **01-23 12:11:29 UTC** - **Web discovery**: WPScan tool is detected probing the web server at `intranet.hurstwong.wardbeck.info`, attempting to access WordPress directories and files.
- **01-23 12:55:01 UTC** - **Privilege escalation**: A user (`blord`) successfully escalates privileges using `su` and `sudo` to access the `/etc/shadow` file, indicating potential access to system credentials.

### Affected assets & IOCs
- **Hosts**: `172.21.241.88`, `intranet-server`, `mail`, `10.132.56.81`, `10.132.56.171`
- **Source IPs**: `10.132.56.81`, `192.168.96.3`
- **Accounts**: `www-data`, `blord`, `root`
- **URLs**: 
  - `https://intranet.hurstwong.wardbeck.info`
  - `/wp-content/uploads/`
  - `/wp-login.php`
  - `/wp-content/backup-db/`
  - `/var/www/intranet.hurstwong.wardbeck.info/wp-content/uploads/2022/01/`
- **Tools**: WPScan, Nmap, sudo exploitation

### MITRE ATT&CK
- **TA0043 Reconnaissance** / **T1595 Active Scanning** – Nmap user-agent detection and WPScan scanning.
- **T1595.003 Wordlist Scanning** – WPScan probing WordPress directories.
- **T1110.002 Password Cracking** – Indications of credential access via sudo and su.
- **T1548.003 Sudo and Sudo Caching** – Successful sudo execution to access root privileges.

### Recommended response
1. **Isolate affected hosts** (`172.21.241.88`, `intranet-server`, `10.132.56.81`) and investigate the source IP `10.132.56.81` for compromise.
2. **Investigate the `blord` account** for unauthorized access and ensure no credentials were leaked or misused.
3. **Review sudo and su configurations** on affected hosts to ensure proper access controls and disable unnecessary privileges.
4. **Block the source IP `10.132.56.81`** and investigate its origin to prevent further attacks.
5. **Perform a full forensic analysis** of the affected hosts and logs to determine the full scope of the breach and any data exfiltration.

## wheeler — incident #1 (risk 5.94)
*2022-01-30 07:39 → 07:56 UTC · 59 meta-alerts · 430,711 raw alerts · stages: Reconnaissance → Web discovery → Initial access (webshell upload)*

### Verdict
**TRUE POSITIVE** (high confidence) - Multiple sensors (Wazuh, Suricata, AMiner) detected coordinated reconnaissance, web discovery, and initial access (webshell upload) activities with rare rules, high entropy, and Nmap signatures.

### What happened
- **01-30 07:39:03 UTC - Reconnaissance**: Multiple hosts (e.g., `webserver`, `cloud-share`, `internal-share`) reported SSH connection attempts from `10.38.243.125` and `172.27.181.218`, flagged as insecure scans by Wazuh and AMiner.
- **01-30 07:39:10 UTC - Web discovery**: Apache logs showed multiple 400 and 403 errors, and attempts to access forbidden files (e.g., `/var/www/html/`, `/.hta`, `/.bashrc`) from `10.38.243.125`, indicating directory enumeration and use of common web attack patterns.
- **01-30 07:56:52 UTC - Initial access (webshell upload)**: A high-entropy request was detected attempting to access a `.php` file with suspicious query parameters, suggesting a potential webshell upload.

### Affected assets & IOCs
- **Hosts**: `10.38.243.24`, `192.168.2.114`, `webserver`, `cloud-share`, `internal-share`, `intranet-server`
- **Source IPs**: `10.38.243.125`, `172.27.181.218`
- **URLs**: `/`, `/.hta`, `/.bashrc`, `/_mem_bin`, `/wp-content/uploads/2022/01/blupxljcmk-1643529407.9648.php`
- **Indicators**: Nmap user-agent strings, high entropy in request lines, multiple 400/403 errors, and failed directory index access.

### MITRE ATT&CK
- **TA0043 - Reconnaissance**: T1595 Active Scanning (SSH scans, web server probing)
- **T1595.003 - Web discovery**: Wordlist Scanning (directory enumeration, forbidden file access)
- **T1190 - Initial access**: Exploit Public-Facing App (webshell upload attempt)

### Recommended response
1. **Isolate affected hosts**: Immediately isolate `192.168.2.114`, `10.38.243.24`, and any other hosts showing signs of compromise to prevent further lateral movement.
2. **Investigate the source IPs**: Investigate `10.38.243.125` and `172.27.181.218` to determine if they are legitimate or compromised systems.
3. **Analyze the webshell**: Investigate the `.php` file at `/wp-content/uploads/2022/01/blupxljcmk-1643529407.9648.php` for signs of malicious activity or persistence.
4. **Review web server logs**: Examine Apache logs for additional suspicious activity, especially around the time of the webshell upload.
5. **Patch and harden web applications**: Ensure that WordPress and other web applications are up to date and configured securely to prevent exploitation.

## wheeler — incident #2 (risk 3.43)
*2022-01-30 17:51 → 17:52 UTC · 13 meta-alerts · 36 raw alerts · stages: Execution (reverse shell) → Privilege escalation*

### Verdict
**TRUE POSITIVE** (high confidence) - Multiple rare and high-risk alerts from AMiner and Wazuh indicate a privilege escalation and reverse shell attempt, with evidence of sudo exploitation and unusual audit log entries.

### What happened
- **01-30 17:51:41 UTC** - **Execution (reverse shell)** - AMiner detected high entropy in an Apache access log, suggesting a potential reverse shell attempt via a malicious PHP file (`blupxljcmk-1643529407.9648.php`).
- **01-30 17:51:52 UTC** - **Privilege escalation** - Wazuh detected a successful `su` command by user `www-data` to gain access as `kford`, followed by audit log anomalies indicating a new user session and credential acquisition.
- **01-30 17:52:10 UTC** - **Privilege escalation** - `kford` executed `sudo` to gain root access and read `/etc/shadow`, a highly sensitive file, indicating a successful privilege escalation.

### Affected assets & IOCs
- **Hosts**: `192.168.2.114`, `intranet-server`
- **Source IPs**: None explicitly listed, but the attack may originate from an external IP (`10.38.243.125`) based on the Apache log.
- **Accounts**: `www-data`, `kford`, `root`
- **URLs**: `/wp-content/uploads/2022/01/blupxljcmk-1643529407.9648.php`
- **Files**: `/etc/shadow`
- **Commands**: `sudo`, `su`, `/bin/cat /etc/shadow`

### MITRE ATT&CK
- **T1059** - Command and Scripting Interpreter (used in the reverse shell attempt)
- **T1548.003** - Sudo and Sudo Caching (exploited to gain root access)

### Recommended response
1. **Isolate affected hosts** (`192.168.2.114`, `intranet-server`) and perform a full forensic analysis to determine the scope of the breach.
2. **Investigate the source IP** (`10.38.243.125`) and block it at the network level if it is confirmed to be malicious.
3. **Reset compromised user credentials** (`kford`, `www-data`) and enforce multi-factor authentication (MFA) for all administrative accounts.
4. **Review and harden sudo configurations** to prevent unauthorized root access and ensure least privilege is enforced.
5. **Monitor for similar activity** across the network and consider deploying additional detection rules for high-entropy web requests and anomalous sudo usage.

## wilson — incident #1 (risk 7.41)
*2022-02-07 10:59 → 11:50 UTC · 68 meta-alerts · 434,930 raw alerts · stages: Reconnaissance → Web discovery → Credential access → Execution (reverse shell) → Privilege escalation*

### Verdict
**TRUE POSITIVE** (high confidence) - Multiple sensors detect a coordinated attack with rare event types, high entropy in logs, and clear signs of reconnaissance, web discovery, credential access, execution, and privilege escalation.

### What happened
- **02-07 10:59:15 UTC - Reconnaissance**: Multiple hosts (e.g., `webserver`, `mail`, `intranet-server`) detect SSH connection attempts from `10.182.193.78` on unusual ports, flagged as insecure scans.
- **02-07 11:48:08 UTC - Execution (reverse shell)**: A high-entropy GET request to a suspicious PHP file (`/wp-content/uploads/2022/02/zpinqklqgo-1644232829.6164.php`) is detected, suggesting a reverse shell attempt.
- **02-07 11:48:18 UTC - Privilege escalation**: `jwilkinson` successfully escalates privileges using `su` and `sudo`, with logs indicating access to `/etc/passwd` as root.

### Affected assets & IOCs
- **Hosts**: `10.182.194.5`, `172.26.243.167`, `intranet-server`, `webserver`, `mail`, `cloud-share`
- **Source IPs**: `10.182.193.78`, `192.168.226.71`, `10.182.193.181`
- **Accounts**: `www-data`, `jwilkinson`, `root`
- **URLs**: `/wp-content/uploads/2022/02/zpinqklqgo-1644232829.6164.php`, `/.history`, `/_mem_bin`, `/HNAP1`, `/nmaplowercheck1644231573`, `/sdk`

### MITRE ATT&CK
- **TA0043 Reconnaissance** / **T1595 Active Scanning** (SSH scans, Nmap user-agent)
- **T1595.003 Wordlist Scanning** (multiple web directory attempts)
- **T1110.002 Password Cracking** (high entropy in request parameters)
- **T1059 Command and Scripting Interpreter** (reverse shell attempt)
- **T1548.003 Sudo and Sudo Caching** (successful `sudo` and `su` to root)

### Recommended response
1. **Isolate affected hosts** (`10.182.194.5`, `172.26.243.167`, `intranet-server`) and investigate the origin of the attack.
2. **Investigate the user `jwilkinson`** and audit all sudo/su activity on the affected systems.
3. **Block the source IPs** (`10.182.193.78`, `192.168.226.71`, `10.182.193.181`) at the firewall or network layer.
4. **Analyze the suspicious PHP file** (`/wp-content/uploads/2022/02/zpinqklqgo-1644232829.6164.php`) for potential reverse shell payloads.
5. **Perform a full network scan** to identify any other compromised systems or lateral movement.
