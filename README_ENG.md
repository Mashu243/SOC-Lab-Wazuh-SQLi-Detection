# Home SOC Lab: Telemetry Analysis and Detection Engineering in Wazuh SIEM

![SIEM](https://img.shields.io/badge/SIEM-Wazuh-blue?style=for-the-badge)
![Environment](https://img.shields.io/badge/Lab-VMware%20%7C%20Docker-informational?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Ubuntu%20%7C%20Kali%20Linux-blueviolet?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-T1190%20%7C%20T1083%20%7C%20T1059-red?style=for-the-badge)

## 1. Project Objective 
The objective of this project was to design, deploy, and test a **Security Operations Center (SOC)** environment in a laboratory setting. The project reflects the full workflow of a Tier 1 SOC Analyst and a Detection Engineer:
1. Building a log collection architecture from a vulnerable web application (**OWASP Juice Shop**) running in a Docker container.
2. Conducting controlled web attack simulations (**SQL Injection**, **Directory Brute-Force**, **Path Traversal**, **XSS**) from an attacker machine (Kali Linux).
3. Analyzing raw telemetry and identifying Indicators of Compromise (IoCs).
4. Developing custom detection and time-correlation rules in XML for the **Wazuh SIEM** engine, mapped to the **MITRE ATT&CK** framework.

---

## 2. Lab Architecture

The environment was virtualized using the **VMware Workstation** hypervisor and divided into two main segments:

| Component | System / Technology | Role in the environment |
| :--- | :--- | :--- |
| **Wazuh Server (SIEM)** | Ubuntu Server (Docker Compose) | Central log manager (`wazuh-manager`), analytical engine, indexing, and visualization in OpenSearch Dashboards. |
| **Monitored Host & Target** | Kali Linux (`kali-endpoint`) | Host with the Wazuh agent installed, running the attack target – the **OWASP Juice Shop** application (Node.js / SQLite). |

### Telemetry flow:
```text
[Attack from Kali Linux] ──> [Docker Container: OWASP Juice Shop] 
                              │
                              ▼ (Redirect stdout/stderr stream)
                  [/var/log/juiceshop/access.log]
                              │
                              ▼ (Wazuh Agent: localfile syslog)
                  [Wazuh Manager: XML Analysis and Correlation]
                              │
                              ▼ (Wazuh Indexer / OpenSearch)
                  [Alert in SOC Dashboard + MITRE Mapping]
```

---

## 3. Log Pipeline Configuration

To ensure continuous event forwarding from the OWASP Juice Shop application to the Wazuh agent, the container's output stream was configured to redirect to a dedicated log file on the Kali Linux host:

```bash
sudo su -
mkdir -p /var/log/juiceshop
docker logs -f juiceshop >> /var/log/juiceshop/access.log 2>&1 &
```

The Wazuh agent configuration file (`/var/ossec/etc/ossec.conf`) was updated to monitor the newly created file:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/juiceshop/access.log</location>
</localfile>
```

---

## 4. Attack Simulation and IoC Analysis

### Attack vector:
An attempt was made to manipulate the database query in the product search endpoint using a SQL Injection payload:

```bash
curl -s "http://localhost:3000/rest/products/search?q='''%20OR%201=1--" > /dev/null
```

### Raw log analysis (IoC):
The lack of query parameterization on the application side triggered an execution error in the SQLite database engine, which was recorded in the log stream:
```text
Error: SQLITE_ERROR: incomplete input
```

* **Attacker's perspective view (Kali Linux):**  
  ![Terminal Kali - Ataki](wazuh_img/kali_attacks.png)

---

## 5. Detection Engineering

To automate threat detection and distinguish isolated errors from automated scanning, a set of custom rules was deployed in the `/var/ossec/etc/rules/juiceshop_rules.xml` file (tested and verified using the built-in *Ruleset Test* module).

### Implemented detection rules:

```xml
<group name="web,app,juiceshop_detection">

  <!-- 1. SQL INJECTION (Single error and time correlation) -->
  <rule id="100010" level="5">
    <match>SQLITE_ERROR</match>
    <description>Juice Shop: Single SQL query error detected</description>
  </rule>

  <rule id="100011" level="12" frequency="5" timeframe="60">
    <if_matched_sid>100010</if_matched_sid>
    <description>Juice Shop: Multiple SQL errors (automated SQLi attack)</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- 2. DIRECTORY BRUTE-FORCE (Resource scanning - HTTP 404 series) -->
  <rule id="100012" level="3">
    <match> 404 </match>
    <description>Juice Shop: Resource not found (HTTP 404)</description>
  </rule>

  <rule id="100013" level="10" frequency="8" timeframe="30">
    <if_matched_sid>100012</if_matched_sid>
    <description>Juice Shop: Automated directory scanning detected (404 series)</description>
    <mitre>
      <id>T1083</id>
    </mitre>
  </rule>

  <!-- 3. PATH TRAVERSAL (Attempt to escape the root directory) -->
  <rule id="100014" level="11">
    <regex>\.\./|%2e%2e%2f|%2e%2e/</regex>
    <description>Juice Shop: Directory / Path Traversal attack attempt detected</description>
    <mitre>
      <id>T1083</id>
    </mitre>
  </rule>

  <!-- 4. CROSS-SITE SCRIPTING (XSS) -->
  <rule id="100015" level="10">
    <regex>script>|%3Cscript|onerror=|javascript:|alert\(</regex>
    <description>Juice Shop: Cross-Site Scripting (XSS) attack attempt detected</description>
    <mitre>
      <id>T1059.007</id>
    </mitre>
  </rule>

</group>
```

* **Rules view in Wazuh Dashboard:**  
  ![Niestandardowe reguły Wazuh](wazuh_img/custom_rules.png)

* **Validation in the Ruleset Test module:**  
  ![Test reguł](wazuh_img/rules_test.png)

---

## 6. LSASS Credential Dumping (Endpoint Security)

In addition to web attacks, the laboratory was expanded to include attack simulations on Windows endpoints (Windows 10). The focus was on detecting credential dumping from the LSASS (Local Security Authority Subsystem Service) process memory, mapping to the **MITRE ATT&CK T1003.001** technique.
Tests were conducted using the **Atomic Red Team** framework, and events were monitored using **Sysmon**.

### Conducted attacks:
During the tests, LSASS process memory dump simulations were executed using various tools (LoLBins and external tools):

*   **Memory dump using ProcDump (T1003.001-1):**
    ![Zrzut ProcDump](lsass_dump.png)
*   **Memory dump using the comsvcs.dll library (T1003.001-2):**
    ![Zrzut comsvcs.dll](lsass_dump2.png)
*   **Memory dump using direct system calls and API unhooking (T1003.001-3):**
    ![Zrzut syscalls](lsass_dump3.png)

### Visualization in Wazuh Dashboard:
The Wazuh system, relying on Sysmon logs (Event ID 10 - ProcessAccess), successfully identified and categorized the memory dump attempts, specifically when using external tools like ProcDump. The built-in rule with ID `92900`, assigned a critical level of 12, was triggered.

*   **LSASS memory dump detection in the Threat Hunting panel:**
    ![Detekcja LSASS w Wazuh](attacks_lsass.png)

---

## 7. Visualization and Triage in the Dashboard (Threat Hunting)

Events streaming from the agent are continuously correlated and presented in the Wazuh system's *Threat Hunting* module. 

* **Registered alerts in the Discover panel:**  
  ![Alerty Wazuh](wazuh_img/wazuh_logs.png)
  ![Alerty Wazuh2](wazuh_img/wazuh_logs2.png)

* **Analytical summary:**
  * The engine successfully detected SQL injection attempts, classifying them under the **MITRE ATT&CK T1190** (*Exploit Public-Facing Application*) technique.
  * Applying correlation rules based on a time window (`timeframe` and `frequency`) effectively increases the event priority when automated scanning is detected.

---

## 8. Remediation Recommendations 
1. **AppSec:** Implement parameterized queries (*Prepared Statements*) to completely eliminate the SQL Injection vulnerability within the application.
2. **Network/WAF:** Configure a Web Application Firewall (WAF) at the network edge to block character strings characteristic of XSS and Path Traversal attacks.
3. **SIEM / SOAR:** Implement automated *Active Response* rules in Wazuh to block IP addresses generating a series of high-severity incidents.
4. **Endpoint Security (Windows):** Enable the **Credential Guard** feature in Windows, restrict account privileges to standard user levels, and deploy ASR (Attack Surface Reduction) policies blocking access to the LSASS process.

---

## 9. Encountered Issues and Troubleshooting (Conclusions)

During the laboratory deployment and configuration, the following technical challenges were encountered and resolved:

1. **Rule Conflicts (Overly broad Juice Shop detection scope):**
   * *Symptom:* The custom Path Traversal rule (`100014`), not narrowed down to a specific source channel, analyzed every incoming log. When a Windows system log (e.g., from Sysmon) containing a file path (backslashes `\`) appeared, the Wazuh engine interpreted it as a directory attack on the web application, overriding the original notification.
   * *Solution:* The rule was updated and fenced with a condition enforcing matches only in logs containing classic protocol keywords (GET, POST, HTTP), isolating its execution to web traffic.

2. **Silent Blocking of Endpoint Attacks (EDR/Defender):**
   * *Observation:* LoLBin-based attacks (e.g., memory dumping using the built-in `comsvcs.dll` library or direct system calls – T1003.001-2 and T1003.001-3) did not generate the corresponding ProcessAccess logs in Sysmon.
   * *Conclusion:* Modern EDR mechanisms and antivirus software (e.g., Windows Defender running in the background) frequently analyze calls at the OS foundation and terminate the memory dumping process before Sysmon can record the event. The absence of a log does not signify a SIEM error, but rather confirms that Endpoint Protection mechanisms effectively intervened at the source.

3. **XML parser validation errors in Wazuh Dashboard (Error `1113` / `invalid token`):**
   * *Symptom:* The web-based rule editor reported a syntax error when special entities (e.g., `&lt;script`) were used inside `<regex>` tags.
   * *Solution:* Regular expressions were adjusted (replacing less-than signs with universal ending patterns, e.g., `script>`), allowing successful API validation and saving of rules without disrupting the XML tree structure.

4. **Issue with Docker log streaming (background `docker logs`):**
   * *Symptom:* The process launched with the `&` operator and `sudo` hung with a `suspended (tty input)` status because the shell attempted to prompt for a password in the background.
   * *Solution:* Launching a privileged session (`sudo su -`) before initiating the log pipeline eliminated the interactive password prompt issue, allowing stable stream redirection to the `/var/log/juiceshop/access.log` file.

---
## Utilized Skills/Competencies
* **SIEM & Log Management:** Wazuh, OpenSearch Dashboards, raw log analysis.
* **Detection Engineering:** Writing XML rules, handling regular expressions (Regex), event correlation, MITRE ATT&CK mapping.
* **Web Security:** Understanding OWASP Top 10 vectors (SQLi, XSS, Path Traversal, Brute-Force).
* **Endpoint Security:** Windows OS mechanics fundamentals (Sysmon, LSASS, Atomic Red Team).
* **Infrastructure:** Linux, Docker, VMware Workstation, SSH, rule testing via CLI and UI.

---

## 10. Automated Blocking of Suspicious IPs (Python)

The `wazuh_auto_block.py` script was added to the repository. It performs the following:
1. Logs into the Wazuh API.
2. Retrieves alerts.
3. Filters them by `rule.id`, `rule.level`, and time window.
4. Extracts source IP addresses.
5. Triggers an **Active Response** to block the IP (or runs in dry-run mode).

### Quick Start

```bash
export WAZUH_BASE_URL="https://192.168.118.133:55000"
export WAZUH_USERNAME="wazuh-wui"
export WAZUH_PASSWORD="<API_PASSWORD>"

# Dry-run mode (preview only)
python3 wazuh_auto_block.py --no-verify-ssl

# Actual IP blocking
python3 wazuh_auto_block.py --no-verify-ssl --execute-block
```

### Key Parameters

- `--rule-ids` (default: `100011,100013,100014,100015`)
- `--min-level` (default: `10`)
- `--lookback-minutes` (default: `15`)
- `--agent-id` (default: `001`)
- `--block-command` (default: `firewall-drop`)
- `--execute-block` (without this flag, the script operates in dry-run mode)