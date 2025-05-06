# cybersecurity-projects
CAPSTONE PROJECT
Threat Detection & Incident Response Using
Wireshark, pfSense, and Wazuh
Organization: SoCraTech
Analyst: John Moma
Role: Security Operations Center (SOC) Analyst
Submission Date: 25 April 2025
Table of Contents
Table of Contents ................................................................................................... 2
1 Executive Summary ......................................................................................... 4
2 Project Introduction......................................................................................... 5
2.1 Project Objectives: ................................................................................... 5
2.2 Rationale for the Project: .......................................................................... 5
2.2.1 Importance of the project to the business and the SOC Analyst ......... 5
2.2.2 Tech Tools Stack: ............................................................................... 5
3 Methodology ................................................................................................... 6
4 Phase 1: Network Tra􀆯ic Capture and Analysis (Wireshark) ............................. 8
4.1 Objective: ................................................................................................. 8
4.2 Key Actions: .............................................................................................. 8
4.3 Findings: ................................................................................................... 9
4.3.1 Suspicious DNS Requests: ................................................................. 9
4.3.2 Unusual HTTP Tra􀆯ic: ....................................................................... 10
4.3.3 SSH Access Patterns: ...................................................................... 11
5 Phase 2: Firewall Implementation & Policy Enforcement (pfSense) ................ 12
5.1 Objective: ............................................................................................... 12
5.2 Key Actions: ............................................................................................ 12
5.3 Findings: ................................................................................................. 14
5.4 Remarks: ................................................................................................ 16
6 Phase 3: Security Event Monitoring and and Incident Response (Wazuh) ....... 17
6.1 Objective: ............................................................................................... 17
6.2 Key Actions: ............................................................................................ 17
6.3 Findings: ................................................................................................. 17
6.4 Remarks: ................................................................................................ 20
7 Phase 4: Final Incident Report and Recommendations .................................. 21
7.1 Objective: ............................................................................................... 21
7.2 Executive Summary: ............................................................................... 21
7.3 Technical Report ..................................................................................... 21
7.3.1 Incident overview: ........................................................................... 21
7.4 Security Recommendations ................................................................... 22
7.4.1 Strengthen Authentication Mechanisms .......................................... 22
7.4.2 Harden Network Perimeter .............................................................. 22
7.4.3 Endpoint Hardening ......................................................................... 22
7.4.4 SIEM Optimization ........................................................................... 22
7.4.5 Network Monitoring Enhancements ................................................. 22
7.5 Final SOC Summary for Management...................................................... 23
1 Executive Summary
A three-phase approach was used to conduct a SOC analysis on SoCraTech’s network
using Wireshark, pfSense and Wazuh as tools to detect and respond to its network
anomalies, block malicious tra􀆯ic and investigate potential threats. During the security
event monitoring phase, multiple incidents were identified that posed risk to the
confidentiality, integrity and availability of SoCraTech’s network environment. These
included:
 Suspicious outbound connections potentially linked to malware
 Repeated SSH brute force attempts
 MITRE ATT&CK
 Network vulnerabilities
 Unauthorized privilege escalations on internal endpoints.
As a Security Operations Center (SOC) analyst, I successfully detected and mitigated
these threats using an integrated approach with Wazuh (SIEM), Wireshark (network
capture) and pfSense (firewall). Key remediations involved IP blocking, access control
adjustments and endpoint remediation. This report outlines the incidents and
recommends improvements for proactive defense of SoCraTech’s network.
2 Project Introduction
SoCraTech, a growing technology solutions provider, has noticed an increase in
suspicious network activity, leading to concerns about potential unauthorized access,
malware infections, and insider threats.
As a cybersecurity analyst in the company's Security Operations Center (SOC), your task
is to deploy, monitor, and analyze network security events using Wireshark, pfSense, and
Wazuh to strengthen the organization's cybersecurity posture.
2.1 Project Objectives:
 Deploy and configure Wireshark, pfSense and Wazuh to monitor and analyze
network tra􀆯ic.
 Identify and analyze threats such as malware communication, unauthorized
access and anomalies.
 Implement security policies using pfSense to block malicious tra􀆯ic.
 Perform incident response and document security findings with Wazuh.
2.2 Rationale for the Project:
2.2.1 Importance of the project to the business and the SOC Analyst
 To practice with SOC tools and understand incident detection better.
 Learn to analyze security threats from packet captures, firewall logs, and SIEM
alerts.
 Improve network defense strategies using pfSense firewall rules and SIEM
automation for the organization.
2.2.2 Tech Tools Stack:
 Wireshark
 pfSense
 Wazuh
 Ubuntu VM
 Kali Linux
3 Methodology
The methodology of this project follows a structure approach for deploying, monitoring
and analyzing network security events within SoCraTech’s network infrastructure. The
goal is to detect, respond to, and mitigate potential threats using an array of SIEM tools
including Wireshark, pfSense, Wazuh, Kali Linus and Ubuntu VM. The methodology is
divided into the following phases:
(i) Network tra􀆯ic capture and analysis using Wireshark – the objective is to
monitor and analyze SoCraTech’s network tra􀆯ic for suspicious activities. This
will be accomplished by performing the following tasks:
- Install Wireshark on UbuntuVM inside the corporate network or use
Wireshark on Kali Linux.
- Capture network tra􀆯ic, focusing on HTTP, DNS, and SSH tra􀆯ic.
- Identify suspicious tra􀆯ic patterns, such as unautorized connections or
signs of malware infection (e.g. excessive outbound connections,
beaconing).
The deliverables will include screenshots of packet captures showing
potential threats and a report detailing network anomalies and potential
threats.
(ii) Firewall implementation and policy enforcement using pfSense – the objective
is to set up and use pfSense as a network security appliance to filter, block and
log malicious tra􀆯ic.
This will be accomplished by carrying out the following tasks:
- Install and configure pfSense as a firewall/gateway.
- Implement Intrusion Detection System (IDS)/Intrusion Prevention System
(IPS) (recommended: Snort) rules to detect and block threats.
- Set up Geoblocking to restrict access from high-risk countries.
- Configure firewall rules to prevent unauthorized SSH access from external
sources.
The deliverables will include screenshots of firewall rules and blocked threats
and a report detailing firewall rule e􀆯ectiveness and threat mitigation results.
(iii) Security event monitoring and incident response using Wazuh. The goal is to
deploy Wazuh as a SIEM solution to correlate and analyze logs from di􀆯erent
sources, including Wireshark and pfSense. This objective will be achieved by
undertaking the following tasks:
- Configure Wazuh to aggregate logs from pfSense and endpoint systems.
- Setting up alerts for brute force attacks, privilege escalation attempts, and
malware activity,
- Perform log analysis to investigate security events and identify indicators
of compromise (IoCs).
The deliverables will include screenshot of Wazuh alerting dashboard with
detected threats and a report on incident response findings and mitigation
actions.
(iv) Final Incident report and recommendations. This will summarize the findings,
propose security improvements, and present recommendations and
mitigation measures. This will be accomplished by
- documenting identified security incidents and their impact.
- providing recommendations to improve network security posture and
- presenting the final SOC analysis report to management.
The final deliverables will include and executive summary (overview of security
events and mitigation, a technical report (details of Wireshark, pfSense and
Wazuh findings) and security recommendations (best practices for enhancing
network defense).
4 Phase 1: Network Tra􀆯ic Capture and Analysis
(Wireshark)
4.1 Objective:
The goal of this phase of the project was to monitor and analyze SoCraTech’s internal
network tra􀆯ic using Wireshark to detect suspicious behaviour that could indicate
security threats, such as malware activity or unauthorized access.
4.2 Key Actions:
Wireshark was installed on Kali Linux. To simulate tra􀆯ic from SoCraTech’s network, I will
use pre-captured tra􀆯ic from malware-tra􀆯ic-analysis.net. This site contains network
tra􀆯ic related to malware infections mostly from Windows-based malware. The packet
capture file used from the site is “2025-04-13-twelve-days-of-scans-and-probes-andweb-
tra􀆯ic-hitting-my-web-server.pcap.zip 12.5 MB (12,465,405 bytes)” which has
been analyzed on Wireshark in UbuntuVM to identify suspicious tra􀆯ic patterns.
Figure 1 shows a screenshot of the link for the tra􀆯ic that has been used for the project.
Figure1: Screenshot of the malware-tra􀆯ic-analysis.net site showing the link to the network tra􀆯ic
used for the Wireshark analysis.
Figure 2: Screenshot of captured packets in Wireshark
Several filters were applied to the .pcap data. The tra􀆯ic analysis focused on HTTP, DNS
and SSH tra􀆯ic.
 HTTP analyzed for unauthorized file transfers and possible data exfiltration.
 DNS monitored for connections to suspicious domains (e.g. C2 servers)
 SSH checked for brute force attempts or abnormal login patterns.
Suspicious domains were checked against sites such as www.virustotal.com,
https://otx.alienvault.com and https://www.abuseipdb.com.
4.3 Findings:
4.3.1 Suspicious DNS Requests:
 Anomalous behaviour: Several DNS queries to domains flagged by threat
intelligence associated with known malware phishing attacks were identified.
Examples of such domains included: 196.251.85.238 (from the Netherlands;
Cheapy-Host, associated with malware, suspicious and phishing), 83.222.191.42
(from Romania; SS-Net, associated with botnet activity, malware and phishing
attack), 67.205.131.141 (from the USA; DIGITALOCEAN-ASN, associated with
malware and suspicious activities), 92.55.190.215 (from Kazakhstan; Kar-Tel LLC,
associated with malware, phishing and malicious activity) and many others.

Figure 3: Filtered suspicious domain in packet capture file.
Figure 4: Associated virustotal report for suspicious domain in Fig 3.
 Frequency: There was repetitive DNS querying from domain 193.142.146.136 and
many ICMP requests from the host to the same domain with the destination port
being unreachable. This domain according to virustotal is from Germany
(ColocaTelInc) and is associated with several phishing, malware and malicious
activities.
4.3.2 Unusual HTTP Tra􀆯ic:
 Repeated identical requests to a login-related JavaScript file
(/admin/assets/js/views/login.js) were identified which can be a sign of:
- Automated scanning: attackers often probe admin paths or scripts.
- Reconnaissance: trying to learn how the admin login page works.
- Bypassing of exploiting logic: Trying to look into JS code for vulnerabilities.
 Several http requests with path GET /ckfinder/core/connector/php/connector/php
were identified. This request path could indicate an attacker probing for known
vulnerable endpoints.
 Figure : Screenshot of suspicious activity probing vulnerable endpoints.
 Several requests with the path GET /systembc/password.php HTTP/1.1 were
identified. The path is highly suspicious and potentially indicative of malware
activity, particularly linked to SystemBC malware. SystemBC is a remote access
trojan (RAT) and proxy malware often used in post-exploitation phases of atatcks.
It provides encrypted command-and-control (C2) channels, allowing attackers to
control compromised systems covertly.
Figure 6: Screenshot of suspicious SystemBC malware activity.
4.3.3 SSH Access Patterns:
The pcap file did not contain any SSH data.
4.4 Remarks:
The Wireshark analysis revealed clear signs of suspicious network activity,
particularly involving DNS and HTTP tra􀆯ic, which suggest attempts of
communication with malicious infrastructure and possible data exfiltration.
Immediate action is recommended to contain and remediate these threats.
5 Phase 2: Firewall Implementation & Policy
Enforcement (pfSense)
5.1 Objective:
This phase of the project involves deploying and configuring pfSense as a network firewall
and security appliance for SoCraTech. The objectives are to strengthen SoCraTech’s
network by blocking unauthorized and potentially malicious tra􀆯ic, logging suspicious
activity, preventing attacks using Snort IDS/IPS and GeoIP-based filtering.
5.2 Key Actions:
Snort was installed through pfSense package manager. Snort was used as an Intrusion
Detection System/Intrusion Prevention System (IDS/IPS) and rules were configured to
detect and block threats.
Figure 7: Snort configuration rules to detect and block threats.
To prevent unauthorized SSH access from external sources while still allowing internal or
trusted access, firewall rules were configured to block SSH port 22 from external IP
addresses and allow SSH only from trusted IP addresses or internal networks.
pfBlockerNG-devel was installed in pfSense and configured to block GeoIP addresses
from specific countries including GeoIP Top Spammers, GeoIP Asia and GeoIP Europe as
well as any ransomware from specific sites attributed to LockBit ransomware attacks.
Figure 8: pfBlockerNG rules blocking GeoIP addresses from Top Spammers, Asia and Europe.
Figure 9: Firewall rules configured to block SSH port 22 from some untrusted sites.
pfSense logs were monitored for blocked Ips, brute force attempts and unauthorized
access attempts.
5.3 Findings:
To determine the e􀆯ectiveness of pfBlockerNG-devel to block GeoIP addresses that were
blocked, www.yandex.ru and www.baidu.com representing IP addresses from Russia
and India respectively were run from the Firefox web browser in Ubuntu and it was found
that these websites were inaccessible.
Figure 10: Unsuccessful attempt to access www.yandex.ru as a GeoIP address from Russia to
demonstrate that pfBlockerNG-devel successfully blocked IP addresses from Russia.
Figure 11: Unsuccessful attempt to access www.baidu.com as a GeoIP address from China to
demonstrate that pfBlockerNG-devel successfully blocked IP addresses from China.
pfSense logs that denied connection attempts were reviewed to prove unauthorized SSH
access is being blocked especially with the firewall rules.
Figure 12: pfSense logs to show blocked connection from SSH access attempts and malicious
tra􀆯ic.
Figure 13: Failed attempt to access a blocked LockBit IP address 81.19.135.219
5.4 Remarks:
The findings from this phase of the project show that the firewall rules that were
configured through Snort, pfBlockerNG-devel and blocking of LockBit IP addresses were
successful in strengthening SoCraTech’s network by blocking unauthorized and
potentially malicious tra􀆯ic.
6 Phase 3: Security Event Monitoring and and
Incident Response (Wazuh)
6.1 Objective:
The main objective of this phase of the project was to deploy and configure Wazuh as a
Security Information and Event Management (SIEM) tool to collect, analyze, and correlate
security logs from multiple sources. These included pfSense (firewall logs), Wireshark
(network tra􀆯ic analysis), and various endpoints. The system was also tasked with realtime
alerting for security incidents such as brute force attacks, privilege escalations and
malware activities.
6.2 Key Actions:
Wazuh Manager and agent components were successfully deployed.
Log forwarding from pfSense firewall and endpoints were integrated into Wazuh.
Wireshark PCAP analysis was configured was configured to complement log data with
deep packet inspection.
Alerting rules in Wazuh were customized to detect brute force login attempts, privilege
escalation and malware patterns.
A parallel and modular password brute-forcing tool (medusa) targeting the SSH server for
files containing a list of usernames and common passwords was then deployed (medusa
-h 192.168.1.102 -U ssh-usernames.txt -P top-20-common-SSH-passwords.txt -M ssh)
in Wazuh.
A structured log analysis and threat hunting was then performed to identify anomalies
and potential indicators of compromise (IoCs), correlate alerts with network tra􀆯ic
captured in Wireshark and track suspicious user behaviour and unauthorized file
changes.
6.3 Findings:
From the analysis of the Wazuh dashboard for MITRE attack and Threat Hunting, several
attack methods were detected. There were numerous attempted credential access
through password guessing, SSH and brute force attacks. There were also several Lateral
Movements through SSH and brute force attacks. There was also evidence of persistence
and privilege escalation on valid accounts. Figures 10 (a) and (b) show the screenshots
of the Wazuh MITRE attack and Threat Hunting dashboards respectively.
Figure 14(a): Wazuh dashboard showing various MITRE attacks
Figure 14(b): Wazuh dashboard showing various Threat Hunting attacks.
Further analysis of the attack techniques showed that the Threat Hunting attacks ranged
from attempted login using non-existent user, multiple failed logins in a small period of
time, user missed the password more than once, maximum authentication attempts
exceeded and user login failed.
Figure 15: Wazuh timestamp showing various attack techniques by Threat Hunting.
Figure 16: Screenshot of analysis of a brute force attack showing attack using invalid username
with too many authentication failures.
The Wazuh dashboard analysis also showed several vulnerabilities with severity ranging
from critical to low. The CVE numbers of these vulnerabilities were also captured.
Figure 17: Screenshot of Wazuh dashboard showing vulnerabilities detected by severity.
The findings further showed alerts triggered for unauthorized shell access using elevated
privileges and further investigation revealed script execution from an unknown user
account.
6.4 Remarks:
Wazuh proved to be an e􀆯ective SIEM tool, o􀆯ering deep visibility into both network and
endpoint security events. Through its integration with pfSense and endpoint systems, it
provided actionable alerts which can enable rapid detection and response to security
incidents.
7 Phase 4: Final Incident Report and
Recommendations
7.1 Objective:
The last phase of this project is aimed at providing a comprehensive summary of the
security incidents identified in SoCraTech’s network during the monitoring phase using
Wireshark, pfSense, and Wazuh. The report includes the analysis of detected events,
their potential impact, and the actionable recommendations to strengthen SoCraTech’s
cybersecurity posture.
7.2 Executive Summary:
A three-phase approach was used to conduct a SOC analysis on SoCraTech’s network
using Wireshark, pfSense and Wazuh as tools to detect and respond to its network
anomalies, block malicious tra􀆯ic and investigate potential threats. During the security
event monitoring phase, multiple incidents were identified that posed risk to the
confidentiality, integrity and availability of SoCraTech’s network environment. These
included:
 Suspicious outbound connections potentially linked to malware
 Repeated SSH brute force attempts
 MITRE ATT&CK
 Network vulnerabilities
 Unauthorized privilege escalations on internal endpoints.
As a Security Operations Center (SOC) analyst, I successfully detected and mitigated
these threats using an integrated approach with Wazuh (SIEM), Wireshark (network
capture) and pfSense (firewall). Key remediations involved IP blocking, access control
adjustments and endpoint remediation. This report outlines the incidents and
recommends improvements for proactive defense of SoCraTech’s network.
7.3 Technical Report
7.3.1 Incident overview:
Incident Description Tool used Impact
SSH Brute
Force
Attempted credential access
from unknown user to host
192.168.2.11
Wazuh +
pfSense
Potential
unauthorized access.
Malware-like
network
behaviour
Outbound tra􀆯ic to
blacklisted domain from host
matched malware
signatures.
Wireshark
+ Wazuh
Potential data
exfiltration
Suspicious
DNS requests
DNS queries to flagged
domains and repetitive DNS
queries.
Ubuntu +
Wireshark
Potential phishing
and malware
Unusual HTTP
tra􀆯ic
Requests with paths linked to
malware activity, repeated
identical requests to loginrelated
Java files and
repeated requests with paths
known for attacking
vulnerable endpoints.
Ubuntu +
Wireshark
Attacks to admin
paths and endpoint
vulnerabilities.
7.4 Security Recommendations
7.4.1 Strengthen Authentication Mechanisms
 Implement multi-factor authentication (MFA) on all administrative interfaces.
 Enforce SSH key-based authentication and disable password login.
7.4.2 Harden Network Perimeter
 Tighten firewall rules to limit access to critical ports (e.g. SSH restricted by IP)
 Deploy pfBlockerNG-devel with updated GeoIP and VPN detection.
7.4.3 Endpoint Hardening
 Apply least privilege principle for user accounts.
 Regularly update endpoint software and endpoint patches.
 Enable application whitelisting and restrict PowerShell/Bash Scripting.
7.4.4 SIEM Optimization
 Expand Wazuh log sources (add DNS logs, application logs).
 Fine-tune alert thresholds to reduce false positives.
 Implement automatic remediation playbooks for high-risk alerts.
7.4.5 Network Monitoring Enhancements
 Continue packet capture sampling via Wireshark.
 Add network behaviour analytics (NBA) tools to detect lateral movement and C2.
7.5 Final SOC Summary for Management
The deployed monitoring framework successfully identified and contained multiple
security incidents, demonstrating e􀆯ective detection and response capabilities.
However, persistent threats, internal misuse and malware behaviour highlight the need
for continuous monitoring, user training and enhanced access control policies. With
recommended improvements, the organization will significantly reduce its attack surface
and improve its incident response maturity.
