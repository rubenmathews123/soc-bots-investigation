# SOC Investigation Report - Simulated APT Attack Analysis

**Dataset:** Splunk BOTS (Boss of the SOC) v1 - Attack-Only Dataset
**Tools used:** Splunk (SPL), MITRE ATT&CK Framework
**Role simulated:** SOC Analyst investigating a website compromise

## Overview

This project uses Splunk's publicly released BOTS v1 training dataset to investigate a simulated advanced persistent threat (APT) attack against a corporate web server. The dataset contains real network and application logs (HTTP traffic, IDS alerts, Windows event logs) generated from an actual attack simulation, used industry-wide for blue-team SOC training.

Using Splunk Search Processing Language (SPL), I investigated the incident from initial reconnaissance through to [exploitation/persistence - update as you complete more findings], documenting each step as a real analyst would: hypothesis, search, evidence, technique mapping, and conclusion.

## Scenario

A corporate website was reported defaced. As the investigating analyst, the goal was to reconstruct the attack timeline using only the available logs - identifying the attacker's reconnaissance activity, the tools and techniques used, and how the compromise occurred.

---

## Finding 1: Reconnaissance Scan Identified

**Question investigated:** Which IP scanned the site for vulnerabilities before the attack?

**Search used:**
```spl
index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70"
| stats count by src_ip
| sort -count
```

**Evidence found:**
One IP, `40.80.148.42`, made 17,546 requests to the server - over 12 times
more than the next busiest IP. No normal visitor generates that kind of
traffic, so this had to be some kind of automated scan.

![Reconnaissance scan results](https://github.com/rubenmathews123/soc-bots-investigation/blob/main/screenshots/finding_1_recon_scan.png)

**MITRE ATT&CK mapping:** Reconnaissance - Active Scanning ([T1595](https://attack.mitre.org/techniques/T1595/))

**Conclusion:** Someone scanned the site before the actual attack happened -
classic recon behavior. This IP (`40.80.148.42`) became the main thing I
tracked for the rest of the investigation.

---
## Finding 2: Attacker Reconnaissance - Tool and Target Identified

**Question investigated:** What tool did the attacker use to scan the site, and what software was the site running?

**Search used:**
```spl
index=botsv1 sourcetype="stream:http" src_ip="40.80.148.42"
| table _time, uri_path, src_headers
```

**Evidence found:**
Two things showed up in the same request. First, a custom header -
`Acunetix-Product: WVS/10.0 (Acunetix Web Vulnerability Scanner - Free
Edition)` - gave away the exact tool. Second, the request path itself,
`/joomla/index.php`, showed the site is running Joomla.

Worth noting: the User-Agent on this same request was faked to look like a
normal Chrome browser. The Acunetix-specific headers weren't disguised
though, so the tool gave itself away anyway.

![Scanner and CMS identification](https://github.com/rubenmathews123/soc-bots-investigation/blob/main/screenshots/finding_2_scanner_headers.png)

**MITRE ATT&CK mapping:** Reconnaissance - Active Scanning: Vulnerability Scanning ([T1595.002](https://attack.mitre.org/techniques/T1595/002/))

**Conclusion:** The attacker used Acunetix's free scanner to fingerprint the
site and confirmed it's running Joomla - likely the next step before looking
up known Joomla vulnerabilities to actually exploit.

---


---

## Finding 3: [Target Reconnaissance - CMS Identification]
*Not yet started*

---

## Finding 4: [Credential Access - Brute Force Attempt]
*Not yet started*

---

## Finding 5: [Payload Delivery]
*Not yet started*

---

## Skills Demonstrated

- Splunk Search Processing Language (SPL): `stats`, `sort`, filtering by field values
- Log analysis across HTTP/network traffic data
- MITRE ATT&CK technique identification and mapping
- Structured incident documentation and evidence-based conclusions

## About This Dataset

BOTS (Boss of the SOC) is a training dataset and blue-team CTF originally created and open-sourced by Splunk, used industry-wide to teach SOC investigation skills using realistic (simulated) attack data.
