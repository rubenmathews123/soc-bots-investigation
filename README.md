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

## Finding 3: Brute Force Attempt Against Admin Login

**Question investigated:** Was there a brute force attempt against the site's login page, and did it succeed?

**Search used:**
```spl
index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" http_method="POST"
| stats count by src_ip, uri_path
| sort -count
```

**Evidence found:**
IP `23.22.63.114` sent 412 POST requests to `/joomla/administrator/index.php`
- a completely different IP from the Acunetix scanner in Findings 1, 2, and
4. The timestamps showed requests landing fractions of a second apart,
which rules out a human typing. The User-Agent confirmed it further:
`Python-urllib/2.7` - an automated script, not a browser.

Checking the responses in detail:
- 411 of the 412 attempts returned an identical result: a 303 redirect
  pointing back to the login page itself (not to an admin dashboard),
  confirming each attempt failed.
- The 1 remaining attempt had no captured response due to a network packet
  capture gap (a `missing_packets_out` flag in the raw event) - its request
  pattern matched the rest of the attack, but the outcome couldn't be
  confirmed either way.
- The submitted login data was visible in plain text in the captured
  traffic, confirming the login form runs over unencrypted HTTP rather than
  HTTPS - meaning any credentials submitted here, real or guessed, were
  exposed in transit.

![Brute force attempt evidence](https://github.com/rubenmathews123/soc-bots-investigation/blob/main/screenshots/finding_3_bruteforce_volume.png)
![Brute force attempt evidence](https://github.com/rubenmathews123/soc-bots-investigation/blob/main/screenshots/finding_3_bruteforce.png)

**MITRE ATT&CK mapping:** Credential Access - Brute Force: Password Guessing ([T1110.001](https://attack.mitre.org/techniques/T1110/001/))

**Conclusion:** A second, separate actor from the Acunetix scanner ran an
automated password-guessing attack against the admin login using a Python
script. 411 of 412 attempts are confirmed failed; the last one is
unconfirmed due to a capture gap but shows the same pattern. This also
exposed that the login form's lack of encryption would have leaked
credentials in transit regardless of whether any guess succeeded.

---

## Finding 4: SQL Injection Testing Against Search Function

**Question investigated:** Why did one endpoint receive nearly 12,000 requests from the scanner - was this just noise, or something specific?

**Search used:**
```spl
index=botsv1 sourcetype="stream:http" src_ip="40.80.148.42" uri_path="/joomla/index.php/component/search/"
| search form_data="*waitfor delay*"
| table _time, form_data
| head 5
```

**Evidence found:**
The scanner wasn't just hammering this page randomly - it was systematically
testing it for SQL injection. Checking the request data, the same Acunetix
headers from Findings 1 and 2 were present, confirming this was the same
scanner, now targeting a different part of the site.

One example payload found in the captured traffic:
`areas[]=JayQrUag'); waitfor delay '0:0:5' --`

This is a known technique called time-based blind SQL injection. The logic:
inject a command telling the database to pause for 5 seconds before
responding. If the site's actual response comes back slow, that proves the
input reached the database layer unprotected - confirming a real
vulnerability exists, even without ever seeing any actual data leak.

The server's response also reflected the exact injected string back in the
redirect Location header, confirming the input wasn't being filtered before being processed.

![SQL injection payload evidence](https://github.com/rubenmathews123/soc-bots-investigation/blob/main/screenshots/finding_4_sqli_payload.png)

**MITRE ATT&CK mapping:** Initial Access - Exploit Public-Facing Application ([T1190](https://attack.mitre.org/techniques/T1190/))

**Conclusion:** The nearly 12,000 hits on this one endpoint weren't random -
the scanner was cycling through different injection payloads, systematically
checking whether this search field was vulnerable to SQL injection. This
moves beyond passive recon (Findings 1-2) into an actual exploitation
attempt against the application itself.


---

## Skills Demonstrated

- Splunk Search Processing Language (SPL): `stats`, `sort`, filtering by field values
- Log analysis across HTTP/network traffic data
- MITRE ATT&CK technique identification and mapping
- Structured incident documentation and evidence-based conclusions

## About This Dataset

BOTS (Boss of the SOC) is a training dataset and blue-team CTF originally created and open-sourced by Splunk, used industry-wide to teach SOC investigation skills using realistic (simulated) attack data.
