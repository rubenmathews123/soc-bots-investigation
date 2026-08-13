# SSOC Investigation Report – BOTS v1 Website Compromise Analysis

**Dataset:** Splunk BOTS (Boss of the SOC) v1 - Attack-Only Dataset
**Tools used:** Splunk (SPL), MITRE ATT&CK Framework
**Role simulated:** SOC Analyst investigating a website compromise

## Overview

This project investigates a simulated attack against a corporate web server,
using Splunk's publicly released BOTS v1 training dataset - real network and
application logs (HTTP traffic, IDS alerts, Windows event logs) built
specifically for SOC training.

Using Splunk Search Processing Language (SPL), I worked through this the way
a real analyst would: started with reconnaissance activity, followed it
through an attempted credential attack, and finished by checking whether the
IDS actually caught what happened. Each finding below follows the same
structure - hypothesis, search, evidence, MITRE ATT&CK mapping, and
conclusion.

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

**MITRE ATT&CK mapping:** Reconnaissance - Active Scanning: Vulnerability Scanning ([T1595.002](https://attack.mitre.org/techniques/T1595/002/)) for the scanner identification, and Gather Victim Host Information: Software ([T1592.002](https://attack.mitre.org/techniques/T1592/002/)) for the CMS identification.

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

**MITRE ATT&CK mapping:** Reconnaissance - Active Scanning: Vulnerability Scanning ([T1595.002](https://attack.mitre.org/techniques/T1595/002/))

**Conclusion:** The nearly 12,000 hits on this one endpoint weren't random -
the same Acunetix scanner from Findings 1 and 2 was cycling through
different injection payloads, testing whether this search field was
vulnerable to SQL injection. This is still automated vulnerability
scanning, not confirmed exploitation - there's no evidence the attacker
actually extracted data or gained access, only that they confirmed the
vulnerability's presence.


---

## Finding 5: IDS Detection Coverage Gap

**Question investigated:** Did the IDS (Suricata) detect either of the two attacks found in Findings 1-4?

**Search used:**
```spl
index=botsv1 sourcetype=suricata src_ip="40.80.148.42" OR src_ip="23.22.63.114"
| stats count by src_ip, alert.signature
| sort -count
```

**Evidence found:**
The scanning IP (40.80.148.42) generated 50 distinct named alerts, correctly
identifying nearly everything it did - the Acunetix scan itself, SQL
injection attempts, XSS attempts, and specific CVE exploitation attempts.

The brute-force IP (23.22.63.114) had 3,273 logged events in the same
dataset, but zero matching alert signatures. The IDS saw this traffic but
never flagged it as an attack.

Digging into one alert in detail also revealed the scanner tried more than
just the Joomla/PHP attacks from earlier findings - it also attempted a
null-byte directory traversal against a Tomcat-specific file
(`/WEB-INF/web.xml%00.jsp`), a Java-platform attack, showing the scanner
tests broadly across multiple technology stacks rather than assuming what
the target runs. This attempt returned an HTTP 400 and did not succeed. All
detected alerts, including this one, were logged with `alert.action:
allowed` - meaning Suricata identified the threat but did not block it.

![IDS caught the scanner](https://github.com/rubenmathews123/soc-bots-investigation/blob/main/screenshots/finding_5_ids_scanner_detected.png)

![IDS missed the brute force entirely](https://github.com/rubenmathews123/soc-bots-investigation/blob/main/screenshots/finding_5_ids_silence.png)

**MITRE ATT&CK mapping:**  No additional ATT&CK technique identified in this finding. The underlying brute-force activity analyzed in Finding 3 maps to Credential Access – Brute Force: Password Guessing([T1110.001](https://attack.mitre.org/techniques/T1110/001/)).

**Conclusion:** Signature-based detection caught the loud, tool-based attack
completely but missed the quieter, script-based credential attack entirely.
This is a realistic and important gap - it shows that IDS coverage alone is
not sufficient, and manual log review (like the analysis done in Finding 3)
is still necessary to catch attacks that don't match a known signature.

---


## About This Dataset

BOTS (Boss of the SOC) is a training dataset and blue-team CTF originally created and open-sourced by Splunk, used industry-wide to teach SOC investigation skills using realistic (simulated) attack data.
