# Phishing-Analysis-Lab

## Overview
This lab analyzes a suspected phishing email and its URL. The analysis includes DNS resolution, WHOIS/RDAP investigation, HTTP/SSL inspection, VirusTotal checks, and IP threat intelligence.

⚠️ **Safety Disclaimer**  
This lab involved a malicious phishing URL hosted on Weebly. All sensitive information (live URLs, IP addresses, email addresses, and attachments) has been redacted in this public repository. Do **not** attempt to access, click, or execute any artifacts from this repo. Full raw indicators of compromise (IOCs) are stored privately and are available only on request for verified employers or instructors.

## Tools Used
- PowerShell (DNS lookup, HTTP header checks)
- VirusTotal
- AbuseIPDB
- whois.exe
- URLScan.io (not available for this URL)

## Folder Contents
- `email1.txt`:The raw phishing email analyzed in this lab
- `notes.txt`: Visual triage and initial observations of the phishing email
- `url_analysis.txt`: Full structured analysis of the phishing URL, including final verdict
- `dns_lookup.txt` and `resolved_ips.txt`: PowerShell outputs for resolved IPs
- `ipinfo.json`: Provides hosting and geolocation information for the resolved IP.
- `whois_dates.txt`: Domain registration information (empty for subdomains) 
- `whois_rdap.json`: Blank RDAP/WHOIS data for the subdomain (acknowledged)
- `header_status.txt`: Provides hosting and geolocation information for the resolved IP.
- `screenshots/`: Optional screenshots of VirusTotal, AbuseIPDB, and URLScan.io.
