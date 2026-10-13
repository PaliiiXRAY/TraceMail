# SIH26106 Presentation Slides Content
**Problem Statement Title:** AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform  
**Organization:** All India Council for Technical Education (AICTE)  
**Category:** Software | **Domain:** Cybersecurity & Forensics  
**Platform Name:** AegisForensics  

---

## Slide 1: Title Slide
* **Project Name:** AegisForensics (SIH26106)
* **Tagline:** Deterministic Email Relay Forensics & Multi-Vector Threat Intelligence Platform
* **Theme:** Blockchain & Cybersecurity (AICTE)
* **Team Name:** [Your Team Name]
* **Team Leader & Members:** [List 6 Members + College Roll Numbers]
* **Institute:** [Your College / University Name]

---

## Slide 2: Problem Statement & Real-World Challenges
* **The Core Gap:**
  * Conventional spam filters stop at statistical classification (Bayesian/NLP) and score-based heuristics.
  * Attackers exploit this gap through **Business Email Compromise (BEC)**, **Lookalike/Homoglyph Domains** (e.g., `paypa1-security.com`), **Display-Name Impersonation**, and multi-hop offshore relay infrastructure.
* **Why Traditional Tools Fail:**
  * They flag *what* the email says, but cannot prove *where* it came from or *who* authorized it.
  * Enterprise SOC teams lack automated tools to reconstruct the underlying SMTP transmission chain into actionable legal & network indicators (IoCs).

---

## Slide 3: Proposed Solution & Core Innovation (AegisForensics)
* **Two-Pillar Architecture:**
  1. **Ground-Truth Protocol & Domain Analysis:** Real-time extraction of SPF, DKIM, and DMARC alignment, combined with Levenshtein-distance typosquatting detection against high-value targets.
  2. **Deterministic Infrastructure Forensics:** Chronological parsing of RFC822 `Received:` headers to map the complete route:
     `Threat Origin -> Intermediate Proxy/MTA -> Recipient MX Gateway`.
* **Visual Intelligence:**
  * Real-time spatial mapping with animated geographic flight paths using Leaflet.
  * Autonomous System Number (ASN), ISP, and bulletproof host classification.
  * 1-Click Forensic Dossier export (PDF) formatted for incident responders and CERT-In reporting.

---

## Slide 4: Technical Architecture & Pipeline
```
[Raw Email / .EML Upload]
            │
            ▼
┌──────────────────────────────────────────────────────────────┐
│                  AegisForensics Processing Core              │
├──────────────────────────────┬───────────────────────────────┤
│    Authentication Engine     │      Forensic Tracer Engine   │
│  - SPF / DKIM / DMARC Check  │  - RFC822 'Received:' Parser  │
│  - Cryptographic Sig Audit   │  - RFC1918 Private IP Filter  │
├──────────────────────────────┼───────────────────────────────┤
│      Domain Intelligence     │     Geo-Location & ASN Intel  │
│  - Levenshtein Edit-Distance │  - Hop Coordinates (Lat/Lon)  │
│  - Homoglyph & Display Spoof │  - ISP / Bulletproof Tagging  │
└──────────────────────────────┴───────────────────────────────┘
            │
            ▼
┌──────────────────────────────────────────────────────────────┐
│                     SOC Analyst Dashboard                    │
│  • Visual Flight Path Map (Leaflet) • Threat Verdict Gauge   │
│  • Diagnostic Indicators            • Automated IoC & PDF    │
└──────────────────────────────────────────────────────────────┘
```

---

## Slide 5: Innovation & Unique Selling Proposition (USP)
* **Deterministic Reliability vs "Black Box" AI:**
  * While other teams rely solely on NLP classifiers (which hallucinate and produce false positives), AegisForensics grounds its verdicts in unarguable cryptographic truth (SPF/DMARC) and concrete infrastructure evidence.
* **Infrastructure Attribution (Not Fake Identity Claims):**
  * Accurately unmasks proxy chains, Tor relays, and bulletproof hosting (e.g., Russian/Offshore networks) rather than making unverifiable claims about individual perpetrators.
* **Turnkey SOC Readiness:**
  * Outputs standardized Indicators of Compromise (IoCs) for immediate ingestion into enterprise firewalls (Palo Alto, Fortinet) and SIEM systems (Splunk/Elastic).

---

## Slide 6: Feasibility, Viability & Deployment
* **Zero Overhead / Lightweight Architecture:**
  * Deterministic Python-based parsing runs in under **50 milliseconds** per email.
  * Can be deployed as a cloud API, an on-premise mail gateway plugin (Postfix/Exim/Exchange), or a standalone SOC investigation terminal.
* **Cost & Scalability:**
  * Zero expensive GPU requirements for baseline forensic analysis.
  * Scales horizontally using asynchronous microservices.

---

## Slide 7: Roadmap & Team Capabilities
* **Phase 1 (Current - Hackathon MVP):** RFC822 parsing, hop-by-hop geocoding, DMARC/SPF/DKIM audit, lookalike detection, Leaflet map, PDF incident report.
* **Phase 2 (Next 6 Months):** Direct integration with Microsoft 365 / Google Workspace APIs via OAuth, and automated MISP/STIX threat-feed syndication.
* **Phase 3:** Integration with Indian national cybercrime reporting frameworks (NCRP / CERT-In).
