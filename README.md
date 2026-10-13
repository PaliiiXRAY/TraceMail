# TraceMail 🛡️✉️
### AI-Powered Email Threat Detection & Infrastructure Forensic Tracing Platform
**Smart India Hackathon (SIH 2024 / Problem ID: SIH26106)**

---

## 📌 Executive Summary

Modern spear-phishing, business email compromise (BEC), and state-sponsored email spoofing attacks manipulate email headers, abuse open mail relays, and exploit visual lookalike domains (homoglyphs) to deceive both legacy email filters and end-users.

**TraceMail** is a lightweight, zero-external-dependency email forensic intelligence suite designed for Security Operations Center (SOC) analysts, CERT teams, and cybersecurity investigators. It decodes raw RFC822 email headers, validates cryptographic email authentication (SPF, DKIM, DMARC), detects typosquatting and homoglyphs, reconstructs the multi-hop SMTP relay chain with interactive geospatial visualization, computes a multi-vector threat risk score (0–100), and exports audit-ready forensic PDF dossiers in one click.

---

## 🌟 Key Capabilities

- **RFC822 Header Decomposition & Reverse Hop Reconstruction**: Parses complex multi-hop `Received:` chains in correct temporal sequence (Originating Mail User Agent $\rightarrow$ Intermediate Relays $\rightarrow$ Border MTA $\rightarrow$ Internal Mail Server).
- **Cryptographic Authentication Verification**:
  - **SPF (Sender Policy Framework)**: Validates IP alignment with sending envelope.
  - **DKIM (DomainKeys Identified Mail)**: Inspects digital signatures, selectors, and body hash status.
  - **DMARC (Domain-based Message Authentication, Reporting & Conformance)**: Computes alignment between Header `From:` and SPF/DKIM domains, checking enforcement policies (`none`, `quarantine`, `reject`).
- **Domain Intelligence & Homoglyph Engine**:
  - Detects lookalike domains (e.g., `micros0ft.com`, `paypa1.com`, `arnazon.com`, Cyrillic `а` vs Latin `a`).
  - Flags newly registered / high-risk top-level domains (TLDs) and disposable email services.
  - Highlights sender display name spoofing (`display_name != envelope_sender`).
- **Interactive Geospatial Hop Visualizer**:
  - Renders IP geographic locations on a dark-matter Leaflet world map with hop numbers, autonomous system numbers (ASN), hosting providers, and delay latencies.
- **Explainable Multi-Vector Threat Scoring (0–100)**:
  - Generates clear, non-black-box verdict ratings: `BENIGN`, `SUSPICIOUS`, `HIGH RISK`, or `MALICIOUS PHISHING / SPOOF`.
  - Pinpoints exact Indicators of Compromise (IoCs) with severity weights.
  - Supplies prescriptive SOC mitigation playbooks and firewall block rules.
- **Instant Forensic PDF Export**:
  - Client-side vector PDF dossier generation for chain-of-custody documentation, incident tickets, and legal evidence handling.

---

## 📂 Project Architecture

```
sih-email-forensics/
├── api/
│   └── index.py            # Vercel serverless gateway wrapper
├── backend/
│   ├── auth_check.py       # SPF / DKIM / DMARC verification engine
│   ├── domain_intel.py     # Homoglyph, typosquatting & domain reputation
│   ├── forensics.py        # Multi-hop SMTP relay chain reconstructor & IP resolver
│   ├── parser.py           # RFC822 / MIME email parser & header extractor
│   ├── samples.py          # Pre-packaged real-world forensic test cases
│   └── threat_engine.py    # Multi-factor threat scoring & IoC aggregator
├── presentation/
│   ├── DEMO_SCRIPT.md      # Live pitch & judge walkthrough script
│   └── SIH_SLIDES.md       # Slide deck content for technical evaluations
├── static/
│   ├── app.js              # Map rendering, UI controllers & jsPDF exporter
│   ├── index.html          # Cyber-intelligence dashboard interface
│   └── style.css           # Glassmorphism, animations & styling
├── app.py                  # Standalone zero-dependency Python HTTP server
├── vercel.json             # Serverless deployment configuration
├── requirements.txt        # Optional Python packages (standard library default)
└── README.md               # Documentation & setup guide
```

---

## 🚀 Quickstart & Local Setup

TraceMail is engineered to run out-of-the-box using the Python standard library with zero external pip dependencies.

### 1. Clone the Repository
```bash
git clone https://github.com/PaliiiXRAY/TraceMail.git
cd TraceMail
```

### 2. Launch the Development Server
```bash
python app.py
```

### 3. Open in Browser
Navigate to:
```
http://localhost:5000
```

---

## 🧪 Built-in Test Cases & Scenarios

TraceMail includes pre-loaded forensic test scenarios accessible directly from the header navigation bar:

1. **PayPal Brand Spoof (Homoglyph Attack)**:
   - Uses `service@paypa1.com` with failing SPF/DKIM and relay originating from an unauthorized bulletproof VPS in Russia.
2. **Executive CEO Impersonation (Display Name Spoof)**:
   - Uses `Sundar Pichai <spichai.exec@fastmail-temp.xyz>` targeting internal employees with wire transfer requests.
3. **Legitimate Google Security Alert (Benign Control)**:
   - Authentic cryptographic headers with passing SPF, DKIM (1024-bit/2048-bit RSA), and strict DMARC alignment.

---

## 🔌 API Reference

### `POST /api/analyze`
Analyzes a raw email header or entire RFC822 message.

**Request Payload:**
```json
{
  "raw_email": "Delivered-To: victim@example.com\nReceived: from ..."
}
```

**Response Payload Structure:**
```json
{
  "email": {
    "subject": "...",
    "from": "...",
    "to": "...",
    "date": "...",
    "message_id": "...",
    "envelope_sender": "...",
    "display_name": "..."
  },
  "auth": {
    "spf": "pass|fail|softfail|none",
    "dkim": "pass|fail|none",
    "dmarc": "pass|fail|none",
    "details": [...]
  },
  "domain": {
    "domain": "...",
    "is_lookalike": true|false,
    "target_brand": "...",
    "tld": "...",
    "is_high_risk_tld": true|false
  },
  "hops": [
    {
      "hop_number": 1,
      "role": "ORIGINATING_MUA",
      "ip": "185.220.101.5",
      "city": "Moscow",
      "country": "Russia",
      "asn": "AS49981",
      "org": "WorldStream B.V.",
      "is_suspicious_host": true
    }
  ],
  "threat": {
    "threat_score": 92,
    "verdict": "MALICIOUS PHISHING / SPOOF",
    "recommended_action": "QUARANTINE_AND_BLOCK",
    "iocs": [...],
    "reasons": [...]
  }
}
```

### `GET /api/samples`
Returns all pre-configured forensic sample metadata.

### `GET /api/sample/<id>`
Retrieves the raw RFC822 content of a specific test scenario.

### `GET /api/health`
Returns service status, uptime, and engine capabilities.

---

## 🏆 SIH Team & Contribution

- **Repository**: [https://github.com/PaliiiXRAY/TraceMail](https://github.com/PaliiiXRAY/TraceMail)
- **Built for**: Smart India Hackathon (SIH26106)
- **Maintainer**: Pallabi Pandi ([@PaliiiXRAY](https://github.com/PaliiiXRAY))

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
