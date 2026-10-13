# AegisForensics 2-Minute Stage Pitch & Judge Defense Script

This is your exact word-for-word script for presenting the live demo in front of college evaluators and professors.

---

### Part 1: The Pitch & Live Demo (Total: 2 Minutes)

#### Step 1: The Hook (0:00 - 0:30)
> *"Respected judges, every day millions of Indian citizens and enterprises receive phishing emails. Existing spam filters look only at the text content. If an attacker uses a lookalike domain or impersonates a CEO with urgent language, ordinary AI models often let it pass.  
> 
> For **SIH26106**, we built **AegisForensics**—a platform that doesn't just ask **what** the email says, but deterministically proves **where it originated and what infrastructure carried it**."*

#### Step 2: The Live Demonstration (0:30 - 1:30)
*(Click the top preset button: **"🚨 PayPal Phishing"**)*

> *"Notice what just happened in under 100 milliseconds:
> 
> 1. **Authentication Ground Truth:** The system instantly detected that SPF and DMARC have **FAILED**. The sender domain is unauthorized.
> 2. **Lookalike Domain Detection:** Our algorithm detected that the domain `paypa1-security.com` is a typosquatting homoglyph mimicking the authentic `paypal.com`.
> 3. **Infrastructure Forensics:** Look at the interactive world map below. We parsed the chronological `Received:` headers. The attack did not come from California. It originated from a known bulletproof VPS in **St. Petersburg, Russia (Hop #1)**, routed through an unmanaged proxy in **Frankfurt, Germany (Hop #2)**, before arriving at the recipient's mail gateway.
> 4. **Threat Score:** Our engine calculated a **100% Critical Threat Verdict**."*

#### Step 3: The Actionable Deliverable (1:30 - 2:00)
*(Click the **"Export Forensic Report (PDF)"** button at the top right)*

> *"Most importantly, an analyst or law enforcement officer can click **Export Forensic Report** to immediately generate an incident dossier with standardized Indicators of Compromise (IoCs) like malicious IPs, ASNs, and domains ready to push to firewalls and CERT-In.  
> 
> We also tested this against legitimate enterprise emails—*(Click 'Google Cloud Notice')*—where it scores 0% and verifies all cryptographic signatures with zero false positives. Thank you, we are now open for questions!"*

---

### Part 2: Defense Against Tough Judge Questions

#### Q1: "Can't attackers forge the 'Received' headers?"
* **Your Winning Answer:**
  > *"Excellent question, sir. An attacker can only forge the headers **before** the email leaves their own server. However, once the email hits the first public, untrusted MTA relay and our receiving mail gateway, those intermediate and destination `Received:` headers are cryptographically timestamped and appended by trusted mail transfer agents. Our algorithm traces backwards from the verified recipient gateway down to the boundary of the first untrusted external hop. That is why we focus on infrastructure indicators rather than claiming to know the physical person."*

#### Q2: "Why didn't you just use an LLM or ChatGPT to classify the email?"
* **Your Winning Answer:**
  > *"LLMs are great for NLP, but in cybersecurity, explainability and deterministic truth are critical. If an LLM hallucinates, an innocent email gets blocked or a cyber attack slips through. AegisForensics uses cryptographic standards—SPF, DKIM signatures, and DMARC DNS policies—which are mathematical ground truth, not probabilistic guesses. We use ML where it counts: for typosquatting distance and NLP urgency analysis."*

#### Q3: "What if the attacker used a VPN or Tor?"
* **Your Winning Answer:**
  > *"That is precisely what our forensic layer reveals. Notice how in our demo, Hop #1 was flagged as 'Petersburg Internet Network Ltd' and Hop #2 as 'M247 Proxy Node'. We surface the ASN and hosting provider type. When a corporate recipient sees that an email claiming to be from 'State Bank of India' originated from a foreign bulletproof host or proxy ASN, the attack is immediately neutralized regardless of the VPN."*
