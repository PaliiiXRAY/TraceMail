"""
Threat Scoring and Forensic Intelligence Engine for SIH26106
Combines authentication ground truth, typosquatting indicators, forensic relay anomalies,
and urgency heuristics into an explainable threat score (0-100) and IoC table.
"""
import re

URGENCY_KEYWORDS = [
    "urgent", "action required", "account suspended", "immediate action",
    "password expired", "verify your identity", "kyc pending", "unauthorized access",
    "wire transfer", "confidential request", "swift transfer", "24 hours",
    "tax refund", "gift card", "arrest warrant", "legal notice"
]

class ThreatEngine:
    @staticmethod
    def evaluate_threat(parsed_email: dict, auth_data: dict, domain_data: dict, hops: list) -> dict:
        score = 0
        signals = []
        iocs = []

        # 1. Check Authentication Failures (Weight: Up to 35 points)
        if auth_data.get("dmarc") == "fail":
            score += 25
            signals.append({
                "type": "CRITICAL",
                "category": "Protocol Authentication",
                "title": "DMARC Alignment Failed",
                "detail": "Sending domain explicitly rejected this message. Origin is unauthorized by domain policy."
            })
        if auth_data.get("spf") == "fail":
            score += 15
            signals.append({
                "type": "HIGH",
                "category": "Protocol Authentication",
                "title": "SPF (Sender Policy Framework) Failed",
                "detail": "Sending mail server IP is not listed in the DNS SPF record of the domain."
            })
        if auth_data.get("dkim") == "fail":
            score += 15
            signals.append({
                "type": "HIGH",
                "category": "Protocol Authentication",
                "title": "DKIM Cryptographic Signature Invalid",
                "detail": "Cryptographic signature failed verification; header or body modified in transit."
            })

        # 2. Check Domain Typosquatting / Homoglyph / Spoofing (Weight: Up to 35 points)
        if domain_data.get("is_lookalike"):
            score += 35
            signals.append({
                "type": "CRITICAL",
                "category": "Domain Impersonation",
                "title": f"Lookalike Domain Detected: {domain_data.get('domain')}",
                "detail": f"Domain closely mimics high-value target '{domain_data.get('matched_target')}' (Edit distance: {domain_data.get('edit_distance')})."
            })
            iocs.append({
                "type": "MALICIOUS_DOMAIN",
                "value": domain_data.get("domain"),
                "context": f"Typosquatting {domain_data.get('matched_target')}"
            })
        
        if domain_data.get("display_name_spoof"):
            score += 20
            signals.append({
                "type": "HIGH",
                "category": "Identity Deception",
                "title": "Display Name vs Envelope Sender Mismatch",
                "detail": f"Email display name impersonates '{domain_data.get('spoofed_entity')}', but the actual sender domain is '{domain_data.get('domain')}'."
            })

        # 3. Check Forensic Relay Chain (Weight: Up to 25 points)
        if hops:
            origin_hop = hops[0]
            # If originating hop is in a suspicious host or known offshore bulletproof provider
            if origin_hop.get("is_suspicious_host"):
                score += 20
                signals.append({
                    "type": "HIGH",
                    "category": "Infrastructure Forensics",
                    "title": f"Suspicious Originating Infrastructure ({origin_hop.get('country')})",
                    "detail": f"Origin IP {origin_hop.get('ip')} traced to bulletproof/proxy hosting: {origin_hop.get('org')} ({origin_hop.get('asn')})."
                })
                iocs.append({
                    "type": "SUSPICIOUS_IP",
                    "value": origin_hop.get("ip"),
                    "context": f"Originating MTA - {origin_hop.get('org')} ({origin_hop.get('country')})"
                })

        # 4. Check Content Urgency & Social Engineering (Weight: Up to 15 points)
        body_lower = (parsed_email.get("subject", "") + " " + parsed_email.get("body_text", "")).lower()
        matched_urgency = [k for k in URGENCY_KEYWORDS if k in body_lower]
        if matched_urgency:
            score += 15
            signals.append({
                "type": "MEDIUM",
                "category": "Social Engineering",
                "title": "Artificial Urgency & Coercive Phrasing",
                "detail": f"Detected high-urgency keywords: {', '.join(matched_urgency[:4])}"
            })

        # 5. Check Links & URLs
        links = parsed_email.get("links", [])
        for link in links:
            link_domain = link.get("domain", "")
            # Check if link domain mismatches sender domain or is suspicious
            if domain_data.get("is_lookalike") or any(ext in link_domain for ext in [".tk", ".ru", ".xyz", ".top", ".cc"]):
                score += 10
                iocs.append({
                    "type": "SUSPICIOUS_URL",
                    "value": link.get("url"),
                    "context": f"Phishing landing page / credential harvester on {link_domain}"
                })
                break

        # Normalize score between 0 and 100
        score = min(score, 100)

        # Categorize verdict
        if score >= 75:
            verdict = "CRITICAL THREAT (Phishing / BEC Confirmed)"
            badge_color = "red"
            action = "Block sender, isolate mailbox, and quarantine IP on firewall."
        elif score >= 50:
            verdict = "HIGH RISK (Suspicious Impersonation)"
            badge_color = "orange"
            action = "Warn recipient, strip embedded links, flag for SOC review."
        elif score >= 25:
            verdict = "MEDIUM RISK (Anomalies Detected)"
            badge_color = "yellow"
            action = "Proceed with caution, verify sender through secondary channel."
        else:
            verdict = "LEGITIMATE (Verified Origin)"
            badge_color = "green"
            action = "Message passed standard authentication and domain checks."

        return {
            "threat_score": score,
            "verdict": verdict,
            "badge_color": badge_color,
            "recommended_action": action,
            "signals": signals,
            "iocs": iocs
        }
