"""
Email Authentication Validator for SIH26106
Extracts and validates SPF, DKIM, and DMARC verification signals from email headers.
"""
import re

class AuthValidator:
    @staticmethod
    def evaluate(auth_results_header: str, headers_raw: dict = None) -> dict:
        """
        Parses Authentication-Results and Received-SPF headers to verify SPF, DKIM, DMARC.
        """
        text = (auth_results_header or "").lower()

        # Check SPF
        spf_status = "none"
        if "spf=pass" in text:
            spf_status = "pass"
        elif "spf=fail" in text or "spf=softfail" in text:
            spf_status = "fail"
        elif "spf=neutral" in text:
            spf_status = "neutral"

        # Check DKIM
        dkim_status = "none"
        if "dkim=pass" in text:
            dkim_status = "pass"
        elif "dkim=fail" in text:
            dkim_status = "fail"
        elif "dkim=neutral" in text:
            dkim_status = "neutral"

        # Check DMARC
        dmarc_status = "none"
        if "dmarc=pass" in text:
            dmarc_status = "pass"
        elif "dmarc=fail" in text:
            dmarc_status = "fail"
        elif "dmarc=none" in text or "dmarc=quarantine" in text:
            dmarc_status = "quarantine"

        # Look for DKIM Signature header presence
        has_dkim_sig = False
        if headers_raw:
            has_dkim_sig = any("dkim-signature" in k.lower() for k in headers_raw.keys())

        # Determine overall protocol trust
        is_spoofed = (spf_status == "fail" and dmarc_status == "fail") or (dmarc_status == "fail")
        
        reasons = []
        if spf_status == "fail":
            reasons.append("Sender Policy Framework (SPF) failed: sending IP is not authorized by domain owner")
        if dkim_status == "fail":
            reasons.append("DKIM cryptographic signature verification failed: message content or headers were tampered with")
        if dmarc_status == "fail":
            reasons.append("DMARC alignment failed: sender domain policy explicitly rejects this message origin")

        return {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "has_dkim_signature": has_dkim_sig,
            "is_spoofed": is_spoofed,
            "reasons": reasons
        }
