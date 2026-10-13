"""
Domain Intelligence and Typosquatting Detector for SIH26106
Identifies homoglyphs, lookalike domains, display name spoofing, and brand impersonation.
"""

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


HIGH_VALUE_TARGETS = [
    "paypal.com",
    "microsoft.com",
    "office365.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "sbi.co.in",
    "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "rbi.org.in",
    "incometax.gov.in",
    "gov.in",
    "nic.in",
    "netflix.com",
    "meta.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "dropbox.com"
]

class DomainIntel:
    @staticmethod
    def analyze_domain(domain: str, display_name: str = "") -> dict:
        """
        Analyzes a sender domain for lookalikes, typosquatting, homoglyphs, and impersonation.
        """
        domain = (domain or "").lower().strip()
        display_name = (display_name or "").strip()

        # Check exact legitimate match
        is_known_brand_exact = domain in HIGH_VALUE_TARGETS

        matched_target = None
        min_dist = 999
        is_lookalike = False
        lookalike_ratio = 0.0

        for target in HIGH_VALUE_TARGETS:
            # Strip TLD for root comparison
            target_name = target.split(".")[0]
            domain_name = domain.split(".")[0] if "." in domain else domain

            dist = levenshtein_distance(domain_name, target_name)
            
            # If domain isn't an exact match, but edit distance is 1 or 2, it's a lookalike!
            if domain != target and 0 < dist <= 2 and abs(len(domain_name) - len(target_name)) <= 2:
                if dist < min_dist:
                    min_dist = dist
                    matched_target = target
                    is_lookalike = True

        # Check for numeric or common substitution tricks (e.g. 0 for o, 1 for l)
        homoglyph_detected = False
        suspicious_subs = {'0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b', 'vv': 'w'}
        normalized_name = domain
        for char, repl in suspicious_subs.items():
            if char in normalized_name:
                for target in HIGH_VALUE_TARGETS:
                    target_root = target.split(".")[0]
                    if target_root in normalized_name:
                        homoglyph_detected = True
                        matched_target = target
                        is_lookalike = True

        # Display Name Mismatch (Display name says "State Bank of India" but domain is "mail-vps99.ru")
        display_name_spoof = False
        spoofed_entity = ""
        for target in HIGH_VALUE_TARGETS:
            brand_name = target.split(".")[0]
            # If the brand name appears in display name but domain does NOT contain it
            if brand_name in display_name.lower() and brand_name not in domain:
                display_name_spoof = True
                spoofed_entity = brand_name.upper()

        return {
            "domain": domain,
            "is_lookalike": is_lookalike,
            "matched_target": matched_target,
            "edit_distance": min_dist if is_lookalike else 0,
            "homoglyph_detected": homoglyph_detected,
            "display_name_spoof": display_name_spoof,
            "spoofed_entity": spoofed_entity,
            "is_known_brand_exact": is_known_brand_exact
        }
