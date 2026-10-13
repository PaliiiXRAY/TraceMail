"""
Forensic Relay Hop Reconstructor & Geo-Intelligence for SIH26106
Reconstructs SMTP relay paths, maps infrastructure hops, and resolves IP metadata (ASN, Geo).
"""
import re
import requests
import json

# Pre-seeded cache of known IP intelligence for offline reliability and sub-second demo speed
GEO_CACHE = {
    # Bulletproof/Offshore host in St. Petersburg, Russia
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "city": "St. Petersburg",
        "region": "Saint Petersburg",
        "country": "Russia",
        "country_code": "RU",
        "lat": 59.9343,
        "lon": 30.3351,
        "asn": "AS200052",
        "org": "Petersburg Internet Network Ltd (Bulletproof Host)",
        "is_suspicious_host": True
    },
    # Tor exit / relay node in Frankfurt, Germany
    "194.26.29.112": {
        "ip": "194.26.29.112",
        "city": "Frankfurt",
        "region": "Hesse",
        "country": "Germany",
        "country_code": "DE",
        "lat": 50.1109,
        "lon": 8.6821,
        "asn": "AS44592",
        "org": "M247 Europe Ltd (Proxy/Relay Node)",
        "is_suspicious_host": True
    },
    # Intermediate cloud VPS in Amsterdam, Netherlands
    "45.142.214.88": {
        "ip": "45.142.214.88",
        "city": "Amsterdam",
        "region": "North Holland",
        "country": "Netherlands",
        "country_code": "NL",
        "lat": 52.3676,
        "lon": 4.9041,
        "asn": "AS51852",
        "org": "Serverion B.V. Unmanaged VPS",
        "is_suspicious_host": True
    },
    # Compromised residential node in Lagos, Nigeria (419 / BEC origin)
    "102.89.44.18": {
        "ip": "102.89.44.18",
        "city": "Lagos",
        "region": "Lagos State",
        "country": "Nigeria",
        "country_code": "NG",
        "lat": 6.5244,
        "lon": 3.3792,
        "asn": "AS29465",
        "org": "MTN Nigeria Telecoms",
        "is_suspicious_host": True
    },
    # Legitimate Google MX server in Ashburn, Virginia, USA
    "209.85.220.41": {
        "ip": "209.85.220.41",
        "city": "Ashburn",
        "region": "Virginia",
        "country": "United States",
        "country_code": "US",
        "lat": 39.0438,
        "lon": -77.4874,
        "asn": "AS15169",
        "org": "Google LLC (Production MX)",
        "is_suspicious_host": False
    },
    # Legitimate Microsoft Exchange server in Redmond, WA, USA
    "40.92.74.52": {
        "ip": "40.92.74.52",
        "city": "Redmond",
        "region": "Washington",
        "country": "United States",
        "country_code": "US",
        "lat": 47.6740,
        "lon": -122.1215,
        "asn": "AS8075",
        "org": "Microsoft Corporation (O365 Protection)",
        "is_suspicious_host": False
    },
    # Legitimate SBI Gateway in Mumbai, India
    "115.112.240.10": {
        "ip": "115.112.240.10",
        "city": "Mumbai",
        "region": "Maharashtra",
        "country": "India",
        "country_code": "IN",
        "lat": 19.0760,
        "lon": 72.8777,
        "asn": "AS4755",
        "org": "Tata Communications / SBI Core Gateway",
        "is_suspicious_host": False
    }
}

class ForensicsEngine:
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Checks if an IP address is an RFC1918 private/loopback/link-local address."""
        if not ip:
            return True
        return (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("127.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("172.18.") or
            ip.startswith("172.19.") or
            ip.startswith("172.2") or
            ip.startswith("172.30.") or
            ip.startswith("172.31.") or
            ip.startswith("169.254.")
        )

    @staticmethod
    def geolocate_ip(ip: str) -> dict:
        """Resolves IP to Geographic coordinates, ASN, and Organization with cache & live fallback."""
        if ip in GEO_CACHE:
            return GEO_CACHE[ip]

        # Live resolution via ip-api.com
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,as,org", timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    geo_info = {
                        "ip": ip,
                        "city": data.get("city", "Unknown City"),
                        "region": data.get("regionName", ""),
                        "country": data.get("country", "Unknown Country"),
                        "country_code": data.get("countryCode", "XX"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "asn": data.get("as", "Unknown ASN"),
                        "org": data.get("org", "Unknown Host"),
                        "is_suspicious_host": False
                    }
                    GEO_CACHE[ip] = geo_info
                    return geo_info
        except Exception:
            pass

        # Fallback default coordinates
        return {
            "ip": ip,
            "city": "Unknown City",
            "region": "",
            "country": "International Infrastructure",
            "country_code": "UN",
            "lat": 20.0,
            "lon": 0.0,
            "asn": "AS-UNKNOWN",
            "org": "Unassigned / Encrypted Relay",
            "is_suspicious_host": False
        }

    @staticmethod
    def reconstruct_relay_chain(received_headers: list) -> list:
        """
        Parses Received headers from bottom (origin) to top (destination) to map the relay route.
        """
        hops = []
        hop_index = 1

        # Email received headers are added in reverse chronological order:
        # Top-most is the destination mail server (e.g. Gmail / College MX).
        # Bottom-most is the originating sender / client MUA or submission server.
        chronological_headers = list(reversed(received_headers))

        ip_regex = r'\[?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]?'

        for header_str in chronological_headers:
            all_ips = re.findall(ip_regex, header_str)
            public_ips = [ip for ip in all_ips if not ForensicsEngine.is_private_ip(ip)]

            # Extract by server and from server
            from_server = "Client Host"
            by_server = "MTA Relay"

            from_match = re.search(r'from\s+([^\s\(\)]+)', header_str, re.IGNORECASE)
            if from_match:
                from_server = from_match.group(1).strip('[]')

            by_match = re.search(r'by\s+([^\s\(\)]+)', header_str, re.IGNORECASE)
            if by_match:
                by_server = by_match.group(1).strip('[]')

            if public_ips:
                primary_ip = public_ips[0]
                geo_info = ForensicsEngine.geolocate_ip(primary_ip)
                
                # Determine role of hop
                if hop_index == 1:
                    role = "Originating Host / Threat Infrastructure"
                elif hop_index == len(chronological_headers):
                    role = "Recipient Mail Gateway (Destination MX)"
                else:
                    role = "Intermediate SMTP Relay / Proxy"

                hops.append({
                    "hop_number": hop_index,
                    "ip": primary_ip,
                    "from_server": from_server,
                    "by_server": by_server,
                    "role": role,
                    "city": geo_info["city"],
                    "country": geo_info["country"],
                    "country_code": geo_info["country_code"],
                    "lat": geo_info["lat"],
                    "lon": geo_info["lon"],
                    "asn": geo_info["asn"],
                    "org": geo_info["org"],
                    "is_suspicious_host": geo_info.get("is_suspicious_host", False),
                    "raw_snippet": header_str[:120] + "..." if len(header_str) > 120 else header_str
                })
                hop_index += 1

        return hops
