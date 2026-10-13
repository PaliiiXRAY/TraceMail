"""
AegisForensics Core Server (SIH26106)
Zero-dependency HTTP Server exposing REST API and serving SOC Dashboard.
"""
import os
import sys
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.parser import EmailParser
from backend.auth_check import AuthValidator
from backend.domain_intel import DomainIntel
from backend.forensics import ForensicsEngine
from backend.threat_engine import ThreatEngine
from backend.samples import SAMPLES

PORT = 5000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

class AegisRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Route 1: Root Dashboard
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
                self.wfile.write(f.read())
            return

        # Route 2: Static Assets
        if path.startswith("/static/"):
            file_name = path.replace("/static/", "")
            file_path = os.path.join(STATIC_DIR, file_name)
            if os.path.isfile(file_path):
                self.send_response(200)
                if file_name.endswith(".css"):
                    self.send_header("Content-Type", "text/css")
                elif file_name.endswith(".js"):
                    self.send_header("Content-Type", "application/javascript")
                elif file_name.endswith(".html"):
                    self.send_header("Content-Type", "text/html")
                self.end_headers()
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
                return

        # Route 3: API Samples List
        if path == "/api/samples":
            sample_list = [
                {"id": s["id"], "title": s["title"], "description": s["description"]}
                for s in SAMPLES.values()
            ]
            self.send_json_response({"samples": sample_list})
            return

        # Route 4: API Get Specific Sample
        if path.startswith("/api/sample/"):
            sample_id = path.replace("/api/sample/", "").strip()
            if sample_id in SAMPLES:
                self.send_json_response(SAMPLES[sample_id])
            else:
                self.send_json_response({"error": "Sample not found"}, status=404)
            return

        self.send_error(404, "Endpoint not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/analyze":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                post_body = self.rfile.read(content_length).decode("utf-8")
                req_data = json.loads(post_body)
                raw_email = req_data.get("raw_email", "").strip()

                if not raw_email:
                    self.send_json_response({"error": "Empty email content provided"}, status=400)
                    return

                # Pipeline Step 1: Parse RFC822 Email
                parsed_email = EmailParser.parse_raw(raw_email)

                # Pipeline Step 2: Validate Authentication (SPF, DKIM, DMARC)
                auth_data = AuthValidator.evaluate(parsed_email.get("auth_results", ""))

                # Pipeline Step 3: Domain & Typosquatting Analysis
                domain_data = DomainIntel.analyze_domain(
                    parsed_email.get("sender_domain", ""),
                    parsed_email.get("display_name", "")
                )

                # Pipeline Step 4: Reconstruct SMTP Relay Forensics & Geolocation
                hops = ForensicsEngine.reconstruct_relay_chain(parsed_email.get("received_headers", []))

                # Pipeline Step 5: Threat Scoring & IoCs
                threat_data = ThreatEngine.evaluate_threat(parsed_email, auth_data, domain_data, hops)

                # Assemble Full Response Payload
                response_payload = {
                    "email": {
                        "subject": parsed_email.get("subject"),
                        "display_name": parsed_email.get("display_name"),
                        "envelope_sender": parsed_email.get("envelope_sender"),
                        "sender_domain": parsed_email.get("sender_domain"),
                        "date": parsed_email.get("date"),
                        "links_count": len(parsed_email.get("links", []))
                    },
                    "auth": auth_data,
                    "domain": domain_data,
                    "hops": hops,
                    "threat": threat_data
                }

                self.send_json_response(response_payload)

            except Exception as e:
                self.send_json_response({"error": str(e)}, status=500)
            return

        self.send_error(404, "Endpoint not found")

    def send_json_response(self, data, status=200):
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_bytes)

def run():
    server_address = ("", PORT)
    httpd = HTTPServer(server_address, AegisRequestHandler)
    print(f"\n=======================================================")
    print(f" [*] AegisForensics SOC Platform Online!")
    print(f" [*] SIH26106 AICTE Cyber Threat & Forensic Intel")
    print(f" [*] Local Dashboard: http://localhost:{PORT}")
    print(f"=======================================================\n")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
