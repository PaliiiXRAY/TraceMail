"""
Email RFC822 Parser for SIH26106
Extracts headers, Received trace lines, sender identity, authentication results, and links.
"""
import email
from email import policy
import re
from urllib.parse import urlparse

class EmailParser:
    @staticmethod
    def parse_raw(raw_content: str) -> dict:
        """Parses a raw email string or .eml content into a structured dictionary."""
        try:
            msg = email.message_from_string(raw_content, policy=policy.default)
        except Exception:
            msg = email.message_from_string(raw_content)

        # Extract envelope and display sender
        from_header = str(msg.get("From", ""))
        display_name = ""
        envelope_sender = ""
        if "<" in from_header and ">" in from_header:
            display_name = from_header.split("<")[0].strip().strip('"').strip("'")
            envelope_sender = from_header.split("<")[1].split(">")[0].strip()
        else:
            envelope_sender = from_header.strip()
            display_name = envelope_sender.split("@")[0] if "@" in envelope_sender else envelope_sender

        sender_domain = envelope_sender.split("@")[1].lower() if "@" in envelope_sender else ""

        # Extract Received headers
        received_headers = msg.get_all("Received", [])
        if isinstance(received_headers, str):
            received_headers = [received_headers]

        # Extract plain text & HTML body
        body_text = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition", ""))
                if "attachment" in cdispo:
                    continue
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        decoded_text = payload.decode(charset, errors='replace')
                        if ctype == "text/plain" and not body_text:
                            body_text = decoded_text
                        elif ctype == "text/html" and not body_html:
                            body_html = decoded_text
                except Exception:
                    pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    body_text = payload.decode(charset, errors='replace')
                else:
                    body_text = str(msg.get_payload() or "")
            except Exception:
                body_text = str(msg.get_payload() or "")

        links = EmailParser.extract_links(body_text + " " + body_html)

        return {
            "subject": str(msg.get("Subject", "No Subject")),
            "from_raw": from_header,
            "display_name": display_name,
            "envelope_sender": envelope_sender,
            "sender_domain": sender_domain,
            "to": str(msg.get("To", "")),
            "date": str(msg.get("Date", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "auth_results": str(msg.get("Authentication-Results", "")),
            "received_headers": [str(h) for h in received_headers],
            "body_text": body_text.strip(),
            "links": links
        }

    @staticmethod
    def extract_links(text: str) -> list:
        """Extracts unique URLs found in the text/html content."""
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*'
        raw_urls = re.findall(url_pattern, text)
        cleaned = []
        seen = set()
        for url in raw_urls:
            clean_url = url.rstrip('.,);:?!')
            parsed = urlparse(clean_url)
            if parsed.netloc and clean_url not in seen:
                seen.add(clean_url)
                cleaned.append({
                    "url": clean_url,
                    "domain": parsed.netloc.lower(),
                    "protocol": parsed.scheme
                })
        return cleaned
