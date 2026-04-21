import email
import re
from email.message import Message
from typing import Any


def parse_raw_email(raw_email: str) -> dict[str, Any]:
    """Parse raw email string into structured data."""
    msg = email.message_from_string(raw_email)

    return {
        "headers": dict(msg.items()),
        "body": extract_body(msg),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
    }


def extract_body(msg: Message) -> str:
    """Extract email body text."""
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode()
        except Exception:
            body = str(msg.get_payload())

    return body


def extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+(?<![.,:;?])'
    return re.findall(url_pattern, text)


def extract_email_addresses(text: str) -> list[str]:
    """Extract email addresses from text."""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(email_pattern, text)