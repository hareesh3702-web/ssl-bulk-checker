#!/usr/bin/env python3
import os
import ssl
import socket
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAINS_FILE = "domains.txt"
TIMEOUT = 10
WARNING_DAYS = 30
DIGICERT_EMAIL_TO = os.getenv("DIGICERT_EMAIL_TO", "hareesh3702@gmail.com")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)


def get_ssl_info(domain):
    domain = domain.strip()
    if not domain or domain.startswith("#"):
        return None

    context = ssl.create_default_context()
    result = {
        "domain": domain,
        "status": "ERROR",
        "expiry": "-",
        "days_left": "-",
        "provider": "-",
        "issuer": "-",
    }

    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=timezone.utc)
        days_left = (expiry - datetime.now(timezone.utc)).days

        issuer_parts = []
        for key, value in cert.get("issuer", []):
            issuer_parts.append(f"{key}={value}")

        issuer_text = ", ".join(issuer_parts)

        # Common certificate provider detection
        issuer_lower = issuer_text.lower()
        providers = [
            "DigiCert", "Let's Encrypt", "Sectigo", "GoDaddy",
            "GlobalSign", "ZeroSSL", "Google Trust Services",
            "Amazon", "Cloudflare", "Entrust", "SSL.com"
        ]

        provider = "Other"
        for name in providers:
            if name.lower() in issuer_lower:
                provider = name
                break

        if days_left < 0:
            status = "EXPIRED"
        elif days_left <= WARNING_DAYS:
            status = "EXPIRING SOON"
        else:
            status = "VALID"

        result.update({
            "status": status,
            "expiry": expiry.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_left": days_left,
            "provider": provider,
            "issuer": issuer_text,
        })

    except Exception as e:
        result["issuer"] = str(e)

    return result


def send_digicert_alert(records):
    digicert_sites = [r for r in records if r["provider"] == "DigiCert"]

    if not digicert_sites:
        print("No DigiCert SSL websites found. No email sent.")
        return

    lines = [
        "DigiCert SSL certificate report",
        "=" * 40,
        ""
    ]

    for r in digicert_sites:
        lines.append(
            f"Website: {r['domain']}\n"
            f"SSL Provider: {r['provider']}\n"
            f"Status: {r['status']}\n"
            f"Expiry Date: {r['expiry']}\n"
            f"Days Remaining: {r['days_left']}\n"
            f"Issuer: {r['issuer']}\n"
        )

    msg = EmailMessage()
    msg["Subject"] = f"DigiCert SSL Report - {len(digicert_sites)} website(s)"
    msg["From"] = SMTP_FROM
    msg["To"] = DIGICERT_EMAIL_TO
    msg.set_content("\n".join(lines))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

    print(f"DigiCert report emailed to {DIGICERT_EMAIL_TO}")


def main():
    with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    records = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(get_ssl_info, d): d for d in domains}

        for future in as_completed(futures):
            result = future.result()
            if result:
                records.append(result)

    records.sort(key=lambda x: x["domain"])

    print("\nSSL BULK CHECK REPORT")
    print("=" * 110)
    print(f"{'Domain':35} {'Status':15} {'Provider':22} {'Expiry Date':25} {'Days Left'}")
    print("-" * 110)

    for r in records:
        print(
            f"{r['domain'][:34]:35} "
            f"{r['status']:15} "
            f"{r['provider'][:21]:22} "
            f"{r['expiry']:25} "
            f"{r['days_left']}"
        )

    print("=" * 110)
    print(f"Total checked: {len(records)}")

    if SMTP_HOST and SMTP_USER and SMTP_PASS:
        send_digicert_alert(records)
    else:
        print("SMTP settings missing; DigiCert email skipped.")


if __name__ == "__main__":
    main()
