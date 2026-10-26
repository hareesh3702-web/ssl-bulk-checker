import csv
import html
import ipaddress
import os
import socket
import ssl
import smtplib

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.x509.oid import NameOID


TIMEOUT = 12
WORKERS = 10
WARNING_DAYS = 30
OUTPUT_DIR = Path("site")
EMAIL_RECIPIENT = "hareesh3702@gmail.com"

FIELDS = [
    "domain",
    "a_records",
    "status",
    "issuer",
    "expires",
    "days_left",
    "digicert",
    "details",
]


def normalize_domain(value):
    value = value.strip()

    parsed = urlsplit(
        value if "://" in value else "//" + value
    )

    host = parsed.hostname

    if not host:
        raise ValueError("Invalid domain or URL")

    return host.encode("idna").decode("ascii").lower().rstrip(".")


def resolve_public_addresses(host):
    results = socket.getaddrinfo(
        host,
        443,
        type=socket.SOCK_STREAM,
    )

    addresses = []
    seen = set()

    for family, socktype, proto, _, address in results:
        ip = ipaddress.ip_address(address[0])

        if not ip.is_global:
            raise ValueError(
                "Private or non-public IP targets are not allowed"
            )

        key = (family, address)

        if key not in seen:
            seen.add(key)
            addresses.append((family, socktype, proto, address))

    if not addresses:
        raise ValueError("No public IP addresses found")

    return addresses


def connect_tls(host, addresses, context):
    last_error = None

    for family, socktype, proto, address in addresses:
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(TIMEOUT)

        try:
            raw.connect(address)

            return context.wrap_socket(
                raw,
                server_hostname=host,
            )

        except Exception as exc:
            raw.close()
            last_error = exc

    if last_error is not None:
        raise last_error

    raise ConnectionError("No addresses available for connection")


def check_domain(host):
    result = {
        "domain": host,
        "a_records": "",
        "status": "ERROR",
        "issuer": "",
        "expires": "",
        "days_left": "",
        "digicert": False,
        "details": "",
    }

    try:
        addresses = resolve_public_addresses(host)

        ipv4_addresses = sorted({
            address[0]
            for family, socktype, proto, address in addresses
            if family == socket.AF_INET
        })

        result["a_records"] = (
            ", ".join(ipv4_addresses)
            if ipv4_addresses
            else "No IPv4 address returned"
        )

        # Inspection retrieves the certificate but does not establish trust.
        inspection = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        inspection.check_hostname = False
        inspection.verify_mode = ssl.CERT_NONE

        with connect_tls(host, addresses, inspection) as connection:
            certificate_der = connection.getpeercert(binary_form=True)
            inspected_ip = connection.getpeername()[0]

        certificate = x509.load_der_x509_certificate(
            certificate_der
        )

        issuer_dn = certificate.issuer.rfc4514_string()
        expires = certificate.not_valid_after_utc
        starts = certificate.not_valid_before_utc
        now = datetime.now(timezone.utc)

        remaining_seconds = (expires - now).total_seconds()

        organizations = [
            attribute.value
            for attribute in certificate.issuer.get_attributes_for_oid(
                NameOID.ORGANIZATION_NAME
            )
        ]

        issuer_label = " / ".join(organizations) or issuer_dn

        result.update({
            "issuer": issuer_label,
            "expires": expires.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_left": int(remaining_seconds // 86400),
            "digicert": "digicert" in issuer_dn.lower(),
        })

        verified = False
        validation_error = ""
        verified_ip = ""

        try:
            validation_context = ssl.create_default_context()

            with connect_tls(
                host,
                addresses,
                validation_context,
            ) as connection:
                verified_ip = connection.getpeername()[0]
                verified_der = connection.getpeercert(binary_form=True)

            # Avoid claiming validation passed for a different certificate.
            if verified_der == certificate_der:
                verified = True
            else:
                validation_error = (
                    "The validation connection returned a different "
                    "certificate. The inspected certificate's validation "
                    "is inconclusive."
                )

        except ssl.SSLCertVerificationError as exc:
            validation_error = (
                "Certificate validation failed: "
                f"{exc.verify_message}"
            )

        except Exception as exc:
            validation_error = (
                "Validation connection failed: "
                f"{type(exc).__name__}: {exc}"
            )

        if remaining_seconds <= 0:
            result["status"] = "EXPIRED"

        elif starts > now:
            result["status"] = "NOT YET VALID"

        elif not verified:
            result["status"] = "VALIDATION FAILED"

        elif remaining_seconds <= WARNING_DAYS * 86400:
            result["status"] = "EXPIRING SOON"

        else:
            result["status"] = "VALID"

        details = [
            f"Inspected endpoint IP: {inspected_ip}",
            f"Issuer DN: {issuer_dn}",
            f"Valid from: {starts.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]

        if verified:
            details.append(
                "Trust and hostname verification passed."
            )
        else:
            details.append(validation_error)

        if verified_ip:
            details.append(
                f"Validation endpoint IP: {verified_ip}"
            )

        result["details"] = "\n".join(details)

    except Exception as exc:
        result["details"] = (
            f"{type(exc).__name__}: {exc}"
        )

    return result


def publish_report(records, input_errors):
    OUTPUT_DIR.mkdir(exist_ok=True)

    with (OUTPUT_DIR / "results.csv").open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=FIELDS,
        )
        writer.writeheader()
        writer.writerows(records)

    def escape(value):
        return html.escape(str(value))

    rows = []

    for item in records:
        if item["status"] == "VALID":
            status_class = "good"

        elif item["status"] == "EXPIRING SOON":
            status_class = "warn"

        else:
            status_class = "bad"

        rows.append(
            "<tr>"
            f"<td>{escape(item['domain'])}</td>"
            f"<td>{escape(item['a_records'])}</td>"
            f"<td class='{status_class}'>"
            f"{escape(item['status'])}</td>"
            f"<td>{escape(item['issuer'])}</td>"
            f"<td>{escape(item['expires'])}</td>"
            f"<td>{escape(item['days_left'])}</td>"
            f"<td>{'Yes' if item['digicert'] else 'No'}</td>"
            "<td><details><summary>View details</summary>"
            f"<pre>{escape(item['details'])}</pre>"
            "</details></td>"
            "</tr>"
        )

    generated = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    digicert_count = sum(
        item["digicert"] for item in records
    )

    valid_count = sum(
        item["status"] == "VALID" for item in records
    )

    expiring_count = sum(
        item["status"] == "EXPIRING SOON"
        for item in records
    )

    issue_count = sum(
        item["status"] not in ("VALID", "EXPIRING SOON")
        for item in records
    )

    warning = ""

    if input_errors:
        warning = (
            "<h2>Skipped input lines</h2>"
            "<pre>"
            + escape("\n".join(input_errors))
            + "</pre>"
        )

    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bulk SSL Checker</title>
<style>
:root {
    color-scheme: dark;
}
* {
    box-sizing: border-box;
}
body {
    margin: 0;
    padding: 24px;
    background: #0f172a;
    color: #e2e8f0;
    font: 15px Arial, sans-serif;
}
main {
    max-width: 1700px;
    margin: auto;
}
h1 {
    color: #38bdf8;
}
.cards {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 22px 0;
}
.card {
    background: #1e293b;
    padding: 18px;
    border: 1px solid #334155;
    border-radius: 10px;
}
.controls {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 18px;
}
input {
    padding: 12px;
    width: min(100%, 480px);
    border-radius: 8px;
    border: 1px solid #475569;
    background: #1e293b;
    color: white;
    font-size: 15px;
}
.button {
    display: inline-block;
    padding: 12px 16px;
    background: #2563eb;
    color: white;
    border-radius: 8px;
    text-decoration: none;
}
.scroll {
    overflow-x: auto;
    border: 1px solid #334155;
    border-radius: 10px;
}
table {
    width: 100%;
    border-collapse: collapse;
    background: #1e293b;
}
th, td {
    padding: 13px;
    text-align: left;
    border-bottom: 1px solid #334155;
    vertical-align: top;
}
th {
    background: #334155;
    white-space: nowrap;
}
.good {
    color: #4ade80;
}
.warn {
    color: #fbbf24;
}
.bad {
    color: #fb7185;
}
details {
    min-width: 160px;
    max-width: 460px;
}
summary {
    cursor: pointer;
    color: #38bdf8;
}
pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font: inherit;
    line-height: 1.6;
}
.note {
    color: #94a3b8;
    line-height: 1.7;
}
@media (max-width: 600px) {
    body {
        padding: 14px;
    }
    .card {
        flex: 1 1 140px;
    }
}
</style>
</head>
<body>
<main>
<h1>Bulk SSL Certificate Checker</h1>
<p>Last checked: __TIME__</p>

<p class="note">
This report is a snapshot from the latest GitHub Actions run.
IPv4 addresses are resolved from the runner at scan time.
CDN or proxy addresses may not identify the origin server.
The scan checks a reachable HTTPS endpoint on port 443;
it does not independently inspect every listed IP.
This is not a complete revocation or TLS configuration audit.
</p>

<div class="cards">
    <div class="card">Domains: __TOTAL__</div>
    <div class="card">Valid: __VALID__</div>
    <div class="card">Expiring soon: __EXPIRING__</div>
    <div class="card">DigiCert matches: __DIGICERT__</div>
    <div class="card">Errors / issues: __ISSUES__</div>
</div>

<div class="controls">
    <input
        id="search"
        type="search"
        placeholder="Filter domain, IP, issuer, or status..."
        aria-label="Filter SSL results"
    >
    <a class="button" href="results.csv" download>
        Download CSV
    </a>
</div>

<div class="scroll">
<table>
<thead>
<tr>
    <th>Website</th>
    <th>A records / IPv4</th>
    <th>Status</th>
    <th>Certificate issuer</th>
    <th>Expiration date</th>
    <th>Days left</th>
    <th>DigiCert</th>
    <th>Details</th>
</tr>
</thead>
<tbody>
__ROWS__
</tbody>
</table>
</div>

__WARNING__

<p class="note">
DigiCert matching uses the presented certificate's issuer name.
Results and CSV files on this website are public.
</p>
</main>

<script>
document.getElementById("search").addEventListener("input", function () {
    const query = this.value.toLowerCase();

    document.querySelectorAll("tbody tr").forEach(function (row) {
        row.hidden = !row.textContent.toLowerCase().includes(query);
    });
});
</script>
</body>
</html>
"""

    replacements = {
        "__TIME__": generated,
        "__TOTAL__": str(len(records)),
        "__VALID__": str(valid_count),
        "__EXPIRING__": str(expiring_count),
        "__DIGICERT__": str(digicert_count),
        "__ISSUES__": str(issue_count),
        "__ROWS__": "\n".join(rows),
        "__WARNING__": warning,
    }

    for key, value in replacements.items():
        page = page.replace(key, value)

    (OUTPUT_DIR / "index.html").write_text(
        page,
        encoding="utf-8",
    )


def email_digicert(records):
    matches = [
        item for item in records
        if item["digicert"]
    ]

    if not matches:
        print(
            "No DigiCert issuer matches among "
            "successfully inspected certificates. No email sent."
        )
        return

    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = "".join(
        os.getenv("SMTP_PASS", "").split()
    )
    sender = os.getenv("SMTP_FROM", "").strip() or user
    port = int(
        os.getenv("SMTP_PORT", "").strip() or "587"
    )

    if not all([host, user, password]):
        raise RuntimeError(
            "Missing SMTP_HOST, SMTP_USER, or SMTP_PASS"
        )

    sections = []

    for item in matches:
        sections.append(
            "\n".join(
                f"{field}: {item[field]}"
                for field in FIELDS
                if field != "digicert"
            )
        )

    message = EmailMessage()
    message["Subject"] = (
        f"DigiCert SSL report: {len(matches)} website(s)"
    )
    message["From"] = sender
    message["To"] = EMAIL_RECIPIENT

    message.set_content(
        "DigiCert issuer matches from the latest scan.\n\n"
        + "\n\n".join(sections)
        + "\n\nFull report:\n"
        + "https://hareesh3702-web.github.io/ssl-bulk-checker/\n"
    )

    with smtplib.SMTP(
        host,
        port,
        timeout=30,
    ) as smtp:
        smtp.ehlo()
        smtp.starttls(
            context=ssl.create_default_context()
        )
        smtp.ehlo()
        smtp.login(user, password)
        smtp.send_message(message)

    print(
        f"DigiCert report sent to {EMAIL_RECIPIENT}"
    )


def main():
    source = Path("domain.txt")

    if not source.exists():
        source = Path("domains.txt")

    if not source.exists():
        raise FileNotFoundError(
            "Create domain.txt with one domain per line."
        )

    domains = []
    input_errors = []
    seen = set()

    for line in source.read_text(
        encoding="utf-8-sig"
    ).splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            domain = normalize_domain(line)

            if domain not in seen:
                seen.add(domain)
                domains.append(domain)

        except Exception as exc:
            input_errors.append(
                f"{line}: {type(exc).__name__}: {exc}"
            )

    if not domains:
        raise ValueError(
            "No usable domains found in the input file."
        )

    print(f"Checking {len(domains)} unique domains...")

    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as executor:
        records = list(
            executor.map(check_domain, domains)
        )

    records.sort(
        key=lambda item: item["domain"]
    )

    publish_report(records, input_errors)

    for item in records:
        print(
            f"{item['domain']} | "
            f"IPv4: {item['a_records']} | "
            f"{item['status']} | "
            f"{item['issuer']} | "
            f"{item['expires']}"
        )

        if item["status"] not in (
            "VALID",
            "EXPIRING SOON",
        ):
            print(
                f"  Details: {item['details']}"
            )

    try:
        email_digicert(records)

    except Exception as exc:
        # Email failure must not prevent website publishing.
        print(
            f"::warning::Email failed: "
            f"{type(exc).__name__}: {exc}"
        )

    print(
        f"Website report prepared for "
        f"{len(records)} unique domains."
    )


if __name__ == "__main__":
    main()
