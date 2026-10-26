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
OUT = Path("site")
FIELDS = [
    "domain", "status", "issuer", "expires",
    "days_left", "digicert", "details"
]


def normalize(value):
    value = value.strip()
    parsed = urlsplit(
        value if "://" in value else "//" + value
    )
    host = parsed.hostname
    if not host:
        raise ValueError("Invalid domain")
    return host.encode("idna").decode("ascii").lower().rstrip(".")


def resolve_public(host):
    addresses = socket.getaddrinfo(
        host, 443, type=socket.SOCK_STREAM
    )
    allowed = []
    for family, socktype, proto, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global:
            raise ValueError(
                "Private or non-public IP targets are not allowed"
            )
        allowed.append((family, socktype, proto, address))
    if not allowed:
        raise ValueError("No public IP addresses found")
    return allowed


def connect_tls(host, addresses, context):
    last_error = None
    for family, socktype, proto, address in addresses:
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(TIMEOUT)
        try:
            raw.connect(address)
            return context.wrap_socket(
                raw, server_hostname=host
            )
        except Exception as exc:
            raw.close()
            last_error = exc
    raise last_error


def check_domain(host):
    result = {
        "domain": host,
        "status": "ERROR",
        "issuer": "",
        "expires": "",
        "days_left": "",
        "digicert": False,
        "details": "",
    }

    try:
        addresses = resolve_public(host)

        # Inspection only: this does not establish trust.
        inspection = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        inspection.check_hostname = False
        inspection.verify_mode = ssl.CERT_NONE

        with connect_tls(host, addresses, inspection) as connection:
            der = connection.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der)
        issuer = cert.issuer.rfc4514_string()
        expiry = cert.not_valid_after_utc
        starts = cert.not_valid_before_utc
        now = datetime.now(timezone.utc)
        remaining = (expiry - now).total_seconds()

        organizations = [
            attr.value
            for attr in cert.issuer.get_attributes_for_oid(
                NameOID.ORGANIZATION_NAME
            )
        ]
        issuer_label = " / ".join(organizations) or issuer

        result.update({
            "issuer": issuer_label,
            "expires": expiry.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "days_left": int(remaining // 86400),
            "digicert": "digicert" in issuer.lower(),
        })

        # A separate connection checks trust and hostname.
        verified = False
        validation_error = ""
        try:
            with connect_tls(
                host, addresses, ssl.create_default_context()
            ):
                verified = True
        except ssl.SSLCertVerificationError as exc:
            validation_error = (
                f"Certificate validation failed: "
                f"{exc.verify_message}"
            )
        except Exception as exc:
            validation_error = (
                f"Validation connection failed: {exc}"
            )

        if remaining <= 0:
            result["status"] = "EXPIRED"
        elif starts > now:
            result["status"] = "NOT YET VALID"
        elif not verified:
            result["status"] = "VALIDATION FAILED"
        elif remaining <= 30 * 86400:
            result["status"] = "EXPIRING SOON"
        else:
            result["status"] = "VALID"

        result["details"] = (
            f"Issuer DN: {issuer}. "
            + (
                "Trust and hostname verification passed."
                if verified else validation_error
            )
        )

    except Exception as exc:
        result["details"] = f"{type(exc).__name__}: {exc}"

    return result


def publish_report(records, input_errors):
    OUT.mkdir(exist_ok=True)

    with (OUT / "results.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)

    def escape(value):
        return html.escape(str(value))

    rows = []
    for item in records:
        if item["status"] == "VALID":
            css_class = "good"
        elif item["status"] == "EXPIRING SOON":
            css_class = "warn"
        else:
            css_class = "bad"

        rows.append(
            "<tr>"
            f"<td>{escape(item['domain'])}</td>"
            f"<td class='{css_class}'>{escape(item['status'])}</td>"
            f"<td>{escape(item['issuer'])}</td>"
            f"<td>{escape(item['expires'])}</td>"
            f"<td>{escape(item['days_left'])}</td>"
            f"<td>{'Yes' if item['digicert'] else 'No'}</td>"
            "<td><details><summary>View details</summary>"
            f"{escape(item['details'])}"
            "</details></td></tr>"
        )

    generated = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
    digicert_count = sum(item["digicert"] for item in records)
    problems = sum(
        item["status"] not in ("VALID", "EXPIRING SOON")
        for item in records
    )

    warning = ""
    if input_errors:
        warning = (
            "<h2>Skipped input lines</h2><pre>"
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
body{margin:0;background:#0f172a;color:#e2e8f0;
font:15px Arial,sans-serif;padding:24px}
main{max-width:1500px;margin:auto}
h1{color:#38bdf8}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
.card{background:#1e293b;padding:18px;border-radius:10px}
input{padding:12px;width:min(90%,420px);margin-bottom:18px;
border-radius:8px;border:1px solid #475569;
background:#1e293b;color:white}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;background:#1e293b}
th,td{padding:13px;text-align:left;border-bottom:1px solid #334155;
vertical-align:top}
th{background:#334155;white-space:nowrap}
.good{color:#4ade80}.warn{color:#fbbf24}.bad{color:#fb7185}
a{color:#38bdf8}details{max-width:420px;overflow-wrap:anywhere}
summary{cursor:pointer}pre{white-space:pre-wrap}
.note{color:#94a3b8;line-height:1.6}
</style>
</head>
<body><main>
<h1>Bulk SSL Certificate Checker</h1>
<p>Last checked: __TIME__</p>
<p class="note">Snapshot from the latest workflow run.
Checks cover the certificate served on HTTPS port 443.
They are not a full revocation or TLS configuration audit.
DigiCert matching uses the presented certificate's issuer name.</p>
<div class="cards">
<div class="card">Domains: __TOTAL__</div>
<div class="card">DigiCert matches: __DIGICERT__</div>
<div class="card">Errors / validation issues: __PROBLEMS__</div>
</div>
<p><a href="results.csv" download>Download CSV report</a></p>
<input id="search" placeholder="Filter by domain, issuer, or status"
aria-label="Filter results">
<div class="scroll"><table>
<thead><tr>
<th>Website</th><th>Status</th><th>Certificate issuer</th>
<th>Expiration date</th><th>Days left</th>
<th>DigiCert</th><th>Details</th>
</tr></thead>
<tbody>__ROWS__</tbody>
</table></div>
__WARNING__
<script>
document.getElementById("search").addEventListener("input", function(){
  const query = this.value.toLowerCase();
  document.querySelectorAll("tbody tr").forEach(function(row){
    row.hidden = !row.textContent.toLowerCase().includes(query);
  });
});
</script>
</main></body></html>"""

    replacements = {
        "__TIME__": generated,
        "__TOTAL__": str(len(records)),
        "__DIGICERT__": str(digicert_count),
        "__PROBLEMS__": str(problems),
        "__ROWS__": "\n".join(rows),
        "__WARNING__": warning,
    }
    for key, value in replacements.items():
        page = page.replace(key, value)

    (OUT / "index.html").write_text(page, encoding="utf-8")


def email_digicert(records):
    matches = [item for item in records if item["digicert"]]
    if not matches:
        print("No DigiCert issuer matches among inspected certificates.")
        return

    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = "".join(os.getenv("SMTP_PASS", "").split())
    sender = os.getenv("SMTP_FROM", "").strip() or user
    recipient = "hareesh3702@gmail.com"
    port = int(os.getenv("SMTP_PORT", "").strip() or "587")

    if not all([host, user, password]):
        raise RuntimeError("Missing SMTP_HOST, SMTP_USER, or SMTP_PASS")

    sections = []
    for item in matches:
        sections.append("\n".join(
            f"{field}: {item[field]}"
            for field in FIELDS
            if field != "digicert"
        ))

    message = EmailMessage()
    message["Subject"] = (
        f"DigiCert SSL report: {len(matches)} website(s)"
    )
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "DigiCert issuer matches from the latest scan.\n\n"
        + "\n\n".join(sections)
    )

    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(user, password)
        smtp.send_message(message)

    print(f"DigiCert report sent to {recipient}")


def main():
    source = Path("domain.txt")
    if not source.exists():
        source = Path("domains.txt")
    if not source.exists():
        raise FileNotFoundError(
            "Create domain.txt with one domain per line."
        )

    domains = []
    errors = []
    seen = set()

    for line in source.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            domain = normalize(line)
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
        except Exception as exc:
            errors.append(f"{line}: {exc}")

    if not domains:
        raise ValueError("No usable domains found in the input file.")

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        records = list(executor.map(check_domain, domains))

    records.sort(key=lambda item: item["domain"])
    publish_report(records, errors)

    for item in records:
        print(
            f"{item['domain']} | {item['status']} | "
            f"{item['issuer']} | {item['expires']}"
        )
        if item["status"] not in ("VALID", "EXPIRING SOON"):
            print(f"  Details: {item['details']}")

    try:
        email_digicert(records)
    except Exception as exc:
        # Keep publishing the dashboard even if email fails.
        print(f"::warning::Email failed: {type(exc).__name__}: {exc}")

    print(f"Published report prepared for {len(records)} unique domains.")


if __name__ == "__main__":
    main()
