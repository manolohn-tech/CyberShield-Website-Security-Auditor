
import os
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "High",
        "Encourages browsers to use HTTPS for future visits."
    ),
    "Content-Security-Policy": (
        "High",
        "Helps limit which scripts, styles, and other resources a page can load."
    ),
    "X-Content-Type-Options": (
        "Medium",
        "Helps prevent browsers from guessing a different content type."
    ),
    "X-Frame-Options": (
        "Medium",
        "Can help reduce clickjacking risk when framing is not required."
    ),
    "Referrer-Policy": (
        "Low",
        "Controls how much referrer information the browser sends."
    ),
    "Permissions-Policy": (
        "Low",
        "Restricts access to selected browser features."
    ),
}


def validate_public_url(raw_url):
    """Accept public HTTP(S) websites and block non-public IP addresses."""

    raw_url = (raw_url or "").strip()

    if not raw_url:
        raise ValueError("Enter a website URL.")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Enter a valid domain name.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Enter a valid port number.")

    if port is not None and port not in (80, 443):
        raise ValueError("Only standard web ports 80 and 443 are allowed.")

    host = parsed.hostname.rstrip(".").lower()

    if (
        host in ("localhost", "localhost.localdomain")
        or host.endswith(".local")
    ):
        raise ValueError(
            "Local network targets are blocked. Use a public site "
            "you are authorized to audit."
        )

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            answers = socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
            addresses = list({
                ipaddress.ip_address(item[4][0])
                for item in answers
            })
        except (socket.gaierror, OSError):
            raise ValueError(
                "The domain could not be resolved. Check the URL and try again."
            )

    if not addresses:
        raise ValueError("The domain did not resolve to an IP address.")

    for address in addresses:
        if not address.is_global:
            raise ValueError(
                "Private, loopback, link-local, and non-public IP addresses "
                "are blocked."
            )

    # Remove fragments; fragments are not sent to the web server.
    clean_url = raw_url.split("#", 1)[0]

    return clean_url, host


def audit_site(raw_url):
    """Check HTTPS usage and selected HTTP security response headers."""

    url, host = validate_public_url(raw_url)

    # Redirects are disabled to avoid automatically following redirects
    # to private or internal destinations.
    try:
        response = requests.get(
            url,
            timeout=(4, 7),
            allow_redirects=False,
            headers={
                "User-Agent": "CyberShield-Student-Auditor/1.0"
            },
            stream=True,
        )

    except RequestException:
        # Try HTTP only if the HTTPS request fails.
        if url.startswith("https://"):
            fallback = "http://" + url[len("https://"):]

            try:
                # Validate the fallback URL too.
                validate_public_url(fallback)

                response = requests.get(
                    fallback,
                    timeout=(4, 7),
                    allow_redirects=False,
                    headers={
                        "User-Agent": "CyberShield-Student-Auditor/1.0"
                    },
                    stream=True,
                )
                url = fallback

            except (RequestException, ValueError):
                raise ValueError(
                    "Could not connect safely. The site may be unavailable "
                    "or may block automated requests."
                )
        else:
            raise ValueError(
                "Could not connect safely. The site may be unavailable "
                "or may block automated requests."
            )

    try:
        headers = response.headers
        scheme = urlparse(url).scheme

        findings = []
        score = 100

        if scheme == "https":
            findings.append({
                "name": "HTTPS connection",
                "severity": "Pass",
                "status": "HTTPS was used for this request.",
                "recommendation": (
                    "Keep HTTPS enabled and renew certificates before expiry."
                ),
            })
        else:
            findings.append({
                "name": "HTTPS connection",
                "severity": "High",
                "status": (
                    "The request used HTTP, which does not encrypt traffic."
                ),
                "recommendation": (
                    "Enable HTTPS and redirect HTTP to HTTPS on the server."
                ),
            })
            score -= 25

        for header, (severity, advice) in SECURITY_HEADERS.items():
            if header in headers:
                findings.append({
                    "name": header,
                    "severity": "Pass",
                    "status": "Header was present in the response.",
                    "recommendation": advice,
                })
            else:
                findings.append({
                    "name": header,
                    "severity": severity,
                    "status": "Header was not present in the response.",
                    "recommendation": advice,
                })

                score -= {
                    "High": 12,
                    "Medium": 7,
                    "Low": 3,
                }[severity]

        # Identify potentially revealing technology headers.
        for name in ("Server", "X-Powered-By"):
            value = headers.get(name)

            if value:
                findings.append({
                    "name": name,
                    "severity": "Low",
                    "status": (
                        "The response discloses technology information: "
                        + value[:120]
                    ),
                    "recommendation": (
                        "Consider removing or minimizing detailed technology banners."
                    ),
                })
                score -= 3

        score = max(0, min(100, score))

        counts = {
            "high": sum(
                1 for finding in findings
                if finding["severity"] == "High"
            ),
            "medium": sum(
                1 for finding in findings
                if finding["severity"] == "Medium"
            ),
            "low": sum(
                1 for finding in findings
                if finding["severity"] == "Low"
            ),
            "pass": sum(
                1 for finding in findings
                if finding["severity"] == "Pass"
            ),
        }

        return {
            "url": url,
            "host": host,
            "status_code": response.status_code,
            "score": score,
            "findings": findings,
            "counts": counts,
            "note": (
                "This is a limited header/configuration check, "
                "not a penetration test."
            ),
        }

    finally:
        response.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/audit")
def api_audit():
    data = request.get_json(silent=True) or {}

    try:
        result = audit_site(data.get("url", ""))
        return jsonify({"ok": True, "result": result})

    except ValueError as exc:
        return jsonify({
            "ok": False,
            "error": str(exc),
        }), 400

    except Exception:
        app.logger.exception("Unexpected audit error")
        return jsonify({
            "ok": False,
            "error": (
                "Unexpected error. Check the URL and try again."
            ),
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )