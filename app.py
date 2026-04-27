from __future__ import annotations

import base64
import hashlib
import os
import textwrap
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Flask, Response, render_template, request, send_file

app = Flask(__name__)

CERT_DIR = Path(os.getenv("CERT_DIR", "/app/certs"))
CERT_FILENAME = os.getenv("CERT_FILENAME", "cato-root-ca.cer")
CERT_PATH = CERT_DIR / CERT_FILENAME

PORTAL_NAME = os.getenv("PORTAL_NAME", "Cato BYOD Certificate Setup")
COMPANY_NAME = os.getenv("COMPANY_NAME", "Example Company")
CERT_DISPLAY_NAME = os.getenv("CERT_DISPLAY_NAME", "Cato Networks Root CA")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "helpdesk@example.com")
VERIFY_URL = os.getenv("VERIFY_URL", "https://example.com")
IOS_PROFILE_IDENTIFIER = os.getenv("IOS_PROFILE_IDENTIFIER", "com.example.cato.rootca")


def load_cert_bytes() -> bytes:
    return CERT_PATH.read_bytes()


def load_cert() -> x509.Certificate:
    raw = load_cert_bytes()
    try:
        return x509.load_pem_x509_certificate(raw, default_backend())
    except ValueError:
        return x509.load_der_x509_certificate(raw, default_backend())


def cert_der_bytes() -> bytes:
    cert = load_cert()
    return cert.public_bytes(serialization.Encoding.DER)


def colon_fingerprint(raw_digest: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw_digest)


def cert_info() -> dict[str, str]:
    cert = load_cert()
    der = cert.public_bytes(serialization.Encoding.DER)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "sha256": colon_fingerprint(hashlib.sha256(der).digest()),
        "sha1": colon_fingerprint(hashlib.sha1(der).digest()),
    }


def platform_hint(user_agent: str) -> str:
    ua = user_agent.lower()
    if "iphone" in ua or "ipad" in ua:
        return "ios"
    if "android" in ua:
        return "android"
    if "firefox" in ua:
        return "firefox"
    if "macintosh" in ua or "mac os x" in ua:
        return "macos"
    if "windows" in ua:
        return "windows"
    return "unknown"


def base_url() -> str:
    return request.url_root.rstrip("/")


def ctx() -> dict[str, object]:
    return {
        "portal_name": PORTAL_NAME,
        "company_name": COMPANY_NAME,
        "cert_display_name": CERT_DISPLAY_NAME,
        "support_email": SUPPORT_EMAIL,
        "verify_url": VERIFY_URL,
        "cert_info": cert_info(),
        "base_url": base_url(),
    }


@app.route("/")
def index():
    data = ctx()
    data["platform_hint"] = platform_hint(request.headers.get("User-Agent", ""))
    return render_template("index.html", **data)


@app.route("/windows")
def windows():
    return render_template("windows.html", **ctx())


@app.route("/macos")
def macos():
    return render_template("macos.html", **ctx())


@app.route("/ios")
def ios():
    return render_template("ios.html", **ctx())


@app.route("/android")
def android():
    return render_template("android.html", **ctx())


@app.route("/linux")
def linux():
    return render_template("linux.html", **ctx())


@app.route("/firefox")
def firefox():
    return render_template("firefox.html", **ctx())


@app.route("/verify")
def verify():
    return render_template("verify.html", **ctx())


@app.route("/download/cert")
def download_cert():
    return send_file(
        CERT_PATH,
        as_attachment=True,
        download_name=CERT_FILENAME,
        mimetype="application/x-x509-ca-cert",
    )


@app.route("/download/windows.ps1")
def windows_script():
    script = f"""
    # Installs the Cato/company TLS inspection root certificate into the
    # current user's Trusted Root Certification Authorities store.
    # This is explicit and user-visible; it does not attempt stealth installation.

    $ErrorActionPreference = "Stop"
    $CertUrl = "{base_url()}/download/cert"
    $ExpectedSha256 = "{cert_info()['sha256'].replace(':', '').upper()}"
    $CertPath = Join-Path $env:TEMP "{CERT_FILENAME}"
    $StoreLocation = "Cert:\\CurrentUser\\Root"

    Write-Host "Downloading certificate from $CertUrl ..."
    Invoke-WebRequest -Uri $CertUrl -OutFile $CertPath

    $ActualSha256 = (Get-FileHash -Algorithm SHA256 -Path $CertPath).Hash.ToUpper()
    if ($ActualSha256 -ne $ExpectedSha256) {{
      throw "SHA-256 fingerprint mismatch. Expected $ExpectedSha256 but got $ActualSha256."
    }}

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    Write-Host "Subject:    $($cert.Subject)"
    Write-Host "Issuer:     $($cert.Issuer)"
    Write-Host "Thumbprint: $($cert.Thumbprint)"
    Write-Host "Not After:  $($cert.NotAfter)"

    Write-Host "Installing certificate into CurrentUser Trusted Root store..."
    Import-Certificate -FilePath $CertPath -CertStoreLocation $StoreLocation | Out-Null
    Write-Host "Done. Restart your browser."
    """
    return Response(textwrap.dedent(script).lstrip(), mimetype="text/plain")


@app.route("/download/macos.sh")
def macos_script():
    script = f"""
    #!/usr/bin/env bash
    set -euo pipefail

    CERT_URL="{base_url()}/download/cert"
    EXPECTED_SHA256="{cert_info()['sha256'].replace(':', '').lower()}"
    CERT_PATH="/tmp/{CERT_FILENAME}"

    if [[ $EUID -ne 0 ]]; then
      echo "Please run with sudo so the certificate can be installed into the System keychain."
      exit 1
    fi

    echo "Downloading certificate from ${{CERT_URL}} ..."
    curl -fsSL "${{CERT_URL}}" -o "${{CERT_PATH}}"

    ACTUAL_SHA256="$(shasum -a 256 "${{CERT_PATH}}" | awk '{{print tolower($1)}}')"
    if [[ "${{ACTUAL_SHA256}}" != "${{EXPECTED_SHA256}}" ]]; then
      echo "SHA-256 fingerprint mismatch. Refusing to install."
      echo "Expected: ${{EXPECTED_SHA256}}"
      echo "Actual:   ${{ACTUAL_SHA256}}"
      exit 1
    fi

    openssl x509 -in "${{CERT_PATH}}" -noout -subject -issuer -fingerprint -sha256 -dates

    echo "Installing and trusting certificate in System keychain..."
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${{CERT_PATH}}"
    echo "Done. Restart browsers that were already open."
    """
    return Response(textwrap.dedent(script).lstrip(), mimetype="text/x-shellscript")


@app.route("/download/linux.sh")
def linux_script():
    script = f"""
    #!/usr/bin/env bash
    set -euo pipefail

    CERT_URL="{base_url()}/download/cert"
    EXPECTED_SHA256="{cert_info()['sha256'].replace(':', '').lower()}"
    CERT_NAME="company-cato-root-ca.crt"
    TMP_CERT="/tmp/${{CERT_NAME}}"

    if [[ $EUID -ne 0 ]]; then
      echo "Please run with sudo."
      exit 1
    fi

    curl -fsSL "${{CERT_URL}}" -o "${{TMP_CERT}}"
    ACTUAL_SHA256="$(sha256sum "${{TMP_CERT}}" | awk '{{print tolower($1)}}')"
    if [[ "${{ACTUAL_SHA256}}" != "${{EXPECTED_SHA256}}" ]]; then
      echo "SHA-256 fingerprint mismatch. Refusing to install."
      exit 1
    fi

    openssl x509 -in "${{TMP_CERT}}" -noout -subject -issuer -fingerprint -sha256 -dates

    if [[ -d /usr/local/share/ca-certificates ]]; then
      cp "${{TMP_CERT}}" "/usr/local/share/ca-certificates/${{CERT_NAME}}"
      update-ca-certificates
    elif [[ -d /etc/pki/ca-trust/source/anchors ]]; then
      cp "${{TMP_CERT}}" "/etc/pki/ca-trust/source/anchors/${{CERT_NAME}}"
      update-ca-trust
    else
      echo "Unsupported Linux CA trust layout. Install manually."
      exit 1
    fi

    echo "Done. Restart browsers/apps that were open."
    """
    return Response(textwrap.dedent(script).lstrip(), mimetype="text/x-shellscript")


@app.route("/download/firefox.sh")
def firefox_script():
    script = f"""
    #!/usr/bin/env bash
    set -euo pipefail

    CERT_URL="{base_url()}/download/cert"
    EXPECTED_SHA256="{cert_info()['sha256'].replace(':', '').lower()}"
    CERT_PATH="/tmp/{CERT_FILENAME}"
    CERT_NICKNAME="{CERT_DISPLAY_NAME}"

    if ! command -v certutil >/dev/null 2>&1; then
      echo "certutil is required."
      echo "macOS: brew install nss"
      echo "Debian/Ubuntu: sudo apt install libnss3-tools"
      exit 1
    fi

    curl -fsSL "${{CERT_URL}}" -o "${{CERT_PATH}}"
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL_SHA256="$(sha256sum "${{CERT_PATH}}" | awk '{{print tolower($1)}}')"
    else
      ACTUAL_SHA256="$(shasum -a 256 "${{CERT_PATH}}" | awk '{{print tolower($1)}}')"
    fi

    if [[ "${{ACTUAL_SHA256}}" != "${{EXPECTED_SHA256}}" ]]; then
      echo "SHA-256 fingerprint mismatch. Refusing to install."
      exit 1
    fi

    found=0
    for profile in "$HOME"/.mozilla/firefox/*.default* "$HOME"/Library/Application\ Support/Firefox/Profiles/*.default*; do
      if [[ -d "$profile" ]]; then
        found=1
        echo "Installing certificate into Firefox profile: $profile"
        certutil -A -n "${{CERT_NICKNAME}}" -t "C,," -i "${{CERT_PATH}}" -d "sql:${{profile}}"
      fi
    done

    if [[ "$found" -eq 0 ]]; then
      echo "No Firefox profile found. Import manually from Firefox certificate settings."
    fi

    echo "Done. Restart Firefox."
    """
    return Response(textwrap.dedent(script).lstrip(), mimetype="text/x-shellscript")


@app.route("/download/mobileconfig")
def mobileconfig():
    der_b64 = base64.b64encode(cert_der_bytes()).decode("ascii")
    wrapped_b64 = "\n        ".join(textwrap.wrap(der_b64, 64))
    cert_uuid = str(uuid.uuid4()).upper()
    profile_uuid = str(uuid.uuid4()).upper()
    org = escape(COMPANY_NAME)
    display = escape(CERT_DISPLAY_NAME)
    identifier = escape(IOS_PROFILE_IDENTIFIER)
    profile = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>{escape(CERT_FILENAME)}</string>
      <key>PayloadContent</key>
      <data>
        {wrapped_b64}
      </data>
      <key>PayloadDescription</key>
      <string>Installs the company TLS inspection root certificate.</string>
      <key>PayloadDisplayName</key>
      <string>{display}</string>
      <key>PayloadIdentifier</key>
      <string>{identifier}.cert</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{cert_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Installs the company certificate used for TLS inspection on the BYOD network.</string>
  <key>PayloadDisplayName</key>
  <string>{org} BYOD Certificate Setup</string>
  <key>PayloadIdentifier</key>
  <string>{identifier}.profile</string>
  <key>PayloadOrganization</key>
  <string>{org}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""
    return Response(
        profile,
        mimetype="application/x-apple-aspen-config",
        headers={"Content-Disposition": "attachment; filename=cato-root-ca.mobileconfig"},
    )


@app.after_request
def security_headers(response: Response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
