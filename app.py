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
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

APP_DIR = Path(__file__).resolve().parent
CERT_DIR = Path(os.getenv("CERT_DIR", APP_DIR / "certs"))
CERT_FILENAME = os.getenv("CERT_FILENAME", "cato-root-ca.cer")
CERT_PATH = CERT_DIR / CERT_FILENAME

PORTAL_NAME = os.getenv("PORTAL_NAME", "Cato BYOD Certificate Setup")
COMPANY_NAME = os.getenv("COMPANY_NAME", "Example Company")
CERT_DISPLAY_NAME = os.getenv("CERT_DISPLAY_NAME", "Cato Networks Root CA")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "helpdesk@example.com")
VERIFY_URL = os.getenv("VERIFY_URL", "https://example.com")
IOS_PROFILE_IDENTIFIER = os.getenv("IOS_PROFILE_IDENTIFIER", "com.example.cato.rootca")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

PLATFORM_OPTIONS = {
    "windows": {
        "label": "Windows",
        "path": "/windows",
        "primary_url": "/download/windows.cmd",
        "primary_label": "Download Windows Installer",
    },
    "macos": {
        "label": "macOS",
        "path": "/macos",
        "primary_url": "/download/macos.sh",
        "primary_label": "Download macOS Helper",
    },
    "ios": {
        "label": "iPhone / iPad",
        "path": "/ios",
        "primary_url": "/download/mobileconfig",
        "primary_label": "Download Configuration Profile",
    },
    "android": {
        "label": "Android",
        "path": "/android",
        "primary_url": "/download/cert",
        "primary_label": "Download Certificate",
    },
    "linux": {
        "label": "Linux",
        "path": "/linux",
        "primary_url": "/download/linux.sh",
        "primary_label": "Download Linux Helper",
    },
    "firefox": {
        "label": "Firefox",
        "path": "/firefox",
        "primary_url": "/download/firefox.sh",
        "primary_label": "Download Firefox Helper",
    },
}


def load_cert_bytes() -> bytes:
    return CERT_PATH.read_bytes()


def cert_openssl_inform() -> str:
    if load_cert_bytes().lstrip().startswith(b"-----BEGIN"):
        return "PEM"
    return "DER"


def load_cert() -> x509.Certificate:
    raw = load_cert_bytes()
    try:
        return x509.load_pem_x509_certificate(raw, default_backend())
    except ValueError:
        return x509.load_der_x509_certificate(raw, default_backend())


def cert_der_bytes() -> bytes:
    cert = load_cert()
    return cert.public_bytes(serialization.Encoding.DER)


def cert_sha256_hex() -> str:
    return hashlib.sha256(cert_der_bytes()).hexdigest().upper()


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


def script_response(script: str, filename: str) -> Response:
    return Response(
        textwrap.dedent(script).lstrip(),
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def ctx() -> dict[str, object]:
    return {
        "portal_name": PORTAL_NAME,
        "company_name": COMPANY_NAME,
        "cert_display_name": CERT_DISPLAY_NAME,
        "support_email": SUPPORT_EMAIL,
        "verify_url": VERIFY_URL,
        "cert_info": cert_info(),
        "base_url": base_url(),
        "platform_options": PLATFORM_OPTIONS,
    }


@app.route("/")
def index():
    data = ctx()
    data["platform_hint"] = platform_hint(request.headers.get("User-Agent", ""))
    data["detected_platform"] = PLATFORM_OPTIONS.get(data["platform_hint"])
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


@app.route("/healthz")
def healthz():
    load_cert()
    return {"status": "ok", "certificate": CERT_FILENAME}


@app.route("/download/windows.ps1")
def windows_script():
    script = f"""
    # Installs the Cato/company TLS inspection root certificate into the
    # current user's Trusted Root Certification Authorities store.
    # This is explicit and user-visible; it does not attempt stealth installation.

    $ErrorActionPreference = "Stop"
    $CertUrl = "{base_url()}/download/cert"
    $ExpectedSha256 = "{cert_sha256_hex()}"
    $CertPath = Join-Path $env:TEMP "{CERT_FILENAME}"
    $StoreLocation = "Cert:\\CurrentUser\\Root"

    Write-Host "Downloading certificate from $CertUrl ..."
    Invoke-WebRequest -Uri $CertUrl -OutFile $CertPath

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $ActualSha256 = [BitConverter]::ToString($sha256.ComputeHash($cert.RawData)).Replace("-", "").ToUpper()
    if ($ActualSha256 -ne $ExpectedSha256) {{
      throw "SHA-256 fingerprint mismatch. Expected $ExpectedSha256 but got $ActualSha256."
    }}

    Write-Host "Subject:    $($cert.Subject)"
    Write-Host "Issuer:     $($cert.Issuer)"
    Write-Host "Thumbprint: $($cert.Thumbprint)"
    Write-Host "Not After:  $($cert.NotAfter)"

    Write-Host "Installing certificate into CurrentUser Trusted Root store..."
    Import-Certificate -FilePath $CertPath -CertStoreLocation $StoreLocation | Out-Null
    Write-Host "Done. Restart your browser."
    Write-Host "Opening verification page..."
    Start-Process "{base_url()}/verify"
    """
    return script_response(script, "windows.ps1")


@app.route("/download/windows.cmd")
def windows_cmd():
    script = f"""
    @echo off
    setlocal

    set "SCRIPT_URL={base_url()}/download/windows.ps1"
    set "SCRIPT_PATH=%TEMP%\\cato-cert-install.ps1"

    echo Downloading the Windows certificate installer...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '%SCRIPT_URL%' -OutFile '%SCRIPT_PATH%'"
    if errorlevel 1 (
      echo.
      echo Download failed. Check that you are connected to the onboarding network.
      pause
      exit /b 1
    )

    echo Running the certificate installer...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_PATH%"
    set "INSTALL_RESULT=%ERRORLEVEL%"

    echo.
    if not "%INSTALL_RESULT%"=="0" (
      echo Install failed. Leave this window open and contact support: {SUPPORT_EMAIL}
      pause
      exit /b %INSTALL_RESULT%
    )

    echo Certificate install completed.
    echo Restart browsers that were already open.
    pause
    """
    return script_response(script, "windows.cmd")


@app.route("/download/macos.sh")
def macos_script():
    script = f"""
    #!/usr/bin/env bash
    set -euo pipefail

    CERT_URL="{base_url()}/download/cert"
    EXPECTED_SHA256="{cert_sha256_hex().lower()}"
    OPENSSL_INFORM="{cert_openssl_inform()}"
    CERT_PATH="/tmp/{CERT_FILENAME}"

    if [[ $EUID -ne 0 ]]; then
      echo "Please run with sudo so the certificate can be installed into the System keychain."
      exit 1
    fi

    echo "Downloading certificate from ${{CERT_URL}} ..."
    curl -fsSL "${{CERT_URL}}" -o "${{CERT_PATH}}"

    ACTUAL_SHA256="$(openssl x509 -inform "${{OPENSSL_INFORM}}" -in "${{CERT_PATH}}" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n')"
    if [[ "${{ACTUAL_SHA256}}" != "${{EXPECTED_SHA256}}" ]]; then
      echo "SHA-256 fingerprint mismatch. Refusing to install."
      echo "Expected: ${{EXPECTED_SHA256}}"
      echo "Actual:   ${{ACTUAL_SHA256}}"
      exit 1
    fi

    openssl x509 -inform "${{OPENSSL_INFORM}}" -in "${{CERT_PATH}}" -noout -subject -issuer -fingerprint -sha256 -dates

    echo "Installing and trusting certificate in System keychain..."
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${{CERT_PATH}}"
    echo "Done. Restart browsers that were already open."
    """
    return script_response(script, "macos.sh")


@app.route("/download/linux.sh")
def linux_script():
    script = f"""
    #!/usr/bin/env bash
    set -euo pipefail

    CERT_URL="{base_url()}/download/cert"
    EXPECTED_SHA256="{cert_sha256_hex().lower()}"
    OPENSSL_INFORM="{cert_openssl_inform()}"
    CERT_NAME="company-cato-root-ca.crt"
    TMP_CERT="/tmp/{CERT_FILENAME}"
    PEM_CERT="/tmp/${{CERT_NAME}}"

    if [[ $EUID -ne 0 ]]; then
      echo "Please run with sudo."
      exit 1
    fi

    curl -fsSL "${{CERT_URL}}" -o "${{TMP_CERT}}"
    ACTUAL_SHA256="$(openssl x509 -inform "${{OPENSSL_INFORM}}" -in "${{TMP_CERT}}" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n')"
    if [[ "${{ACTUAL_SHA256}}" != "${{EXPECTED_SHA256}}" ]]; then
      echo "SHA-256 fingerprint mismatch. Refusing to install."
      exit 1
    fi

    openssl x509 -inform "${{OPENSSL_INFORM}}" -in "${{TMP_CERT}}" -noout -subject -issuer -fingerprint -sha256 -dates
    openssl x509 -inform "${{OPENSSL_INFORM}}" -in "${{TMP_CERT}}" -out "${{PEM_CERT}}"

    if [[ -d /usr/local/share/ca-certificates ]]; then
      cp "${{PEM_CERT}}" "/usr/local/share/ca-certificates/${{CERT_NAME}}"
      update-ca-certificates
    elif [[ -d /etc/pki/ca-trust/source/anchors ]]; then
      cp "${{PEM_CERT}}" "/etc/pki/ca-trust/source/anchors/${{CERT_NAME}}"
      update-ca-trust
    else
      echo "Unsupported Linux CA trust layout. Install manually."
      exit 1
    fi

    echo "Done. Restart browsers/apps that were open."
    """
    return script_response(script, "linux.sh")


@app.route("/download/firefox.sh")
def firefox_script():
    script = f"""
    #!/usr/bin/env bash
    set -euo pipefail

    CERT_URL="{base_url()}/download/cert"
    EXPECTED_SHA256="{cert_sha256_hex().lower()}"
    OPENSSL_INFORM="{cert_openssl_inform()}"
    CERT_PATH="/tmp/{CERT_FILENAME}"
    CERT_NICKNAME="{CERT_DISPLAY_NAME}"

    if ! command -v certutil >/dev/null 2>&1; then
      echo "certutil is required."
      echo "macOS: brew install nss"
      echo "Debian/Ubuntu: sudo apt install libnss3-tools"
      exit 1
    fi

    curl -fsSL "${{CERT_URL}}" -o "${{CERT_PATH}}"
    ACTUAL_SHA256="$(openssl x509 -inform "${{OPENSSL_INFORM}}" -in "${{CERT_PATH}}" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \\n')"

    if [[ "${{ACTUAL_SHA256}}" != "${{EXPECTED_SHA256}}" ]]; then
      echo "SHA-256 fingerprint mismatch. Refusing to install."
      exit 1
    fi

    found=0
    for profile in "$HOME"/.mozilla/firefox/*.default* "$HOME"/Library/Application\\ Support/Firefox/Profiles/*.default*; do
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
    return script_response(script, "firefox.sh")


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
    app.run(host=HOST, port=PORT)
