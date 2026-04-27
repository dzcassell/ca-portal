# Cato BYOD Certificate Portal

Dockerized onboarding portal for unmanaged BYOD devices behind Cato Sockets when TLS inspection requires users to trust the Cato TLS resign/root certificate.

The portal hosts the bundled Cato root certificate, displays certificate metadata and SHA-256 fingerprint verification, and provides platform-specific install instructions plus helper scripts where reasonable.

## What this project does

- Hosts the Cato root certificate for download
- Displays certificate subject, issuer, validity dates, serial number, SHA-1, and SHA-256 fingerprint
- Generates helper scripts dynamically using the hostname/IP the user actually visited
- Validates certificate SHA-256 fingerprint before helper scripts install anything
- Provides installation guidance for:
  - Windows
  - macOS
  - iOS / iPadOS
  - Android
  - Linux
  - Firefox
- Generates an Apple `.mobileconfig` profile dynamically for iOS/iPadOS/macOS
- Runs as a small Flask app in Docker

## Bundled certificate

The bundled certificate is stored at:

```text
certs/cato-root-ca.cer
```

Expected SHA-256 fingerprint:

```text
03:CB:01:60:35:6C:41:5A:E3:7F:B5:75:7C:4F:C6:2A:C1:E0:79:AC:16:28:94:41:5B:FA:A8:B2:7E:BF:D2:B1
```

The app computes certificate details at runtime from the actual certificate file on disk. If you replace the certificate later, the UI and helper scripts update automatically.

## Run locally

```bash
docker compose up -d --build
```

Open:

```text
http://<server-ip>:8080/
```

For example:

```text
http://192.168.40.25:8080/
```

## Recommended deployment model

Use a friendly DNS name on the onboarding/BYOD VLAN, for example:

```text
http://cert.company.local/
http://byod.company.local/
```

Serve the onboarding page over plain HTTP on the onboarding VLAN, or HTTPS with a publicly trusted certificate. Do **not** serve this portal using the same private/Cato root certificate that users have not installed yet, or you create a certificate trust chicken-and-egg problem.

## Configure

The app can be configured with environment variables in `docker-compose.yml` or `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `PORTAL_NAME` | `Cato BYOD Certificate Setup` | Browser/page title |
| `COMPANY_NAME` | `Example Company` | Company name shown in UI |
| `CERT_DISPLAY_NAME` | `Cato Networks Root CA` | Friendly cert name shown in UI/scripts |
| `CERT_FILENAME` | `cato-root-ca.cer` | Certificate file under `/app/certs` |
| `SUPPORT_EMAIL` | `helpdesk@example.com` | Help desk email shown in footer |
| `VERIFY_URL` | `https://example.com` | HTTPS site users can open to validate behavior |
| `IOS_PROFILE_IDENTIFIER` | `com.example.cato.rootca` | Payload identifier prefix for mobileconfig |

Example:

```yaml
services:
  ca-portal:
    build: .
    ports:
      - "8080:8080"
    environment:
      COMPANY_NAME: "Acme Corp"
      SUPPORT_EMAIL: "helpdesk@acme.example"
      VERIFY_URL: "https://www.example.com"
```

## Download endpoints

```text
/download/cert
/download/windows.ps1
/download/macos.sh
/download/linux.sh
/download/firefox.sh
/download/mobileconfig
```

Script downloads are generated dynamically so the install helpers use the same base URL the user used to access the portal.

## Platform notes

### Windows

The PowerShell helper downloads the certificate, verifies the SHA-256 fingerprint, and imports the certificate into the current user's Trusted Root Certification Authorities store.

Manual installation is also documented in the UI.

### macOS

The macOS helper downloads the certificate, verifies the SHA-256 fingerprint, and uses `security add-trusted-cert` to trust it in the System keychain. The user still needs administrator approval.

### iOS / iPadOS

The portal generates a `.mobileconfig` profile containing the bundled certificate. iOS/iPadOS still requires the user to manually install the profile and then enable full trust under:

```text
Settings → General → About → Certificate Trust Settings
```

### Android

Android support varies by OS version, browser, and app behavior. Some apps do not trust user-installed CAs. The portal provides manual installation guidance.

### Firefox

Firefox may use its own certificate store. The Firefox helper uses `certutil` from NSS to import the certificate into detected Firefox profiles. Users may still need to import manually depending on profile and platform behavior.

### Linux

The Linux helper supports Debian/Ubuntu-style `update-ca-certificates` and RHEL/Fedora-style `update-ca-trust`.

## Security and privacy notes

Installing a trusted root CA is a sensitive operation. This portal intentionally makes the trust change visible and user-approved. It does not attempt silent or stealth installation.

Recommended policy model:

1. Put unmanaged BYOD devices on an onboarding or BYOD VLAN/SSID.
2. Publish this portal at an easy URL.
3. Let users explicitly install and trust the certificate.
4. Keep devices that do not install the certificate on guest/bypass policy.
5. Use MDM/GPO/RMM for managed corporate devices whenever possible.
6. Consider browser-based access methods for unmanaged BYOD when full-device trust-store modification is not acceptable.

## Local development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
CERT_DIR=./certs python app.py
```

Then open:

```text
http://127.0.0.1:8080/
```

## Publish to GitHub

For a newly created GitHub repo:

```bash
git remote add origin git@github.com:dzcassell/ca-portal.git
git branch -M main
git push -u origin main
```

Or HTTPS:

```bash
git remote add origin https://github.com/dzcassell/ca-portal.git
git branch -M main
git push -u origin main
```

## Files

```text
.
├── Dockerfile
├── docker-compose.yml
├── README.md
├── requirements.txt
├── app.py
├── certs/
│   └── cato-root-ca.cer
└── templates/
    ├── _cert_card.html
    ├── android.html
    ├── base.html
    ├── firefox.html
    ├── index.html
    ├── ios.html
    ├── linux.html
    ├── macos.html
    ├── verify.html
    └── windows.html
```
