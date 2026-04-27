import unittest

from app import app, cert_sha256_hex


class PortalSmokeTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_homepage_renders_certificate_details(self):
        response = self.client.get(
            "/",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("BYOD Certificate Setup", body)
        self.assertIn("Download Windows Helper", body)
        self.assertIn("SHA-256 fingerprint", body)

    def test_healthz_loads_certificate(self):
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_generated_helpers_verify_certificate_fingerprint(self):
        expected = cert_sha256_hex()

        for path in (
            "/download/windows.ps1",
            "/download/macos.sh",
            "/download/linux.sh",
            "/download/firefox.sh",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                body = response.get_data(as_text=True)

                self.assertEqual(response.status_code, 200)
                self.assertIn(expected.lower(), body.lower())
                self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_mobileconfig_downloads_profile(self):
        response = self.client.get("/download/mobileconfig")

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/x-apple-aspen-config", response.content_type)
        self.assertIn("PayloadType", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
