import unittest

from app import app, cert_material, cert_sha256_hex


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
        self.assertIn("Download Windows Installer", body)
        self.assertIn("SHA-256 fingerprint", body)

    def test_healthz_loads_certificate(self):
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_favicon_returns_fast_empty_response(self):
        response = self.client.get("/favicon.ico")

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.get_data(), b"")

    def test_generated_helpers_verify_certificate_fingerprint(self):
        expected = cert_sha256_hex()

        for path in (
            "/download/windows.cmd",
            "/download/windows.ps1",
            "/download/macos.sh",
            "/download/linux.sh",
            "/download/firefox.sh",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                body = response.get_data(as_text=True)

                self.assertEqual(response.status_code, 200)
                if path.endswith(".cmd"):
                    self.assertIn("/download/windows.ps1", body)
                else:
                    self.assertIn(expected.lower(), body.lower())
                self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_windows_helper_installs_to_local_machine_root(self):
        response = self.client.get("/download/windows.ps1")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Cert:\\LocalMachine\\Root", body)
        self.assertIn("Administrator", body)
        self.assertIn("Local Computer Trusted Root", body)

    def test_windows_bootstrapper_requests_elevation(self):
        response = self.client.get("/download/windows.cmd")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Verb RunAs", body)
        self.assertIn("administrator approval", body)

    def test_mobileconfig_downloads_profile(self):
        response = self.client.get("/download/mobileconfig")

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/x-apple-aspen-config", response.content_type)
        self.assertIn("PayloadType", response.get_data(as_text=True))

    def test_verify_page_explains_failed_verification(self):
        response = self.client.get("/verify")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("install did not complete successfully", body)
        self.assertIn("Contact", body)

    def test_verify_reuses_cached_certificate_material(self):
        cert_material.cache_clear()

        first = self.client.get("/verify")
        second = self.client.get("/verify")
        cache_info = cert_material.cache_info()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(cache_info.misses, 1)
        self.assertGreaterEqual(cache_info.hits, 1)

    def test_internal_errors_show_helpdesk_page(self):
        original = app.view_functions["healthz"]

        def broken_healthz():
            raise RuntimeError("forced test failure")

        app.view_functions["healthz"] = broken_healthz
        try:
            response = self.client.get("/healthz")
        finally:
            app.view_functions["healthz"] = original

        self.assertEqual(response.status_code, 500)
        body = response.get_data(as_text=True)
        self.assertIn("Verification could not be completed", body)
        self.assertIn("Contact Helpdesk", body)


if __name__ == "__main__":
    unittest.main()
