import unittest

from mpvm_jira.models import (
    Asset,
    SoftwarePackage,
    Vulnerability,
    localized_severity,
)


class ModelTests(unittest.TestCase):
    def test_asset_title_prefers_fqdn_and_adds_ips(self):
        asset = Asset(
            "id-1",
            fqdn="srv.example.org",
            ip_addresses=("192.0.2.1", "2001:db8::1"),
        )
        self.assertEqual(
            asset.title, "srv.example.org (192.0.2.1, 2001:db8::1)"
        )

    def test_asset_title_falls_back_to_ip(self):
        self.assertEqual(
            Asset("id-1", ip_addresses=("192.0.2.2",)).title, "192.0.2.2"
        )

    def test_asset_title_excludes_non_actionable_local_addresses(self):
        addresses = (
            "::1",
            "192.0.2.100",
            "127.0.0.1",
            "fe80::250:56ff:feaf:94d3",
        )
        asset = Asset("id-1", fqdn="bind.example.org", ip_addresses=addresses)
        self.assertEqual(asset.title, "bind.example.org (192.0.2.100)")
        self.assertEqual(asset.as_dict()["ip_addresses"], list(addresses))

    def test_asset_title_uses_id_when_only_filtered_addresses_exist(self):
        asset = Asset(
            "id-1", ip_addresses=("0.0.0.0", "::", "127.0.0.1", "::1")
        )
        self.assertEqual(asset.title, "Актив id-1")

    def test_criticality_is_localized(self):
        vulnerability = Vulnerability(
            cvss_score=8.5, severity="High", bdus=("BDU:2026-00001",)
        )
        self.assertEqual(vulnerability.criticality, "Высокий (8.5)")
        self.assertEqual(localized_severity("", 9.2), "Критический")
        self.assertEqual(vulnerability.as_dict()["bdus"], ["BDU:2026-00001"])

    def test_operating_system_does_not_repeat_embedded_version(self):
        self.assertEqual(
            Asset(
                "id-1",
                os_name="Windows 10",
                os_version="10",
            ).operating_system,
            "Windows 10",
        )

    def test_package_columns_keep_names_and_versions_aligned(self):
        vulnerability = Vulnerability(
            packages=(
                SoftwarePackage("openssl", "3.0.11"),
                SoftwarePackage("libssl3", ""),
            )
        )
        self.assertEqual(vulnerability.package_names, "openssl; libssl3")
        self.assertEqual(vulnerability.package_versions, "3.0.11; -")


if __name__ == "__main__":
    unittest.main()
