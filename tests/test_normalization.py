import unittest
from datetime import datetime, timezone

from mpvm_jira.mpvm import build_snapshot_from_records


class NormalizationTests(unittest.TestCase):
    def test_records_are_grouped_and_fixed_is_excluded(self):
        assets = [
            {
                "AssetId": "asset-1",
                "Fqdn": "srv.example.org",
                "IpAddresses": "192.0.2.10 | 192.0.2.11",
                "AssetImportance": "Medium",
                "OsName": "Debian",
                "OsVersion": "12",
            }
        ]
        vulnerabilities = [
            {
                "AssetId": "asset-1",
                "VulnerabilityId": "PT-1",
                "Cves": ["CVE-2026-1234"],
                "Identifiers": {"displayName": "BDU:2026-00001"},
                "CvssScore": "8,5",
                "Severity": "High",
                "Description": "Описание",
                "HowToFix": "Обновить",
                "Status": "new",
            },
            {
                "AssetId": "asset-1",
                "VulnerabilityId": "PT-1",
                "Identifiers": {"displayName": "CVE-2026-9999"},
                "Status": "new",
            },
            {
                "AssetId": "asset-1",
                "VulnerabilityId": "PT-2",
                "Status": "fixed",
            },
        ]
        software_vulnerabilities = [
            {
                "AssetId": "asset-1",
                "VulnerabilityId": "PT-1",
                "PackageName": "openssl",
                "PackageVersion": "3.0.11-1",
                "Status": "new",
            },
            {
                "AssetId": "asset-1",
                "VulnerabilityId": "PT-1",
                "PackageName": "libssl3",
                "PackageVersion": "3.0.11-1",
                "Status": "new",
            },
            {
                "AssetId": "asset-1",
                "VulnerabilityId": "PT-2",
                "PackageName": "obsolete",
                "PackageVersion": "1.0",
                "Status": "fixed",
            },
        ]
        result = build_snapshot_from_records(
            assets,
            vulnerabilities,
            software_vulnerabilities,
            source_url="https://mpvm.example.org",
            active_statuses=["new"],
            generated_at=datetime(2026, 8, 5, tzinfo=timezone.utc),
        )
        self.assertEqual(result["statistics"]["assets_total"], 1)
        self.assertEqual(result["statistics"]["vulnerabilities_total"], 1)
        asset = result["assets"][0]
        self.assertEqual(
            asset["jira_summary"], "srv.example.org (192.0.2.10, 192.0.2.11)"
        )
        self.assertEqual(asset["operating_system"], "Debian 12")
        self.assertEqual(
            asset["vulnerabilities"][0]["criticality"], "Высокий (8.5)"
        )
        self.assertEqual(
            asset["vulnerabilities"][0]["cves"],
            ["CVE-2026-1234", "CVE-2026-9999"],
        )
        self.assertEqual(
            asset["vulnerabilities"][0]["bdus"], ["BDU:2026-00001"]
        )
        self.assertEqual(
            asset["vulnerabilities"][0]["packages"],
            [
                {"name": "libssl3", "version": "3.0.11-1"},
                {"name": "openssl", "version": "3.0.11-1"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
