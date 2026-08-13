import unittest
from unittest.mock import patch

from mpvm_jira.mpvm import (
    MaxPatrolClient,
    apply_pdql_filter,
    asset_filter_expression,
)


class MpvmAssetFilterTests(unittest.TestCase):
    def _client(self):
        return MaxPatrolClient(
            {
                "base_url": "https://mpvm.example.org",
                "assets_pdql": "Select(@Host as AssetId, Host.FQDN as Fqdn)",
                "vulnerabilities_pdql": (
                    "Filter(Host.@Vulners.Status in ['new']) | "
                    "Select(@Host as AssetId, Host.@Vulners.Id as "
                    "VulnerabilityId, "
                    "Host.@Vulners.Status as Status)"
                ),
                "software_vulnerabilities_pdql": (
                    "Filter(Host.Softs.@Vulners.Status in ['new']) | "
                    "Select(@Host as AssetId, Host.Softs.@Vulners.Id as "
                    "VulnerabilityId, Host.Softs.Name as PackageName, "
                    "Host.Softs.Version as PackageVersion, "
                    "Host.Softs.@Vulners.Status as Status)"
                ),
                "active_statuses": ["new"],
            }
        )

    def test_fqdn_filter_is_added_to_all_pdql_queries(self):
        client = self._client()
        queries = []

        def fetch(pdql):
            queries.append(pdql)
            if len(queries) == 1:
                return [{"AssetId": "asset-1", "Fqdn": "srv.example.org"}]
            if "Host.Softs" in pdql:
                return [
                    {
                        "AssetId": "asset-1",
                        "VulnerabilityId": "PT-1",
                        "PackageName": "openssl",
                        "PackageVersion": "3.0.11",
                        "Status": "new",
                    }
                ]
            return [
                {
                    "AssetId": "asset-1",
                    "VulnerabilityId": "PT-1",
                    "Status": "new",
                }
            ]

        client.fetch_pdql_records = fetch
        client.iter_pdql_records = lambda pdql: iter(fetch(pdql))
        snapshot = client.collect_snapshot(fqdn="Srv.Example.org.")

        prefix = "Filter(Host.FQDN = 'srv.example.org') | "
        self.assertTrue(queries[0].startswith(prefix))
        self.assertTrue(
            queries[1].startswith(
                "Filter((Host.FQDN = 'srv.example.org') and "
                "(Host.@Vulners.Status in ['new'])) | "
            )
        )
        self.assertNotIn("| Filter(", queries[1])
        self.assertTrue(
            queries[2].startswith(
                "Filter((Host.FQDN = 'srv.example.org') and "
                "(Host.Softs.@Vulners.Status in ['new'])) | "
            )
        )
        self.assertEqual(
            snapshot["filters"]["fqdns"],
            ["srv.example.org"],
        )
        self.assertEqual(
            snapshot["statistics"]["assets_with_vulnerabilities"], 1
        )
        self.assertEqual(
            snapshot["assets"][0]["vulnerabilities"][0]["packages"],
            [{"name": "openssl", "version": "3.0.11"}],
        )

    def test_authentication_uses_reference_token(self):
        client = self._client()
        client.config["access_token_env"] = "MPVM_TEST_ACCESS_TOKEN"

        with patch.dict(
            "os.environ",
            {"MPVM_TEST_ACCESS_TOKEN": "test-reference-token"},
        ):
            client.authenticate()

        self.assertEqual(
            client.session.headers["Authorization"],
            "Bearer test-reference-token",
        )

    def test_ip_filter_uses_ip_address_collection(self):
        expression, metadata = asset_filter_expression(ip="2001:0db8::1")
        self.assertEqual(expression, "Host.@IpAddresses contains 2001:db8::1")
        self.assertEqual(metadata, {"ip_selectors": ["2001:db8::1"]})

    def test_multiple_fqdns_use_pdql_in_expression(self):
        expression, metadata = asset_filter_expression(
            fqdn=["Srv1.Example.org.", "srv2.example.org"]
        )
        self.assertEqual(
            expression,
            "Host.FQDN in ['srv1.example.org', 'srv2.example.org']",
        )
        self.assertEqual(
            metadata,
            {"fqdns": ["srv1.example.org", "srv2.example.org"]},
        )

    def test_multiple_ip_addresses_use_intersect_expression(self):
        expression, metadata = asset_filter_expression(
            ip=["192.0.2.10", "192.0.2.11"]
        )
        self.assertEqual(
            expression,
            "Host.@IpAddresses intersect [192.0.2.10, 192.0.2.11]",
        )
        self.assertEqual(
            metadata,
            {"ip_selectors": ["192.0.2.10", "192.0.2.11"]},
        )

    def test_ip_range_is_converted_to_minimal_cidr_filters(self):
        expression, metadata = asset_filter_expression(
            ip=["192.0.2.10-192.0.2.15"]
        )
        self.assertEqual(
            expression,
            "(Host.@IpAddresses.Item in 192.0.2.10/31 or "
            "Host.@IpAddresses.Item in 192.0.2.12/30)",
        )
        self.assertEqual(
            metadata,
            {"ip_selectors": ["192.0.2.10-192.0.2.15"]},
        )

    def test_duplicate_filter_values_are_removed(self):
        expression, metadata = asset_filter_expression(
            fqdn=["srv.example.org", "SRV.EXAMPLE.ORG."]
        )
        self.assertEqual(expression, "Host.FQDN = 'srv.example.org'")
        self.assertEqual(metadata, {"fqdns": ["srv.example.org"]})

    def test_fqdn_and_ip_cannot_be_used_together(self):
        with self.assertRaisesRegex(
            ValueError, "нельзя использовать одновременно"
        ):
            asset_filter_expression(fqdn="srv.example.org", ip="192.0.2.10")

    def test_invalid_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Некорректный IP-адрес"):
            asset_filter_expression(ip="192.0.2.999")

    def test_reversed_ip_range_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "не больше конца"):
            asset_filter_expression(ip="192.0.2.20-192.0.2.10")

    def test_mixed_ip_versions_in_range_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "одну версию IP"):
            asset_filter_expression(ip="192.0.2.10-2001:db8::1")

    def test_multiple_matching_assets_are_allowed(self):
        client = self._client()
        client.config["software_vulnerabilities_pdql"] = ""

        def fetch(pdql):
            if "@Vulners.Id" in pdql:
                return [
                    {
                        "AssetId": "asset-1",
                        "VulnerabilityId": "PT-1",
                        "Status": "new",
                    },
                    {
                        "AssetId": "asset-2",
                        "VulnerabilityId": "PT-2",
                        "Status": "new",
                    },
                ]
            return [
                {"AssetId": "asset-1", "Fqdn": "srv1.example.org"},
                {"AssetId": "asset-2", "Fqdn": "srv2.example.org"},
            ]

        client.fetch_pdql_records = fetch
        client.iter_pdql_records = lambda pdql: iter(fetch(pdql))

        snapshot = client.collect_snapshot(
            fqdn=["srv1.example.org", "srv2.example.org"]
        )

        self.assertEqual(snapshot["statistics"]["assets_total"], 2)
        self.assertEqual(
            snapshot["statistics"]["assets_with_vulnerabilities"],
            2,
        )

    def test_filter_is_merged_with_existing_leading_filter(self):
        query = "Filter(Host.Score > Calc(5 + 2)) | Select(@Host)"
        result = apply_pdql_filter(query, "Host.FQDN = 'srv.example.org'")
        self.assertEqual(
            result,
            "Filter((Host.FQDN = 'srv.example.org') and "
            "(Host.Score > Calc(5 + 2))) "
            "| Select(@Host)",
        )


if __name__ == "__main__":
    unittest.main()
