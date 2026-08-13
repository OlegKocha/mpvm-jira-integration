import tempfile
import unittest
from pathlib import Path

from mpvm_jira.jira import (
    JiraClient,
    build_adf_description,
    build_wiki_description,
    vulnerability_summary,
)
from mpvm_jira.models import Asset, Vulnerability


class FakeResponse:
    status_code = 200
    ok = True
    text = '[{"id":"42","filename":"report.xlsx"}]'

    def json(self):
        return [{"id": "42", "filename": "report.xlsx"}]


class FakeSession:
    def __init__(self):
        self.call = None

    def post(self, url, **kwargs):
        self.call = (url, kwargs)
        return FakeResponse()


class JiraFormatTests(unittest.TestCase):
    def setUp(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.asset = Asset(
            "asset-1",
            fqdn="srv.example.org",
            ip_addresses=("192.0.2.10",),
            vulnerabilities=[
                Vulnerability(cvss_score=9.8, severity="Critical", cvss_vector=vector),
                Vulnerability(cvss_score=8.5, severity="High", cvss_vector=vector),
                Vulnerability(cvss_score=5.5, severity="Medium", cvss_vector=vector),
                Vulnerability(cvss_score=2.1, severity="Low", cvss_vector=vector),
                Vulnerability(cvss_score=9.1, severity="Critical", cvss_vector=""),
            ],
        )

    def test_summary_categories_are_mutually_exclusive(self):
        rows = dict(vulnerability_summary(self.asset.vulnerabilities))
        self.assertEqual(rows["Всего уязвимостей"], 5)
        self.assertEqual(rows["Критического уровня"], 1)
        self.assertEqual(rows["Высокого уровня"], 1)
        self.assertEqual(rows["Среднего уровня"], 1)
        self.assertEqual(rows["Низкого уровня"], 1)
        self.assertEqual(rows["Без критичности (без вектора CVSS)"], 1)
        self.assertEqual(
            sum(value for key, value in rows.items() if key != "Всего уязвимостей"),
            5,
        )

    def test_summary_contains_only_selected_criticality_rows(self):
        rows = vulnerability_summary(
            self.asset.vulnerabilities,
            ["Critical", "High"],
        )
        self.assertEqual(
            rows,
            (
                ("Всего уязвимостей", 2),
                ("Критического уровня", 1),
                ("Высокого уровня", 1),
            ),
        )

        adf = build_adf_description(self.asset, ["Critical", "High"])
        self.assertEqual(len(adf["content"][3]["content"]), 3)
        self.assertNotIn("Среднего уровня", str(adf))

        wiki = build_wiki_description(self.asset, ["Critical", "High"])
        self.assertIn("|*Всего уязвимостей*|*2*|", wiki)
        self.assertNotIn("Низкого уровня", wiki)
        self.assertNotIn("Без критичности", wiki)

    def test_adf_contains_summary_table_without_snapshot_name(self):
        document = build_adf_description(self.asset)
        self.assertEqual(document["type"], "doc")
        self.assertEqual(len(document["content"]), 5)
        table = document["content"][3]
        self.assertEqual(table["type"], "table")
        self.assertEqual(len(table["content"]), 6)
        first_row = table["content"][0]["content"]
        self.assertEqual(first_row[0]["type"], "tableCell")
        self.assertEqual(
            first_row[0]["content"][0]["content"][0]["text"],
            "Всего уязвимостей",
        )
        self.assertEqual(first_row[1]["content"][0]["content"][0]["text"], "5")
        self.assertEqual(
            first_row[0]["content"][0]["content"][0]["marks"],
            [{"type": "strong"}],
        )
        self.assertEqual(
            first_row[1]["content"][0]["content"][0]["marks"],
            [{"type": "strong"}],
        )
        expected_colors = (
            "#FF2400",
            "#D32F2F",
            "#B86E00",
            "#0052CC",
        )
        for row, expected_color in zip(table["content"][1:5], expected_colors):
            for cell in row["content"]:
                text_node = cell["content"][0]["content"][0]
                self.assertEqual(
                    text_node["marks"],
                    [
                        {
                            "type": "textColor",
                            "attrs": {"color": expected_color},
                        }
                    ],
                )
        unclassified_row = table["content"][5]
        for cell in unclassified_row["content"]:
            text_node = cell["content"][0]["content"][0]
            self.assertNotIn("marks", text_node)
        self.assertIn("Актив из MaxPatrol VM", str(document))
        self.assertNotIn("Категория", str(table))
        self.assertNotIn("Количество", str(table))
        self.assertNotIn("JSON-снимок", str(document))
        self.assertIn("Подробная информация", str(document))

    def test_wiki_description_contains_summary_table_without_snapshot_name(
        self,
    ):
        description = build_wiki_description(self.asset)
        self.assertIn("Источник: MaxPatrol VM.", description)
        self.assertIn(
            "Актив из MaxPatrol VM: srv.example.org (192.0.2.10).", description
        )
        self.assertNotIn("||Категория||Количество||", description)
        self.assertIn("|*Всего уязвимостей*|*5*|", description)
        self.assertIn(
            "|{color:#FF2400}Критического уровня{color}|{color:#FF2400}1{color}|",
            description,
        )
        self.assertIn(
            "|{color:#D32F2F}Высокого уровня{color}|{color:#D32F2F}1{color}|",
            description,
        )
        self.assertIn(
            "|{color:#B86E00}Среднего уровня{color}|{color:#B86E00}1{color}|",
            description,
        )
        self.assertIn(
            "|{color:#0052CC}Низкого уровня{color}|{color:#0052CC}1{color}|",
            description,
        )
        self.assertIn("|Без критичности (без вектора CVSS)|1|", description)
        self.assertNotIn("JSON-снимок", description)
        self.assertTrue(description.endswith("находятся в XLSX-вложении."))

    def test_attachment_uses_multipart_and_csrf_header(self):
        client = JiraClient.__new__(JiraClient)
        client.base_url = "https://jira.example.org"
        client.api_version = "2"
        client.timeout = 60
        client.verify = True
        client.session = FakeSession()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.xlsx"
            path.write_bytes(b"xlsx")
            result = client.attach_file("SEC-1", path)
        self.assertEqual(result["id"], "42")
        url, kwargs = client.session.call
        self.assertTrue(url.endswith("/issue/SEC-1/attachments"))
        self.assertEqual(kwargs["headers"]["X-Atlassian-Token"], "no-check")
        filename, _, content_type = kwargs["files"]["file"]
        self.assertEqual(filename, "report.xlsx")
        self.assertEqual(
            content_type,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    def test_description_format_depends_on_api_version_only(self):
        client = JiraClient.__new__(JiraClient)
        client.api_version = "2"
        client.deployment = "cloud"
        self.assertIsInstance(client._description(self.asset), str)

        client.api_version = "3"
        client.deployment = "data_center"
        self.assertIsInstance(client._description(self.asset), dict)


if __name__ == "__main__":
    unittest.main()
