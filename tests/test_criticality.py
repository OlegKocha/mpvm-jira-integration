import unittest

from mpvm_jira.jira.criticality import (
    filter_vulnerabilities,
    normalize_criticalities,
    normalize_criticality,
    vulnerability_criticality,
)
from mpvm_jira.models import Vulnerability


class CriticalityTests(unittest.TestCase):
    def test_values_are_case_insensitive_deduplicated_and_ordered(self):
        selected = normalize_criticalities(
            ["low", "CRITICAL", "Low", "non-CRIT"]
        )
        self.assertEqual(selected, ("Critical", "Low", "Non-crit"))

    def test_unknown_value_is_rejected_with_allowed_values(self):
        with self.assertRaisesRegex(ValueError, "Допустимы: Critical"):
            normalize_criticality("urgent")

    def test_missing_vector_is_non_criticality_even_with_score(self):
        vulnerability = Vulnerability(
            severity="Critical",
            cvss_score=9.8,
            cvss_vector="",
        )
        self.assertEqual(
            vulnerability_criticality(vulnerability),
            "Non-crit",
        )

    def test_filter_returns_only_selected_levels(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vulnerabilities = [
            Vulnerability(severity="Critical", cvss_vector=vector),
            Vulnerability(severity="High", cvss_vector=vector),
            Vulnerability(severity="Medium", cvss_vector=vector),
            Vulnerability(severity="Low", cvss_vector=vector),
            Vulnerability(severity="Critical", cvss_vector=""),
        ]
        filtered = filter_vulnerabilities(
            vulnerabilities,
            ["High", "Non-crit"],
        )
        self.assertEqual(filtered, [vulnerabilities[1], vulnerabilities[4]])

    def test_no_filter_returns_all_vulnerabilities(self):
        vulnerabilities = [Vulnerability(), Vulnerability()]
        self.assertEqual(
            filter_vulnerabilities(vulnerabilities, None),
            vulnerabilities,
        )


if __name__ == "__main__":
    unittest.main()
