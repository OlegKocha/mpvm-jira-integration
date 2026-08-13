"""Проверки разделения интеграции на пакеты MaxPatrol VM и Jira."""

import importlib.util
import unittest

from mpvm_jira.jira import JiraClient, sync_latest_to_jira
from mpvm_jira.mpvm import MaxPatrolClient, export_snapshot


class PackageStructureTests(unittest.TestCase):
    """Проверяет публичные интерфейсы и отсутствие старых общих модулей."""

    def test_mpvm_interfaces_are_exposed_by_mpvm_package(self):
        self.assertTrue(MaxPatrolClient.__module__.startswith("mpvm_jira.mpvm."))
        self.assertEqual(export_snapshot.__module__, "mpvm_jira.mpvm.service")

    def test_jira_interfaces_are_exposed_by_jira_package(self):
        self.assertTrue(JiraClient.__module__.startswith("mpvm_jira.jira."))
        self.assertEqual(sync_latest_to_jira.__module__, "mpvm_jira.jira.service")

    def test_old_shared_modules_are_absent(self):
        old_modules = (
            "mpvm_jira.criticality",
            "mpvm_jira.service",
            "mpvm_jira.snapshot",
            "mpvm_jira.xlsx_export",
        )
        for module_name in old_modules:
            with self.subTest(module_name=module_name):
                self.assertIsNone(importlib.util.find_spec(module_name))


if __name__ == "__main__":
    unittest.main()
