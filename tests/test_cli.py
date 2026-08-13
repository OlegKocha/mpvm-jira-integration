import unittest
from pathlib import Path
from unittest.mock import patch

from mpvm_jira.cli import build_parser, main
from mpvm_jira.setup import run_setup


class CliHelpTests(unittest.TestCase):
    def test_general_help_lists_subcommand_flags(self):
        help_text = build_parser().format_help()
        self.assertIn("setup", help_text)
        self.assertIn("export --fqdn FQDN [FQDN ...]", help_text)
        self.assertIn(
            "export --ip IP_OR_RANGE [IP_OR_RANGE ...]",
            help_text,
        )
        self.assertIn("sync --dry-run", help_text)
        self.assertIn("run --fqdn FQDN [FQDN ...]", help_text)
        self.assertIn(
            "run --ip IP_OR_RANGE [IP_OR_RANGE ...]",
            help_text,
        )
        self.assertIn("run --dry-run", help_text)
        self.assertIn("sync --criticality", help_text)
        self.assertIn("run --criticality", help_text)
        self.assertIn("--config", help_text)
        self.assertIn("--env-file", help_text)
        self.assertIn("--base-dir", help_text)
        self.assertIn("--verbose", help_text)
        self.assertIn("--debug", help_text)

    def test_debug_is_a_global_flag(self):
        args = build_parser().parse_args(["--debug", "latest"])
        self.assertTrue(args.debug)

    def test_export_accepts_multiple_fqdn_filters(self):
        args = build_parser().parse_args(
            [
                "export",
                "--fqdn",
                "Srv1.Example.org.",
                "srv2.example.org",
            ]
        )
        self.assertEqual(
            args.fqdn,
            ["srv1.example.org", "srv2.example.org"],
        )
        self.assertIsNone(args.ip)

    def test_run_accepts_ip_addresses_and_ranges(self):
        args = build_parser().parse_args(
            [
                "run",
                "--ip",
                "192.0.2.10",
                "192.0.2.11-192.0.2.15",
            ]
        )
        self.assertEqual(
            args.ip,
            ["192.0.2.10", "192.0.2.11-192.0.2.15"],
        )
        self.assertIsNone(args.fqdn)

    def test_asset_filters_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                ["run", "--fqdn", "srv.example.org", "--ip", "192.0.2.10"]
            )

    def test_run_help_describes_asset_filters(self):
        parser = build_parser()
        run_parser = parser._subparsers._group_actions[0].choices["run"]
        help_text = run_parser.format_help()
        self.assertIn("--fqdn FQDN [FQDN ...]", help_text)
        self.assertIn(
            "--ip IP_OR_RANGE [IP_OR_RANGE ...]",
            help_text,
        )
        self.assertIn("--dry-run", help_text)

    def test_run_accepts_case_insensitive_criticality_filter(self):
        args = build_parser().parse_args(
            [
                "run",
                "--criticality",
                "critical",
                "HIGH",
                "Non-crit",
            ]
        )
        self.assertEqual(
            args.criticality,
            ["Critical", "High", "Non-crit"],
        )

    def test_sync_help_describes_criticality_filter(self):
        parser = build_parser()
        sync_parser = parser._subparsers._group_actions[0].choices["sync"]
        help_text = sync_parser.format_help()
        self.assertIn("--criticality LEVEL [LEVEL ...]", help_text)
        self.assertIn("Critical, High, Medium, Low, Non-crit", help_text)

    def test_unknown_criticality_is_rejected(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["run", "--criticality", "urgent"])

    @patch("mpvm_jira.cli.run_setup", return_value=0)
    def test_setup_runs_without_loading_existing_config(self, run_setup):
        base_dir = Path("/tmp/mpvm-jira-setup-test")

        result = main(["--base-dir", str(base_dir), "setup"])

        self.assertEqual(result, 0)
        run_setup.assert_called_once_with(base_dir.resolve())

    @patch("mpvm_jira.setup.sys.stdin.isatty", return_value=False)
    def test_setup_requires_an_interactive_terminal(self, _isatty):
        self.assertEqual(run_setup(Path(".")), 2)


if __name__ == "__main__":
    unittest.main()
