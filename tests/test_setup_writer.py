import os
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml

from mpvm_jira.config import load_dotenv
from mpvm_jira.setup.state import FileStrategy, SetupState
from mpvm_jira.setup.writer import (
    build_config,
    render_env,
    save_configuration,
)


def configured_state(**overrides):
    values = {
        "mpvm_url": "https://mpvm.example.org",
        "mpvm_token": "mpvm-token",
        "jira_url": "https://jira.example.org",
        "jira_auth_mode": "basic",
        "jira_user": "user@example.org",
        "jira_token": "jira-token",
        "jira_api_version": "2",
        "project_key": "SEC",
        "issue_type": "Task",
        "priority_map": {
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Undefined": "Medium",
        },
        "default_priority": "Medium",
    }
    values.update(overrides)
    return SetupState(**values)


class SetupWriterTests(unittest.TestCase):
    def test_basic_env_contains_user_and_bearer_env_does_not(self):
        basic = render_env(configured_state())
        bearer = render_env(
            configured_state(jira_auth_mode="bearer", jira_user="ignored")
        )

        self.assertIn("JIRA_USER=user@example.org", basic)
        self.assertNotIn("JIRA_USER", bearer)
        self.assertIn("MPVM_ACCESS_TOKEN=mpvm-token", bearer)
        self.assertIn("JIRA_API_TOKEN=jira-token", bearer)

    def test_state_overrides_defaults_and_preserves_pdql(self):
        config = build_config(
            configured_state(
                project_key="PM",
                additional_fields={"customfield_10000": {"value": "Security"}},
            )
        )

        self.assertEqual(config["jira"]["project_key"], "PM")
        self.assertEqual(
            config["jira"]["additional_fields"],
            {"customfield_10000": {"value": "Security"}},
        )
        self.assertIn("@Vulners", config["mpvm"]["vulnerabilities_pdql"])

    def test_new_files_are_private(self):
        with TemporaryDirectory() as directory:
            result = save_configuration(Path(directory), configured_state())

            self.assertEqual(result.env_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result.config_path.stat().st_mode & 0o777, 0o600)

    def test_backup_strategy_preserves_both_existing_files(self):
        with TemporaryDirectory() as directory:
            base_dir = Path(directory)
            (base_dir / ".env").write_text("old-env", encoding="utf-8")
            (base_dir / "config.yaml").write_text("old-config", encoding="utf-8")
            state = configured_state(file_strategy=FileStrategy.BACKUP)

            result = save_configuration(
                base_dir,
                state,
                now=datetime(2026, 8, 13, 12, 34, 56),
            )

            self.assertEqual(len(result.backups), 2)
            backup_contents = {
                path.name: path.read_text(encoding="utf-8") for path in result.backups
            }
            self.assertIn("old-env", backup_contents.values())
            self.assertIn("old-config", backup_contents.values())

    def test_overwrite_strategy_creates_no_public_backups(self):
        with TemporaryDirectory() as directory:
            base_dir = Path(directory)
            (base_dir / ".env").write_text("old-env", encoding="utf-8")
            (base_dir / "config.yaml").write_text("old-config", encoding="utf-8")

            result = save_configuration(base_dir, configured_state())

            self.assertEqual(result.backups, ())
            self.assertEqual(list(base_dir.glob("*.bak.*")), [])
            self.assertEqual(result.env_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result.config_path.stat().st_mode & 0o777, 0o600)

    def test_second_replace_failure_restores_both_originals(self):
        with TemporaryDirectory() as directory:
            base_dir = Path(directory)
            env_path = base_dir / ".env"
            config_path = base_dir / "config.yaml"
            env_path.write_text("old-env", encoding="utf-8")
            config_path.write_text("old-config", encoding="utf-8")
            original_replace = os.replace
            replacements = 0

            def fail_second_replace(source, destination):
                nonlocal replacements
                if Path(destination) in {env_path, config_path}:
                    replacements += 1
                    if replacements == 2:
                        raise OSError("simulated replace failure")
                return original_replace(source, destination)

            with patch(
                "mpvm_jira.setup.writer.os.replace",
                side_effect=fail_second_replace,
            ):
                with self.assertRaises(OSError):
                    save_configuration(base_dir, configured_state())

            self.assertEqual(env_path.read_text(encoding="utf-8"), "old-env")
            self.assertEqual(config_path.read_text(encoding="utf-8"), "old-config")

    def test_render_failure_does_not_touch_existing_files(self):
        with TemporaryDirectory() as directory:
            base_dir = Path(directory)
            env_path = base_dir / ".env"
            config_path = base_dir / "config.yaml"
            env_path.write_text("old-env", encoding="utf-8")
            config_path.write_text("old-config", encoding="utf-8")

            with patch(
                "mpvm_jira.setup.writer.render_env",
                side_effect=ValueError("invalid token"),
            ):
                with self.assertRaises(ValueError):
                    save_configuration(base_dir, configured_state())

            self.assertEqual(env_path.read_text(encoding="utf-8"), "old-env")
            self.assertEqual(config_path.read_text(encoding="utf-8"), "old-config")

    def test_written_config_is_valid_yaml(self):
        with TemporaryDirectory() as directory:
            result = save_configuration(Path(directory), configured_state())

            loaded = yaml.safe_load(result.config_path.read_text("utf-8"))

        self.assertEqual(loaded["jira"]["project_key"], "SEC")

    def test_special_characters_round_trip_through_dotenv_loader(self):
        state = configured_state(
            mpvm_token='mpvm # "quoted" \\ token',
            jira_token="jira#token\\value",
        )
        with TemporaryDirectory() as directory:
            result = save_configuration(Path(directory), state)
            with patch.dict(os.environ, {}, clear=True):
                load_dotenv(result.env_path)
                self.assertEqual(os.environ["MPVM_ACCESS_TOKEN"], state.mpvm_token)
                self.assertEqual(os.environ["JIRA_API_TOKEN"], state.jira_token)


if __name__ == "__main__":
    unittest.main()
