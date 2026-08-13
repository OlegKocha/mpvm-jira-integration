import unittest

from mpvm_jira.setup.state import SetupState, TlsSettings


class SetupStateTests(unittest.TestCase):
    def test_repr_and_clear_secrets_do_not_expose_tokens(self):
        state = SetupState(
            mpvm_token="mpvm-secret",
            jira_token="jira-secret",
        )

        self.assertNotIn("mpvm-secret", repr(state))
        self.assertNotIn("jira-secret", repr(state))

        state.clear_secrets()

        self.assertEqual(state.mpvm_token, "")
        self.assertEqual(state.jira_token, "")

    def test_tls_settings_convert_to_config_values(self):
        self.assertIs(TlsSettings().config_value(), True)
        self.assertIs(TlsSettings(mode="disabled").config_value(), False)
        self.assertEqual(
            TlsSettings(mode="ca_file", ca_file="/etc/ca.pem").config_value(),
            "/etc/ca.pem",
        )

    def test_custom_ca_requires_a_path(self):
        with self.assertRaises(ValueError):
            TlsSettings(mode="ca_file").config_value()


if __name__ == "__main__":
    unittest.main()
