import logging
import tempfile
import unittest
from pathlib import Path

from mpvm_jira.cli import configure_logging


class LoggingTests(unittest.TestCase):
    def setUp(self):
        root = logging.getLogger()
        self.original_handlers = root.handlers[:]
        self.original_level = root.level

    def tearDown(self):
        root = logging.getLogger()
        for handler in root.handlers:
            if handler not in self.original_handlers:
                handler.close()
        root.handlers[:] = self.original_handlers
        root.setLevel(self.original_level)

    def test_logs_directory_is_not_created_without_debug(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            log_file = configure_logging(base, verbose=False, debug=False)

            self.assertIsNone(log_file)
            self.assertFalse((base / "logs").exists())

    def test_debug_creates_file_and_records_debug_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            log_file = configure_logging(base, verbose=False, debug=True)
            logging.getLogger("mpvm_jira.test").debug(
                "safe diagnostic message"
            )
            for handler in logging.getLogger().handlers:
                handler.flush()

            self.assertIsNotNone(log_file)
            self.assertTrue(log_file.is_file())
            content = log_file.read_text(encoding="utf-8")
            self.assertIn(
                "DEBUG mpvm_jira.test: safe diagnostic message", content
            )

    def test_debug_redacts_tokens_in_messages_and_tracebacks(self):
        with tempfile.TemporaryDirectory() as directory:
            log_file = configure_logging(
                Path(directory), verbose=False, debug=True
            )
            logger = logging.getLogger("mpvm_jira.test")
            logger.debug("GET /data?pdqlToken=temporary-secret&offset=0")
            fake_pat = "pat_" + "personal-secret"
            try:
                raise RuntimeError(
                    f"Authorization: Bearer bearer-secret {fake_pat}"
                )
            except RuntimeError:
                logger.exception("Request failed")
            for handler in logging.getLogger().handlers:
                handler.flush()

            content = log_file.read_text(encoding="utf-8")
            self.assertNotIn("temporary-secret", content)
            self.assertNotIn("bearer-secret", content)
            self.assertNotIn(fake_pat, content)
            self.assertIn("pdqlToken=<redacted>", content)
            self.assertIn("Bearer <redacted>", content)
            self.assertIn("pat_<redacted>", content)


if __name__ == "__main__":
    unittest.main()
