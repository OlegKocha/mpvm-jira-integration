"""Security-focused tests for shared HTTP response handling."""

import unittest

from requests import Response

from mpvm_jira.http import ApiError, checked_json


class CheckedJsonTests(unittest.TestCase):
    """Ensure API failures do not disclose response bodies."""

    def test_error_omits_response_body(self):
        response = Response()
        response.status_code = 401
        # requests.Response has no public setter for a synthetic body.
        response._content = (
            b'{"access_token":"must-not-appear","detail":"denied"}'
        )

        with self.assertRaises(ApiError) as captured:
            checked_json(response, "API check")

        message = str(captured.exception)
        self.assertEqual(message, "API check: HTTP 401")
        self.assertNotIn("must-not-appear", message)
        self.assertNotIn("access_token", message)


if __name__ == "__main__":
    unittest.main()
