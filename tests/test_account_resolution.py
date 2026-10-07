import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from resolve_account import resolve_account_id


class AccountResolutionTests(unittest.TestCase):
    def test_one_scoped_account_is_selected(self):
        account_id = "a" * 32
        payload = {"success": True, "result": [{"id": account_id}]}
        actual = resolve_account_id("private-token", opener=lambda *a, **k: io.StringIO(json.dumps(payload)))
        self.assertEqual(actual, account_id)

    def test_multiple_accounts_require_explicit_selection(self):
        payload = {"success": True, "result": [{"id": "a" * 32}, {"id": "b" * 32}]}
        with self.assertRaisesRegex(RuntimeError, "one account"):
            resolve_account_id("private-token", opener=lambda *a, **k: io.StringIO(json.dumps(payload)))
        self.assertEqual(resolve_account_id("private-token", "b" * 32), "b" * 32)

    def test_lookup_error_cannot_expose_credentials(self):
        def fail(*args, **kwargs):
            raise ValueError("private-token and private response data")
        with self.assertRaises(RuntimeError) as caught:
            resolve_account_id("private-token", opener=fail)
        self.assertNotIn("private-token", str(caught.exception))

    def test_invalid_account_is_not_deployed(self):
        payload = {"success": True, "result": [{"id": "wrong-account"}]}
        with self.assertRaisesRegex(RuntimeError, "invalid account"):
            resolve_account_id("private-token", opener=lambda *a, **k: io.StringIO(json.dumps(payload)))
        with self.assertRaisesRegex(RuntimeError, "32-character"):
            resolve_account_id("private-token", "wrong-account")


if __name__ == "__main__":
    unittest.main()
