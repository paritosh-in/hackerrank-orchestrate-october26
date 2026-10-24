"""Small additional regression cases; not based on private grader data."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "main.py"
S = importlib.util.spec_from_file_location("ghost_main", P)
M = importlib.util.module_from_spec(S)
assert S and S.loader
S.loader.exec_module(M)

class IntentRegressionTests(unittest.TestCase):
    def test_direct_deletion_authorized(self):
        from evidence import request_authorizes_deletion
        self.assertTrue(request_authorizes_deletion("Please permanently delete my account and data."))
    def test_marketing_optout_not_authorized(self):
        from evidence import request_authorizes_deletion
        self.assertFalse(request_authorizes_deletion("Please unsubscribe me from marketing emails."))
    def test_data_export_is_not_deletion(self):
        from evidence import request_authorizes_deletion
        self.assertFalse(request_authorizes_deletion("Please export my data and send me a copy."))
    def test_multilingual_deletion(self):
        from evidence import request_authorizes_deletion
        self.assertTrue(request_authorizes_deletion("Solicito la eliminación permanente de la cuenta asociada."))
if __name__ == "__main__":
    unittest.main()
