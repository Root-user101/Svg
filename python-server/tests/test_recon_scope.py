import unittest

from recon_engine import clean_host, in_scope, valid_recon_root


class ScopeRulesTests(unittest.TestCase):
    def test_exact_hostname_does_not_match_sibling(self):
        scope = [{"host": "api.example.com", "type": "Exact hostname"}]
        self.assertTrue(in_scope("api.example.com", scope))
        self.assertFalse(in_scope("www.example.com", scope))

    def test_wildcard_matches_subdomains_but_not_apex(self):
        scope = [{"host": "example.com", "type": "Wildcard domain"}]
        self.assertTrue(in_scope("api.example.com", scope))
        self.assertTrue(in_scope("a.b.example.com", scope))
        self.assertFalse(in_scope("example.com", scope))

    def test_wildcard_apex_is_allowed_only_as_passive_query_root(self):
        scope = [{"host": "example.com", "type": "Wildcard domain"}]
        self.assertTrue(valid_recon_root("example.com", scope))
        self.assertFalse(in_scope("example.com", scope))

    def test_root_must_match_saved_scope(self):
        scope = [{"host": "api.example.com", "type": "Exact hostname"}]
        self.assertFalse(valid_recon_root("example.com", scope))

    def test_clean_host_rejects_urls(self):
        with self.assertRaises(ValueError):
            clean_host("https://example.com/path")
        self.assertEqual(clean_host("Example.COM."), "example.com")


if __name__ == "__main__":
    unittest.main()
