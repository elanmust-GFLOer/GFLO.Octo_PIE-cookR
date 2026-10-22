import unittest
from b23r6a.run_verified import validate

class ManifestSecurity(unittest.TestCase):
    def test_equal_count_substitution_fails(self):
        with self.assertRaises(ValueError): validate(["A.test_other"],["A.test_required"])
    def test_duplicate_identity_fails(self):
        with self.assertRaises(ValueError): validate(["A.test_one","A.test_one"],["A.test_one","A.test_one"])
    def test_exact_names_succeed(self):
        validate(["A.test_one","B.test_two"],["B.test_two","A.test_one"])
