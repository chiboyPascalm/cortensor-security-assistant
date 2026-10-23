import unittest

from scanner import scan_solidity


class ScannerTests(unittest.TestCase):
    def test_detects_tx_origin(self):
        findings = scan_solidity("contract Example { function f() public view { tx.origin; } }")
        self.assertTrue(any(f["rule"] == "SOL001" for f in findings))

    def test_tx_origin_equality_is_not_reported_twice(self):
        findings = scan_solidity("contract Example { function f() public view { require(tx.origin == owner); } }")
        matching = [f for f in findings if f["rule"] in ("SOL001", "SOL005")]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["rule"], "SOL005")

    def test_detects_call_with_value_options(self):
        findings = scan_solidity('target.call{value: 1}("");')
        self.assertTrue(any(f["rule"] == "SOL002" for f in findings))

    def test_detects_plain_call(self):
        findings = scan_solidity("target.call(data);")
        self.assertTrue(any(f["rule"] == "SOL002" for f in findings))

    def test_detects_delegatecall(self):
        findings = scan_solidity("target.delegatecall(data);")
        self.assertTrue(any(f["rule"] == "SOL003" for f in findings))

    def test_detects_selfdestruct(self):
        findings = scan_solidity("selfdestruct(payable(owner));")
        self.assertTrue(any(f["rule"] == "SOL004" for f in findings))

    def test_ignores_patterns_in_line_comments(self):
        findings = scan_solidity("// tx.origin; target.call(data);\nmsg.sender;")
        self.assertEqual(findings, [])

    def test_ignores_patterns_in_block_comments(self):
        findings = scan_solidity("/* tx.origin; target.call(data); */\nmsg.sender;")
        self.assertEqual(findings, [])

    def test_ignores_patterns_in_strings(self):
        source = 'string memory note = "tx.origin target.call(data)";'
        self.assertEqual(scan_solidity(source), [])

    def test_preserves_line_numbers(self):
        source = "contract Example {\n\n    tx.origin;\n}"
        findings = scan_solidity(source)
        finding = next(f for f in findings if f["rule"] == "SOL001")
        self.assertEqual(finding["line"], 3)

    def test_safe_example_has_no_findings(self):
        source = """
        contract Example {
            function check() public view returns (address) {
                return msg.sender;
            }
        }
        """
        self.assertEqual(scan_solidity(source), [])


if __name__ == "__main__":
    unittest.main()
