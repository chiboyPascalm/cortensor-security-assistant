import json
import tempfile
import unittest
from pathlib import Path

from app import NOTICE, export_json_report


class ReportExportTests(unittest.TestCase):
    def sample_report(self):
        return {
            "file": "example.sol",
            "findings": [
                {
                    "severity": "HIGH",
                    "rule": "SOL005",
                    "line": 12,
                    "message": "tx.origin appears in an equality check, possibly for authorization.",
                    "recommendation": "Use explicit role-based or owner-based authorization instead.",
                }
            ],
        }

    def test_export_creates_valid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "reports" / "report.json"
            export_json_report(self.sample_report(), str(output))

            with output.open(encoding="utf-8") as report_file:
                data = json.load(report_file)

            self.assertEqual(data["finding_count"], 1)
            self.assertEqual(data["tool"], "Cortensor Security Assistant")
            self.assertEqual(data["findings"][0]["rule"], "SOL005")

    def test_export_includes_local_explanations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.json"
            export_json_report(self.sample_report(), str(output))
            data = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(len(data["local_explanations"]), 1)
            self.assertEqual(data["local_explanations"][0]["rule"], "SOL005")
            self.assertIn("recommendation", data["local_explanations"][0])

    def test_export_includes_safety_notice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.json"
            export_json_report(self.sample_report(), str(output))
            data = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(data["notice"], NOTICE)

    def test_export_handles_zero_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.json"
            report = {"file": "simple.sol", "findings": []}
            export_json_report(report, str(output))
            data = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(data["finding_count"], 0)
            self.assertEqual(data["findings"], [])
            self.assertEqual(data["local_explanations"], [])


if __name__ == "__main__":
    unittest.main()
