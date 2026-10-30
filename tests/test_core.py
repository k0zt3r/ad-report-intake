import unittest
import zipfile
from io import BytesIO

from core import analyze, evaluate, read_report


class IntakeTests(unittest.TestCase):
    def test_example_report_extracts_sources_and_keeps_unknowns(self):
        with open("example_report.txt", "rb") as file:
            result = analyze("example_report.txt", file.read())
        obs = result["observations"]
        self.assertEqual(obs["dc_os"]["value"], 0)
        self.assertEqual(obs["dc_segmentation"]["value"], 0)
        self.assertEqual(obs["remote_mfa"]["value"], 1)
        self.assertEqual(obs["ad_backup"]["value"], 1)
        self.assertEqual(obs["restore_test"]["value"], 1)
        self.assertEqual(obs["admin_accounts"]["value"], 1)
        self.assertEqual(obs["admin_workstations"]["value"], 1)
        self.assertEqual(result["context"]["inventory"]["workstations"][0]["count"], 12)
        self.assertEqual(result["context"]["inventory"]["remote_hosts"][0]["count"], 2)
        self.assertIsNone(result["context"]["authorized_scope"])
        self.assertEqual(obs["dc_updates"]["status"], "unknown")
        self.assertIn("строка 3", obs["dc_os"]["evidence"][0]["locator"])
        self.assertEqual(result["evaluation"]["vector"]["Контроллеры домена"]["upper"], 0)

    def test_conflicting_statements_are_not_resolved_silently(self):
        data = "Удалённый доступ VPN без MFA.\nУдалённый доступ VPN: MFA обязательна.\n".encode()
        result = analyze("report.txt", data)
        self.assertEqual(result["observations"]["remote_mfa"]["status"], "conflict")
        self.assertEqual(len(result["observations"]["remote_mfa"]["evidence"]), 2)

    def test_manual_review_recalculates_interval(self):
        result = analyze("report.txt", b"No AD details.")
        obs = result["observations"]
        self.assertEqual(result["evaluation"]["vector"]["Сеть"]["status"], "interval")
        obs["dc_segmentation"].update(status="known", value=0.5, method="manual")
        obs["network_rules"].update(status="known", value=1, method="manual")
        self.assertEqual(evaluate(obs)["vector"]["Сеть"]["lower"], 0.5)

    def test_docx_extracts_paragraphs_without_dependency(self):
        doc = BytesIO()
        xml = ("<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>"
               "<w:body><w:p><w:r><w:t>Контроллер домена: Windows Server 2012.</w:t>"
               "</w:r></w:p></w:body></w:document>")
        with zipfile.ZipFile(doc, "w") as archive:
            archive.writestr("word/document.xml", xml)
        units, _ = read_report("sample.docx", doc.getvalue())
        self.assertEqual(units[0]["locator"], "абзац 1")
        self.assertEqual(analyze("sample.docx", doc.getvalue())["observations"]["dc_os"]["value"], 0)

    def test_unrelated_server_version_is_not_treated_as_domain_controller(self):
        result = analyze("report.txt", "Файловый сервер: Windows Server 2012 R2.".encode())
        self.assertEqual(result["observations"]["dc_os"]["status"], "unknown")

    def test_pdf_text_layer_has_page_provenance(self):
        try:
            import pymupdf
        except ImportError:
            self.skipTest("PyMuPDF не установлен")
        doc = pymupdf.open()
        page = doc.new_page()
        page.insert_text((50, 50), "Domain Controller: Windows Server 2012 R2")
        result = analyze("sample.pdf", doc.tobytes())
        self.assertEqual(result["observations"]["dc_os"]["value"], 0)
        self.assertIn("стр. 1", result["observations"]["dc_os"]["evidence"][0]["locator"])

    def test_invalid_docx_reports_input_error(self):
        with self.assertRaisesRegex(ValueError, "DOCX"):
            analyze("broken.docx", b"not a zip")


if __name__ == "__main__":
    unittest.main()
