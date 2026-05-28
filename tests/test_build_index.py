import unittest
from pathlib import Path

import build_index


class BuildIndexTests(unittest.TestCase):
    def test_extract_comment_block_accepts_utf8_bom_prefixed_ps1_block(self) -> None:
        text = "\ufeff<#\n.SYNOPSIS\nA collection of helper functions for handling files\n#>\n"

        comment_lines = build_index.extract_comment_block(text, ".ps1")

        self.assertEqual(
            comment_lines,
            [
                ".SYNOPSIS",
                "A collection of helper functions for handling files",
            ],
        )

    def test_read_script_doc_extracts_bom_prefixed_helpers_file_docs(self) -> None:
        doc = build_index.read_script_doc(Path("helpers-files.ps1"))

        self.assertEqual(doc.synopsis, "A collection of helper functions for handling files")
        self.assertIsNone(doc.details)
        self.assertIsNotNone(doc.function_docs)
        self.assertGreater(len(doc.function_docs), 0)


if __name__ == "__main__":
    unittest.main()
