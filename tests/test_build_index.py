import unittest
from pathlib import Path

import build_index


class BuildIndexTests(unittest.TestCase):
    def test_publishable_script_discovery_matches_standalone_repo_contract(self) -> None:
        paths = {
            path.relative_to(build_index.ROOT).as_posix()
            for path in build_index.ROOT.rglob("*")
            if build_index.is_publishable_script(path)
        }

        self.assertIn("WindowsUpdatesHelper.ps1", paths)
        self.assertIn("helpers-text-files.ps1", paths)
        self.assertNotIn("release/Publish-NewRelease.ps1", paths)
        self.assertNotIn("tests/run-edit-textfile-tests.ps1", paths)

    def test_every_publishable_script_has_indexable_synopsis(self) -> None:
        docs = [
            build_index.read_script_doc(path)
            for path in build_index.ROOT.rglob("*")
            if build_index.is_publishable_script(path)
        ]

        missing = [
            doc.path.relative_to(build_index.ROOT).as_posix()
            for doc in docs
            if not doc.synopsis
        ]

        self.assertEqual(missing, [])

    def test_helper_function_containers_expose_function_docs(self) -> None:
        helper_docs = [
            build_index.read_script_doc(path)
            for path in build_index.ROOT.glob("helpers-*.ps1")
        ]

        self.assertGreater(len(helper_docs), 0)
        missing_function_docs = [
            doc.path.name
            for doc in helper_docs
            if not doc.function_docs
        ]

        self.assertEqual(missing_function_docs, [])

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

    def test_extract_comment_block_accepts_utf8_bom_prefixed_ps1_banner(self) -> None:
        text = (
            "\ufeff##############################################################\n"
            "#\n"
            "# A collection of helper functions for Networking\n"
            "#\n"
            "##############################################################\n"
        )

        comment_lines = build_index.extract_comment_block(text, ".ps1")

        self.assertEqual(
            comment_lines,
            ["A collection of helper functions for Networking"],
        )

    def test_read_script_doc_extracts_bom_prefixed_helpers_file_docs(self) -> None:
        doc = build_index.read_script_doc(Path("helpers-files.ps1"))

        self.assertEqual(doc.synopsis, "A collection of helper functions for handling files")
        self.assertIsNone(doc.details)
        self.assertIsNotNone(doc.function_docs)
        self.assertGreater(len(doc.function_docs), 0)

    def test_read_script_doc_extracts_bom_prefixed_banner_helpers_file_docs(self) -> None:
        doc = build_index.read_script_doc(Path("helpers-networking.ps1"))

        self.assertEqual(doc.synopsis, "A collection of helper functions for Networking")
        self.assertIsNone(doc.details)
        self.assertIsNotNone(doc.function_docs)
        self.assertGreater(len(doc.function_docs), 0)

    def test_extract_function_docs_handles_inline_comment_based_help(self) -> None:
        text = """function Get-DiskInfo {
    <#
    .SYNOPSIS Gets Win32_LogicalDisk information for one disk.
    .DESCRIPTION Popular properties: FreeSpace, Size, VolumeName, DriveType
    .PARAMETER Disk Disk device ID, for example C:.
    #>
    param([string]$Disk)
}
"""

        docs = build_index.extract_function_docs(text)

        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].name, "Get-DiskInfo")
        self.assertEqual(docs[0].synopsis, "Gets Win32_LogicalDisk information for one disk.")
        self.assertEqual(
            docs[0].details,
            "Popular properties: FreeSpace, Size, VolumeName, DriveType\n"
            ".PARAMETER Disk Disk device ID, for example C:.",
        )

    def test_cleanup_details_strips_leading_inline_description_directive(self) -> None:
        details = ".DESCRIPTION Popular properties: FreeSpace, Size, VolumeName, DriveType"

        cleaned = build_index.cleanup_details(details)

        self.assertEqual(cleaned, "Popular properties: FreeSpace, Size, VolumeName, DriveType")

    def test_extract_function_docs_uses_description_when_synopsis_is_missing(self) -> None:
        text = """function Get-ProcessesWithMatchingCommandLine($likeExpression) {
  <#
.DESCRIPTION
List processes with command lines matching a like expression (e.g. "*myScript.ps1*")
.EXAMPLE
Get-ProcessesWithMatchingCommandLine "*myScript.ps1*"
#>
}
"""

        docs = build_index.extract_function_docs(text)

        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].name, "Get-ProcessesWithMatchingCommandLine")
        self.assertEqual(
            docs[0].synopsis,
            'List processes with command lines matching a like expression (e.g. "*myScript.ps1*")',
        )
        self.assertEqual(
            docs[0].details,
            '.EXAMPLE\nGet-ProcessesWithMatchingCommandLine "*myScript.ps1*"',
        )

    def test_extract_function_docs_handles_help_block_above_function(self) -> None:
        text = """<#
.DESCRIPTION
Quotes a string so it can be safely passed as a single argument.
#>
function Quote-Win32Arg([string]$s) {
}
"""

        docs = build_index.extract_function_docs(text)

        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].name, "Quote-Win32Arg")
        self.assertEqual(
            docs[0].synopsis,
            "Quotes a string so it can be safely passed as a single argument.",
        )
        self.assertIsNone(docs[0].details)


if __name__ == "__main__":
    unittest.main()
