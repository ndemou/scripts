from __future__ import annotations

import html
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TITLE = "Nick's Scripts"
REPO_URL = "https://github.com/ndemou/scripts"
SCRIPT_EXTENSIONS = {".ps1", ".sh"}
HELP_DIRECTIVE_RE = re.compile(r"^\s*\.(?P<name>[A-Z][A-Z0-9_-]*)\b", re.IGNORECASE)
FUNCTION_HEADER_RE = re.compile(
    r"^\s*(function|filter)\b|^\s*\[[A-Za-z][^\]]*\]\s*$|^\s*param\s*\(|^\s*{\s*$",
    re.IGNORECASE,
)


@dataclass
class ScriptDoc:
    path: Path
    synopsis: str | None
    details: str | None


def normalize_comment_lines(lines: list[str]) -> list[str]:
    normalized: list[str] = []
    for line in lines:
        text = line.rstrip()
        if text.startswith("#"):
            text = text[1:]
            if text.startswith(" "):
                text = text[1:]
        normalized.append(text)
    normalized = [textwrap.dedent(line) for line in normalized]
    while normalized and not normalized[0].strip():
        normalized.pop(0)
    while normalized and not normalized[-1].strip():
        normalized.pop()
    normalized = [
        line
        for line in normalized
        if not re.match(r"^\s*[^A-Za-z0-9]+\s*$", line)
    ]
    return normalized


def strip_block_comment_markers(lines: list[str]) -> list[str]:
    if not lines:
        return []

    first = lines[0]
    if "<#" in first:
        first = first.split("<#", 1)[1]
    lines[0] = first

    last = lines[-1]
    if "#>" in last:
        last = last.rsplit("#>", 1)[0]
    lines[-1] = last

    return normalize_comment_lines(lines)


def extract_comment_block(text: str, extension: str) -> list[str]:
    lines = text.splitlines()
    index = 0

    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            index += 1
            continue
        if extension == ".sh" and stripped.startswith("#!"):
            index += 1
            continue
        if extension == ".ps1" and FUNCTION_HEADER_RE.match(stripped):
            index += 1
            continue
        break

    if index >= len(lines):
        return []

    stripped = lines[index].strip()

    if stripped.startswith("<#"):
        block: list[str] = []
        while index < len(lines):
            block.append(lines[index])
            if "#>" in lines[index]:
                return strip_block_comment_markers(block)
            index += 1
        return strip_block_comment_markers(block)

    if stripped.startswith("#") and not stripped.startswith("#!"):
        block = []
        while index < len(lines):
            current = lines[index]
            current_stripped = current.strip()
            if current_stripped.startswith("#") and not current_stripped.startswith("#!"):
                block.append(current)
                index += 1
                continue
            if not current_stripped:
                block.append("#")
                index += 1
                continue
            break
        return normalize_comment_lines(block)

    return []


def extract_synopsis(comment_lines: list[str]) -> tuple[str | None, str | None]:
    if not comment_lines:
        return None, None

    synopsis_index = None
    for i, line in enumerate(comment_lines):
        if re.match(r"^\s*\.SYN(?:O|OS)PSIS\s*$", line, re.IGNORECASE):
            synopsis_index = i
            break

    if synopsis_index is None:
        text = "\n".join(comment_lines).strip()
        return (text or None), None

    synopsis_lines: list[str] = []
    details_lines = comment_lines[:synopsis_index]
    i = synopsis_index + 1
    while i < len(comment_lines):
        if HELP_DIRECTIVE_RE.match(comment_lines[i]):
            break
        synopsis_lines.append(comment_lines[i])
        i += 1

    details_lines.extend(comment_lines[i:])

    synopsis = "\n".join(synopsis_lines).strip() or None
    details = "\n".join(details_lines).strip() or None
    return synopsis, details


def cleanup_details(details: str | None) -> str | None:
    if not details:
        return None

    lines = details.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and re.match(r"^\s*\.DESCRIPTION\s*$", lines[0], re.IGNORECASE):
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)

    cleaned = "\n".join(lines).strip()
    return cleaned or None


def read_script_doc(path: Path) -> ScriptDoc:
    text = None
    for encoding in ("utf-8", "utf-8-sig", "cp1252"):
        try:
            text = path.read_text(encoding=encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = path.read_text(encoding="utf-8", errors="replace")

    comment_lines = extract_comment_block(text, path.suffix.lower())
    synopsis, details = extract_synopsis(comment_lines)
    return ScriptDoc(path=path, synopsis=synopsis, details=cleanup_details(details))


def render_text_block(text: str, css_class: str) -> str:
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text.strip()) if part.strip()]
    if not paragraphs:
        return ""
    body = "\n".join(
        f'          <p class="{css_class}">{html.escape(paragraph).replace(chr(10), "<br>")}</p>'
        for paragraph in paragraphs
    )
    return body


def render_item(doc: ScriptDoc) -> str:
    relative_path = doc.path.relative_to(ROOT).as_posix()
    parts = [
        "      <li class=\"script-item\">",
        f'        <a class="script-link" href="{html.escape(relative_path)}">{html.escape(relative_path)}</a>',
    ]

    if doc.synopsis:
        parts.append(render_text_block(doc.synopsis, "script-synopsis"))

    if doc.details:
        parts.extend(
            [
                "        <details class=\"script-details\">",
                "          <summary>Read more</summary>",
                render_text_block(doc.details, "script-details-text"),
                "        </details>",
            ]
        )

    parts.append("      </li>")
    return "\n".join(part for part in parts if part)


def build_html(docs: list[ScriptDoc]) -> str:
    items = "\n".join(render_item(doc) for doc in docs)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(TITLE)}</title>
  <link rel="stylesheet" href="./styles.css">
</head>
<body>
  <main class="card">
    <h1>{html.escape(TITLE)}</h1>
    <p>PowerShell and shell scripts published via GitHub Pages.</p>

    <h2>Available downloads</h2>
    <ul class="script-list">
{items}
    </ul>

    <p class="footer">
      Source repository:
      <a href="{html.escape(REPO_URL)}">{html.escape(REPO_URL.removeprefix("https://"))}</a>
    </p>
  </main>
</body>
</html>
"""


def main() -> None:
    docs = sorted(
        (read_script_doc(path) for path in ROOT.rglob("*") if path.suffix.lower() in SCRIPT_EXTENSIONS),
        key=lambda doc: doc.path.relative_to(ROOT).as_posix().lower(),
    )
    (ROOT / "index.html").write_text(build_html(docs), encoding="utf-8")


if __name__ == "__main__":
    main()
