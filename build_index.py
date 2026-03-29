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
FUNCTION_NAME_RE = re.compile(r"^(?:function|filter)\s+([A-Za-z_][\w-]*)\s*(?:\(|\{|$)", re.IGNORECASE)


@dataclass
class ScriptDoc:
    path: Path
    synopsis: str | None
    details: str | None
    function_docs: list[FunctionDoc] | None = None


@dataclass
class FunctionDoc:
    name: str
    synopsis: str | None


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


def extract_explicit_synopsis(comment_lines: list[str]) -> str | None:
    for i, line in enumerate(comment_lines):
        if re.match(r"^\s*\.SYN(?:O|OS)PSIS\s*$", line, re.IGNORECASE):
            synopsis_lines: list[str] = []
            j = i + 1
            while j < len(comment_lines):
                if HELP_DIRECTIVE_RE.match(comment_lines[j]):
                    break
                synopsis_lines.append(comment_lines[j])
                j += 1
            return "\n".join(synopsis_lines).strip() or None
    return None


def extract_function_docs(text: str) -> list[FunctionDoc]:
    lines = text.splitlines()
    docs: list[FunctionDoc] = []
    i = 0
    block_comment = False
    brace_depth = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if block_comment:
            if "#>" in line:
                block_comment = False
            i += 1
            continue

        if stripped.startswith("<#"):
            if "#>" not in line:
                block_comment = True
            i += 1
            continue
        if stripped.startswith("#"):
            i += 1
            continue

        match = FUNCTION_NAME_RE.match(line) if brace_depth == 0 else None

        if match:
            name = match.group(1)
            if name.startswith("_"):
                brace_depth += line.count("{") - line.count("}")
                if brace_depth < 0:
                    brace_depth = 0
                i += 1
                continue
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1

            synopsis = None
            if j < len(lines) and lines[j].strip().startswith("<#"):
                block: list[str] = []
                while j < len(lines):
                    block.append(lines[j])
                    if "#>" in lines[j]:
                        break
                    j += 1
                comment_lines = strip_block_comment_markers(block)
                synopsis = extract_explicit_synopsis(comment_lines)

            docs.append(FunctionDoc(name=name, synopsis=synopsis))

        brace_depth += line.count("{") - line.count("}")
        if brace_depth < 0:
            brace_depth = 0
        i += 1

    return docs


def extract_helper_function_docs(synopsis: str | None, details: str | None, text: str, extension: str) -> list[FunctionDoc] | None:
    if extension != ".ps1" or details:
        return None
    if not synopsis:
        return None

    summary_lines = [line.strip() for line in synopsis.splitlines() if line.strip()]
    if len(summary_lines) != 1 or "helper functions" not in summary_lines[0].lower():
        return None

    function_docs = extract_function_docs(text)
    return function_docs or None


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
    details = cleanup_details(details)
    function_docs = extract_helper_function_docs(synopsis, details, text, path.suffix.lower())
    return ScriptDoc(path=path, synopsis=synopsis, details=details, function_docs=function_docs)


def render_text_block(text: str, css_class: str, bold_directives: bool = False) -> str:
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text.strip()) if part.strip()]
    if not paragraphs:
        return ""

    def render_line(line: str) -> str:
        escaped = html.escape(line)
        if bold_directives and re.match(r"^[.][A-Z]+ *$", line.strip()):
            return f'<span class="detail-directive">{escaped}</span>'
        return escaped

    body = "\n".join(
        f'          <p class="{css_class}">{"<br>".join(render_line(line) for line in paragraph.splitlines())}</p>'
        for paragraph in paragraphs
    )
    return body


def render_function_docs(function_docs: list[FunctionDoc]) -> str:
    items = []
    for function_doc in function_docs:
        item = f"<strong>{html.escape(function_doc.name)}</strong>"
        if function_doc.synopsis:
            synopsis = html.escape(" ".join(part.strip() for part in function_doc.synopsis.splitlines() if part.strip()))
            item += f": {synopsis}"
        items.append(f"            <li>{item}</li>")

    return "\n".join(
        [
            "        <details class=\"script-details\">",
            "          <summary>Read more</summary>",
            "          <div class=\"script-details-text\">Functions:</div>",
            "          <ul class=\"function-list\">",
            *items,
            "          </ul>",
            "        </details>",
        ]
    )


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
                render_text_block(doc.details, "script-details-text", bold_directives=True),
                "        </details>",
            ]
        )
    elif doc.function_docs:
        parts.append(render_function_docs(doc.function_docs))

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
