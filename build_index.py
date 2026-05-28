from __future__ import annotations

import html
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TITLE = "Nick's Scripts"
REPO_URL = "https://github.com/ndemou/scripts"
DOWNLOAD_BASE_URL = "https://ndemou.github.io/scripts"
SCRIPT_EXTENSIONS = {".ps1", ".sh"}
EXCLUDED_DIR_NAMES = {"tests", "release", "__pycache__", ".git"}
FILE_COLOR = "\033[96m"
FUNCTION_COLOR = "\033[92m"
RESET_COLOR = "\033[0m"
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


def strip_utf8_bom(text: str) -> str:
    return text.removeprefix("\ufeff")


def extract_comment_block(text: str, extension: str) -> list[str]:
    lines = text.splitlines()
    index = 0

    while index < len(lines):
        stripped = strip_utf8_bom(lines[index].strip())
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

    stripped = strip_utf8_bom(lines[index].strip())

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
            details = None
            if j < len(lines) and lines[j].strip().startswith("<#"):
                block: list[str] = []
                while j < len(lines):
                    block.append(lines[j])
                    if "#>" in lines[j]:
                        break
                    j += 1
                comment_lines = strip_block_comment_markers(block)
                synopsis, details = extract_synopsis(comment_lines)
                details = cleanup_details(details)

            docs.append(FunctionDoc(name=name, synopsis=synopsis, details=details))

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
        item_lines = [
            '          <div class="function-entry">',
            f'            <p class="function-name"><strong>{html.escape(function_doc.name)}</strong></p>',
        ]
        if function_doc.synopsis:
            synopsis = html.escape(" ".join(part.strip() for part in function_doc.synopsis.splitlines() if part.strip()))
            item_lines.append(f'            <p class="function-synopsis">{synopsis}</p>')
        if function_doc.details:
            item_lines.extend(
                [
                    '            <details class="script-details function-details">',
                    '              <summary>Read more</summary>',
                    render_text_block(function_doc.details, "script-details-text", bold_directives=True).replace(
                        '          <p class="script-details-text">',
                        '              <p class="script-details-text">',
                    ),
                    "            </details>",
                ]
            )
        item_lines.append("          </div>")
        items.append("\n".join(item_lines))

    return "\n".join(
        [
            "        <details class=\"script-details\">",
            "          <summary>Read more</summary>",
            "          <div class=\"function-panel\">",
            *items,
            "          </div>",
            "        </details>",
        ]
    )


def render_item(doc: ScriptDoc) -> str:
    relative_path = doc.path.relative_to(ROOT).as_posix()
    copy_command = f'$dir="C:\\IT\\bin";$f="{relative_path}";mkdir $dir -force >$null;iwr -useb {DOWNLOAD_BASE_URL}/$f -out $dir\\$f'
    parts = [
        "      <li class=\"script-item\">",
        "        <div class=\"script-header\">",
        f'          <a class="script-link" href="{html.escape(relative_path)}">{html.escape(relative_path)}</a>',
        (
            '          <button class="copy-button" '
            f'data-copy="{html.escape(copy_command, quote=True)}" '
            f'title="Copy download command for {html.escape(relative_path, quote=True)}" '
            f'aria-label="Copy download command for {html.escape(relative_path, quote=True)}">'
            '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
            '<path d="M5 2.75A1.75 1.75 0 0 1 6.75 1h5.5A1.75 1.75 0 0 1 14 2.75v6.5A1.75 1.75 0 0 1 12.25 11h-5.5A1.75 1.75 0 0 1 5 9.25zm1.75-.25a.25.25 0 0 0-.25.25v6.5c0 .138.112.25.25.25h5.5a.25.25 0 0 0 .25-.25v-6.5a.25.25 0 0 0-.25-.25z"></path>'
            '<path d="M2 5.75C2 4.784 2.784 4 3.75 4h.5a.75.75 0 0 1 0 1.5h-.5a.25.25 0 0 0-.25.25v6.5c0 .138.112.25.25.25h5.5a.25.25 0 0 0 .25-.25v-.5a.75.75 0 0 1 1.5 0v.5A1.75 1.75 0 0 1 9.25 14h-5.5A1.75 1.75 0 0 1 2 12.25z"></path>'
            "</svg>"
            "          </button>"
        ),
        "        </div>",
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
    <h1>Available scripts & functions</h2>
    <ul class="script-list">
{items}
    </ul>

    <p class="footer">
      Source repository:
      <a href="{html.escape(REPO_URL)}">{html.escape(REPO_URL.removeprefix("https://"))}</a>
    </p>
  </main>
  <script>
    document.addEventListener("click", async (event) => {{
      const button = event.target.closest(".copy-button");
      if (!button) return;
      const text = button.getAttribute("data-copy");
      if (!text) return;
      try {{
        await navigator.clipboard.writeText(text);
        button.classList.add("copied");
        setTimeout(() => button.classList.remove("copied"), 1200);
      }} catch {{
        button.classList.add("copy-failed");
        setTimeout(() => button.classList.remove("copy-failed"), 1200);
      }}
    }});
  </script>
</body>
</html>
"""


def is_publishable_script(path: Path) -> bool:
    if path.suffix.lower() not in SCRIPT_EXTENSIONS:
        return False
    relative_parts = path.relative_to(ROOT).parts[:-1]
    return not any(part in EXCLUDED_DIR_NAMES for part in relative_parts)


def print_documented_item(doc: ScriptDoc) -> None:
    relative_path = doc.path.relative_to(ROOT).as_posix()
    print(f"{FILE_COLOR}FILE {relative_path}{RESET_COLOR}")
    if doc.function_docs:
        for function_doc in doc.function_docs:
            print(f"{FUNCTION_COLOR}  FUNC {function_doc.name}{RESET_COLOR}")


def main() -> None:
    docs: list[ScriptDoc] = []
    for path in ROOT.rglob("*"):
        if not is_publishable_script(path):
            continue
        doc = read_script_doc(path)
        docs.append(doc)
        print_documented_item(doc)
    docs.sort(key=lambda doc: doc.path.relative_to(ROOT).as_posix().lower())
    (ROOT / "index.html").write_text(build_html(docs), encoding="utf-8")


if __name__ == "__main__":
    main()
