# Script Index Design Guide

## Purpose

This document defines how `index.html` should be generated for this repository so that all published scripts are presented consistently, readably, and with useful inline documentation.

The index is intended to act as a lightweight script catalog for GitHub Pages:

- Every script should be discoverable from one page.
- Short descriptions should be visible without expanding anything.
- Longer help should be available on demand.
- Helper-library scripts should expose their contained functions in a structured way.

## Scope

The generated index applies to all script files in this repository with these extensions:

- `*.ps1`
- `*.sh`

The page should list every matching script in the repo, not just a hand-maintained subset.

## Content Discovery Rules

### Script inclusion

- Include every `ps1` and `sh` file in the repository.
- The index should be generated automatically from the repo contents.
- Script links should point directly to the script files using repo-relative paths.
- Script links should not use a leading `./`.

### Order

- Scripts should be sorted consistently.
- A stable alphabetical order based on repo-relative path is preferred.

## Documentation Extraction Rules

### Accepted top-level comment styles

The generator should extract documentation from the first meaningful top-level comment block using either of these formats:

- PowerShell / block help: `<# ... #>`
- Top-level line comments: `# ...`

### What counts as top-level

- Skip leading blank lines.
- Skip shell shebang lines like `#!/bin/bash`.
- For PowerShell, tolerate common wrappers before the first real help block, such as:
  - `function ...`
  - `filter ...`
  - attribute lines
  - `param(...)`
  - opening braces

The goal is to find the first real documentation block for the script or top-level function entry point.

### Comment normalization

- Strip comment markers.
- Trim leading and trailing blank lines.
- Ignore decorative separator lines made only of punctuation.
- Preserve meaningful paragraph breaks.

### Encoding tolerance

The parser should be resilient to common script encodings:

- `utf-8`
- `utf-8-sig`
- `cp1252`

If decoding still fails, fall back to replacement rather than crashing the build.

## Synopsis and Help Splitting

### `.SYNOPSIS`

If the extracted top-level comment contains `.SYNOPSIS` or the misspelled `.SYNOSPSIS`, split the documentation into:

- Visible synopsis:
  - only the content of the synopsis section
  - do not show the `.SYNOPSIS` header itself
- Expandable details:
  - all remaining help content outside the synopsis

### No `.SYNOPSIS`

If no `.SYNOPSIS` section exists:

- Use the whole extracted top-level comment as the visible summary by default.
- Do not create an expandable details section unless another rule below requires it.

## Expandable “Read More” Behavior

### General behavior

- Longer help content should be hidden by default.
- It should appear inside a spoiler-style expandable block using the same “Read more” interaction everywhere.
- The implementation should use a native expandable HTML pattern such as `<details>` / `<summary>`.

### `.DESCRIPTION` cleanup

If the first line of the expandable help is only a directive line matching `.DESCRIPTION`, ignore that line.

Do not remove `.DESCRIPTION` when:

- it appears later in the help
- it is part of a larger paragraph rather than a standalone first line

### Monospace styling

Expanded help should be visually distinct from the synopsis:

- render help text in a monospace font
- use a slightly different background from the main card
- preserve readability for multi-line examples and structured help text

### Directive emphasis

Inside expanded help, if a line matches this pattern:

- `^[.][A-Z]+ *$`

then that directive line should be rendered in bold.

Examples:

- `.EXAMPLE`
- `.OUTPUTS`
- `.NOTES`

This rule applies to regular script help blocks.

## Helper Library Special Case

### Trigger condition

For PowerShell scripts, if the top-level help is just a single line whose meaning is essentially “helper functions”, treat the file as a helper-library script.

This is intended for files such as:

- `helpers-networking.ps1`
- `helpers-processes.ps1`
- `helpers-DCs.ps1`

### Visible portion

For helper-library scripts:

- Keep the single “helper functions” line as the always-visible description.
- Do not append the function inventory directly under the synopsis.

### Expandable portion

Instead, use the same `Read more` expandable block used for long help sections and place the function inventory there.

### Function inventory contents

Inside the expandable section:

- Show all top-level function names defined in that helper script.
- For each function, include its `.SYNOPSIS` text if that function has one.
- If a function has no `.SYNOPSIS`, show just the function name.

### Function inventory formatting

- Function names must be bold.
- The list should be easy to scan.
- A normal unordered list inside the expandable section is appropriate.

### Function parsing constraints

When extracting helper-library function names:

- include only top-level function declarations
- only include functions whose `function Foo...` or `filter Foo...` declaration starts at column 1 with zero leading spaces
- do not include nested helper functions defined inside other functions
- do not include functions whose names start with `_`
- do not mistake prose in comment blocks for a function declaration
- only use a function’s real `.SYNOPSIS`, not its `.DESCRIPTION`

## Script Title Presentation

### Link styling

Each script entry should prominently display the script name as the primary clickable element.

The script name should be:

- slightly larger than normal body text
- visually stronger than the synopsis

### No leading dot artifact

The script name should not appear with a leading dot or bullet artifact.

Practical implication:

- if the entries are rendered in a list, remove default list bullets where they interfere with the title presentation

## Overall Page Structure

The generated page should stay close to the existing lightweight style of the repository:

- one main card/container
- page title
- short introductory sentence
- list of available downloads
- source repository link near the footer

The visual treatment should remain simple and utilitarian rather than decorative.

## Recommended Output Structure Per Script

Each script entry should conceptually render like this:

1. Script name as a clickable link
2. Visible short synopsis / summary
3. Optional expandable `Read more` block for:
   - long help text
   - helper-library function inventories

## Non-Goals

The generated index is not meant to:

- fully reproduce PowerShell help formatting exactly as in the console
- replace the scripts themselves as the source of truth
- render every section in a complex documentation-site layout

It should remain a compact browse-and-download page.

## Implementation Notes

A suitable generator should:

- scan the repository for scripts
- parse top-level comments
- split synopsis from remaining help
- detect helper-library scripts
- parse top-level functions and their synopses
- emit `index.html`

Associated CSS should provide:

- stronger script-link styling
- bullet-free script entry layout
- consistent `Read more` styling
- monospace expanded help blocks
- emphasized directive lines
- styled helper function lists
