# scripts

A collection of scripts I use often.

See https://ndemou.github.io/scripts/

## Publishing a new release

This repository does not use a typical GitHub Release flow for publishing.
To publish a new release of the static script index, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\release\Publish-NewRelease.ps1
```

That script:

- runs all PowerShell test scripts under `.\tests\`
- stops immediately if any test fails
- runs `python .\build_index.py` only after all tests pass

This updates `index.html`, which is what powers https://ndemou.github.io/scripts/



