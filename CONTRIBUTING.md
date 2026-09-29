# Contributing to VulnCheck

Thanks for contributing.

## Development principles

Keep changes small and reviewable. The project is intentionally compact, so clarity is more valuable than abstraction for its own sake.

For scanner changes:

- keep network behavior passive and non-destructive
- do not add TLS verification bypasses
- do not add credential attacks, brute force, or mass scanning
- add deterministic unit tests for new response checks
- document what evidence triggers a finding

For UI changes:

- keep the interface usable on both compact and large iPhone displays
- avoid hard-coded screen dimensions
- preserve Dynamic Type and safe-area behavior
- keep the three main sections focused: Scanner, Exploits, Findings

For research files:

- keep supporting text artifacts in `CoreTrust/`
- preserve original filenames when practical
- record version/build context
- distinguish raw observations from conclusions
- avoid presenting unverified hypotheses as established facts

## Build validation

Before opening a pull request:

```bash
xcodegen generate
xcodebuild -project VulnCheck.xcodeproj \
  -scheme VulnCheck \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS'
```

GitHub Actions is also used as the repository build check.
