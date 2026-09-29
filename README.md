# VulnCheck

VulnCheck is a SwiftUI iOS security-audit utility for **authorized, passive HTTP response checks**.

The project is designed as a small, self-contained security research tool: enter an HTTPS target, run a non-destructive request, review the security findings, and keep supporting research notes in the repository.

## What it does

### Security Audit
The scanner performs passive checks against an HTTPS endpoint and reports issues in the HTTP response, including:

- missing or weak security headers
- missing HSTS
- missing Content Security Policy
- clickjacking protection gaps
- exposed `Server` / `X-Powered-By` headers
- insecure cookie attributes
- permissive CORS configurations
- cross-host redirect observations

The scanner uses a normal `URLSession` request and does **not** disable TLS verification or bypass platform security controls.

### Findings
Findings are grouped by severity and include:

- title
- severity
- evidence
- remediation guidance
- expandable details

### Exploit Catalog
The second section is an informational catalog of publicly documented security research references and affected-version notes.

It is a **reference database only**. VulnCheck does not execute exploit payloads, perform privilege escalation, or attempt sandbox escapes.

### CoreTrust research archive
The `CoreTrust/` directory stores text-based research material such as:

- decompilation notes
- call / cross-reference reports
- vector reports
- validation notes
- AMFI / PPL / SPTM-related research notes

These files are kept as a research archive and should be treated as working material rather than automatically verified conclusions.

## Project structure

```text
VulnCheck/
├── .github/
│   └── workflows/
│       └── ios-build.yml          # GitHub Actions iOS build
├── CoreTrust/                     # CoreTrust research archive
│   ├── *.txt
│   └── README.txt
├── VulnCheck/
│   ├── ContentView.swift          # Main UI and scanner screens
│   ├── ExploitCatalogView.swift   # Informational exploit catalog
│   ├── ScannerEngine.swift        # HTTPS request / scan engine
│   ├── ScannerModels.swift        # Scan and finding models
│   ├── SecurityChecks.swift       # Passive response checks
│   └── VulnCheckApp.swift         # App entry point
├── VulnCheckTests/
│   └── SecurityChecksTests.swift  # Unit tests for security checks
├── project.yml                    # XcodeGen project definition
└── README.md
```

## Architecture

The app is intentionally split into a few small layers:

```text
SwiftUI UI
   │
   ├── ScanViewModel
   │      │
   │      └── ScannerEngine
   │               │
   │               └── URLSession
   │
   ├── SecurityChecks
   │      └── HTTP response analysis
   │
   └── ScanReport / Finding models
```

The UI is built with SwiftUI. The minimum deployment target is iOS 16, which matches the use of `NavigationStack` and other iOS 16-era SwiftUI APIs. citeturn719861search2turn719861search1

## Build

The repository is generated with [XcodeGen](https://github.com/yonaskolb/XcodeGen).

The GitHub Actions workflow:

1. checks out the repository
2. selects Xcode 26 on the macOS runner
3. generates `VulnCheck.xcodeproj`
4. builds an iOS device target
5. packages an unsigned IPA
6. uploads the IPA and build log as workflow artifacts

The repository intentionally builds the IPA without embedding signing credentials in source control. Signing can be performed separately with the appropriate Apple-issued certificate and provisioning setup.

## Local development

A Mac with Xcode is required for a native iOS build.

Typical workflow:

```bash
brew install xcodegen
xcodegen generate
xcodebuild -project VulnCheck.xcodeproj \
  -scheme VulnCheck \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS'
```

## Testing

Security checks live in `VulnCheck/SecurityChecks.swift` and are covered by unit tests in `VulnCheckTests/SecurityChecksTests.swift`.

When adding a new check, prefer:

1. a focused helper in `SecurityChecks.swift`
2. a deterministic unit test
3. clear evidence text
4. a remediation recommendation
5. a severity that is explained by the concrete condition being detected

## Scope and safety

VulnCheck is intended for systems you own or are explicitly authorized to assess.

The scanner is deliberately non-destructive. It does not provide:

- credential attacks
- brute force
- port scanning
- mass target scanning
- exploit payload execution
- TLS verification bypass
- destructive requests

The exploit catalog is informational and does not turn the app into an exploitation framework.

## Research notes

Research artifacts that are useful for the project but are not application source code belong under `CoreTrust/`.

Keep raw observations separate from conclusions when possible. Include version/build context, source references, and validation status in new notes so later analysis can distinguish evidence from interpretation.

## Status

VulnCheck is an active prototype. The core passive scanner, findings UI, exploit reference section, tests, and GitHub Actions build pipeline are already present; the surrounding research archive is being expanded alongside the application.

## Roadmap

Planned work includes:

- richer response/header evidence in Findings
- scan history
- exportable reports
- better target validation and error states
- more passive checks
- improved exploit-catalog metadata and filtering
- additional automated tests

## Contributing

Small, focused changes are preferred. Avoid mixing UI redesigns, scanner logic changes, and unrelated refactors in the same commit.

See `CONTRIBUTING.md` for the project workflow.

## Security

For security issues in the project itself, see `SECURITY.md`.
