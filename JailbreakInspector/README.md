# Jailbreak Inspector

This package contains a research-focused SwiftUI iOS application and a reusable detection engine for jailbreak, environment, sandbox, and runtime inspection.

## Overview

The project follows an evidence-based architecture:

- Each detector returns a `DetectionResult` object instead of a single boolean.
- A central `SecurityScanner` orchestrates detectors independently.
- `ScoreEngine` produces a weighted score and a plain-language assessment.
- The app can export JSON and show technical evidence for each detector.

## Package layout

- `Sources/JailbreakInspectorCore` — cross-platform detection logic and scoring
- `Sources/JailbreakInspectorApp` — SwiftUI screens and app entry point
- `Tests/JailbreakInspectorCoreTests` — unit tests for score and export logic

## IOSSecuritySuite integration

The app integrates with `IOSSecuritySuite` as the primary jailbreak and debugger detection library when the package is built for iOS. It is used as an additional signal and never treated as a single definitive proof of jailbreak.

## Notes

- This is a diagnostic tool and not an anti-jailbreak DRM mechanism.
- Detection is inherently bypassable, and findings should be treated as evidence, not certainty.
- Rootless jailbreak layouts and false positives are explicitly considered.
