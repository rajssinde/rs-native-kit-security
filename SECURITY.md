# Security Policy

This document covers reporting a vulnerability **in this SDK itself** (e.g. a detection bypass, a memory-safety issue in the native code, a bug that causes it to falsely report a device as secure). For guidance on the SDK's detection *capabilities and limitations* when integrating it into your own app, see [docs/SECURITY_NOTES.md](docs/SECURITY_NOTES.md).

## Supported versions

| Version | Supported |
|---|---|
| Latest `0.x` release | ✅ |
| Older `0.x` releases | Best-effort only |

Until `1.0.0`, only the latest published version receives security fixes — see [docs/MIGRATION.md](docs/MIGRATION.md#version-policy).

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Instead:

1. Use [GitHub's private vulnerability reporting](https://github.com/rajssinde/rs-native-kit-security/security/advisories/new) for this repository, if enabled, **or**
2. Email the maintainer listed in [package.json](package.json) with a description of the issue, steps to reproduce, and (if applicable) affected versions.

Please include:

- The affected platform(s) (Android/iOS) and OS/RN/library versions.
- Whether the issue is a **detection bypass** (a way to defeat a check that shouldn't be defeatable given this SDK's documented threat model — see [Security Notes](docs/SECURITY_NOTES.md#threat-model)), a **false "secure" report**, or a **native code issue** (crash, memory safety).
- A minimal reproduction if possible.

We aim to acknowledge reports within 5 business days.

## Scope

**In scope:**
- The SDK falsely reporting a device as secure/not-tampered/not-hooked when the opposite is true, for any signal within its documented [threat model](docs/SECURITY_NOTES.md#threat-model).
- Memory-safety, crash, or injection vulnerabilities in the native (Kotlin/Swift/C++) code.
- Vulnerabilities in the risk-scoring logic that could be trivially exploited to always land on `LOW`/`secure: true`.

**Out of scope (already documented, not vulnerabilities):**
- A statically-patched app binary defeating an in-process check — this is a fundamental limitation of any client-side detection SDK, not a bug in this one. See [Security Notes](docs/SECURITY_NOTES.md#threat-model).
- Platform checks that are hard-coded `false`/`true` because the underlying concept doesn't exist on that platform (e.g. `isRooted()` on iOS) — this is documented, intentional behavior, not a false negative.
