# Changelog

All notable changes to **RUK_HACKER** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-10-22

First public release. A complete, dependency-free security toolkit for Termux (Android).

### Added

**Core**
- Colourful interactive CLI with ASCII banner and numbered menu.
- Full subcommand interface: `scan`, `ports`, `dns`, `web`, `whois`, `ip`, `ssl`,
  `subdomains`, `dirscan`, `sysinfo`, `report`, `update`, `version`, `config`.
- Modular package layout (`ruk_hacker/`) with one module per capability.
- Global rate limiting, thread caps and per-connection timeouts.
- One-time authorised-use consent prompt, persisted to a local state file.

**Reconnaissance**
- Portable TCP connect port scanner: port-spec parsing (`22`, `1-1024`, `80,443`,
  `top`, `all`), service names, banner grabbing and severity flags for risky ports.
- Pure-stdlib DNS client: A, AAAA, MX, NS, TXT, SOA, CAA and SRV records over UDP
  with automatic TCP fallback on truncation, plus full name-compression parsing.
- Reverse DNS (PTR) lookup and CNAME chain tracing.
- WHOIS client over port 43 for domains and IPs, with IANA referral following and
  expiry countdown.
- IP intelligence: country, city, ISP, ASN and reverse DNS, plus a `--me` mode.
- Subdomain enumeration via DNS brute-force plus certificate-transparency (crt.sh)
  log harvesting, with wildcard-DNS filtering to remove false positives.
- Directory / path discovery with data-driven wordlists and soft-404 detection so
  catch-all servers do not produce fake hits.

**Web & TLS**
- HTTP header inspection: status, redirect chain, server fingerprinting.
- Security header grading (A+ → F) covering CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy and more.
- Cookie flag analysis (Secure, HttpOnly, SameSite).
- Fingerprinting of common frameworks, servers and CDNs from headers and body.
- TLS/SSL inspection: subject, issuer, SAN list, validity window, expiry countdown,
  chain trust evaluation, negotiated cipher, certificate SHA-256 and self-signed
  detection.

**Reporting**
- JSON, standalone HTML and plain-text report rendering.
- HTML reports are fully self-contained and readable offline.
- Every report embeds the target, timestamp, tool version and findings.

**Operations**
- `install.sh` — one-command Termux setup with optional dependency prompt,
  command aliasing (`ruk_hacker` and `ruk`), and a post-install self-test.
- `uninstall.sh` — clean removal with `--dry-run` and `--purge` modes.
- `update` subcommand — safe `git pull --ff-only` style update check.
- Device/system introspection (`sysinfo`): model, CPU, RAM, storage, interfaces.
- `.gitignore` covering Python artefacts, runtime reports and secrets.
- MIT licence.

**Testing**
- 49 unit tests covering port-spec parsing, target validation, DNS wire format
  encode/parse, rate limiting, grading logic, cookie analysis, WHOIS parsing and
  every report renderer.
- 22 smoke tests running the full tool against real local TCP, HTTP and TLS
  servers, including soft-404 filtering, CLI subprocess invocation and report
  file generation.
- Total: **71 tests, all passing**.

### Security
- Read-only by design: the tool never writes, uploads or modifies anything on a
  target.
- Explicit authorised-use notice, acknowledged once and enforced on first run.
- Rate limiting and conservative timeouts to avoid disruptive scanning.

---

## Roadmap

Ideas under consideration for future releases — not committed:

- PDF report output.
- UDP service probes alongside the existing TCP connect scan.
- Guided wizard mode for first-time users.
- Pluggable wordlists loaded from the user's own files.

---

[1.0.0]: https://github.com/Janrahat/RUK_HACKER/releases/tag/v1.0.0
