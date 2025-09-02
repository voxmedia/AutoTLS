# AutoTLS — Roadmap

* Last updated: **2025‑08‑25**
* Maintainers: SRE team (primary: Barbara Shaurette)

---

## Vision

A lightweight, production‑tested tool that automates TLS certificate issuance, rotation, and distribution, with **pluggable providers** for DNS challenges and secrets storage.

## Principles

* **Safety first:** idempotent operations, test modes, and clear rollback
* **Sharp edges wrapped:** sane defaults, explicit switches for impactful changes
* **Pluggability over hardcoding:** providers as modules
* **Observability:** structured logs; hooks for metrics
* **Docs as a feature:** example snippets included

## Current Snapshot (2025‑08‑21)

* Packaging: `pyproject.toml` with `requires-python = ">=3.9"`.
* Tooling: `pytest`, `pytest-cov`, `ruff`; GitHub Actions present for testing.
* App structure: Flask application factory pattern in progress; internal version stable.
* ACME: Let’s Encrypt via `acme` library; AWS Route 53 for DNS‑01; AWS Secrets Manager for storage; Fastly API integration in internal build.

## Roadmap / Future Features

**Core priorities (short-term)**

* **Additional DNS plugins**: Support for providers beyond AWS Route 53.
    - Cloudflare
    - Google Cloud DNS
    - GoDaddy

* **Additional secrets backends**:
    - Hashicorp Vault
    - GCP Secret Manager
    - local filesystem

* **Write a database initialization helper** that is database agnostic and leverages the existing models

* **Replace deprecated pyOpenSSL calls** with `cryptography` (include any tests that touch functionality that uses pyOpenSSL)

* **Fastly integration enhancements**: Integrate utility scripts for clearing expired keys and listing current certificates.

* **Write troubleshooting docs** (ACME, DNS propagation, Fastly deploys).

* **Improve error handling consistency** (decide on returns vs. exceptions vs. unified result objects, and Slack notifier integration)

* **Improve test coverage** (including new tests for the secrets and DNS backends)

---

**Advanced features (medium-term)**

* **Notifications plugin** to provide alternatives to Slack

* Add a dry‑run alternative to testmode (primarily to validate the Fastly step without uploading)

---

**Stretch goals / nice-to-haves (long-term)**

* **Multi-account DNS management**: Cross-account/organization DNS automation, including minimal‑privilege IAM examples for AWS

* **Pluggable certificate authorities**: Support for alternatives to Let’s Encrypt (e.g., ZeroSSL) behind common ACME interface.

* **Config & CLI polish**: More robust CLI options, YAML config validation, and helpful error messages.


