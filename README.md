# ACF-SDK — Agentic Cognitive Firewall

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Build](https://github.com/c2siorg/acf-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/c2siorg/acf-sdk/actions/workflows/ci.yml)

A Zero Trust security layer for LLM agents. Enforces policy-driven validation at every point an agent ingests input — not just at the front door.

> **Status: Phase 2 Active — High-Performance $O(n)$ Lexical Kernel & Windows IPC Verified.**

---

## 🚀 Key Features

- **Dual-Language Bridge:** High-performance Go Security Kernel (PDP) + Developer-friendly Python SDK (PEP).
- **Cross-Platform IPC:** Seamless support for Windows Named Pipes (`\\.\pipe\acf_security_pipe`) and Unix Domain Sockets.
- **Cognitive Pipeline:** 4-Stage enforcement (Validate → Normalise → Scan → Aggregate) running in <10ms.
- **Advanced Normalisation:** Defeats obfuscation via recursive Base64/URL decoding and Unicode NFKC cleaning.

---

## How it works



The sidecar runs every payload through a four-stage pipeline before evaluating OPA (Rego) policies:

| Stage | Responsibility |
|---|---|
| **1. Validate** | HMAC integrity verification, Nonce replay protection, and DoS size limiting (1MB). |
| **2. Normalise** | De-obfuscation: URL/Base64 decoding, Zero-width stripping, and Leetspeak cleaning. |
| **3. Scan** | **Lexical Kernel:** $O(n)$ Aho-Corasick multi-pattern scanning against threat libraries. |
| **4. Aggregate** | Risk scoring (0.0–1.0) with provenance trust weighting (User vs. System sources). |

---

## Project Structure

```text
acf-sdk/
├── sidecar/               Go enforcement kernel (PDP)
│   ├── cmd/sidecar/       Entrypoint & IPC Listener
│   └── internal/pipeline/ 4-Stage Security Engine
├── sdk/
│   └── python/            Python SDK (PEP) with Secure Binary Protocol
├── policies/v1/           Rego policies + Pattern Data
└── tests/                 Integration & Adversarial test suites