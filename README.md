ACF-SDK | High-Performance Security Sidecar
Status: v0.1-Alpha (Core IPC & Lexical Kernel Verified)
Architecture: Policy Decision Point (PDP) Sidecar Pattern

This repository implements the Centralized Enforcement (Point 8) of the AI Control Framework. It separates security logic (Go) from the AI application (Python) using high-speed Inter-Process Communication (IPC).

🚀 Key Features
Dual-Language Bridge: High-performance Go Security Kernel + Developer-friendly Python SDK.

Ultra-Low Latency: Windows Named Pipes (\\.\pipe\acf_security_pipe) providing <1ms overhead.

Multi-Layer Defense: * L1 (Hygiene): Base64 de-obfuscation and Unicode normalization.

L2 (Lexical): Deterministic regex-based SQLi and Prompt Injection detection.

L3 (Heuristic): [Summer 2026 Goal] Semantic analysis via vector embeddings.
