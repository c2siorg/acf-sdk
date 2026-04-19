## 🛠️ Implementation Strategy (Finalized v1.5)
- **Sidecar:** Go 1.26 (Centralized Enforcement)
- **SDK:** Python 3.13 (SDK-First Integration)
- **Transport:** UDS/Named Pipes (Minimal Overhead)

## 🏗️ The 3-Layer Shield (Ref: Issue #3)
To meet the strict **<10ms latency requirement**, the Go PDP follows a tiered "Short-Circuit" execution model.



### 1. SDK Interceptor (Python)
Captures the prompt at the source before it hits the LLM.

### 2. Normalization Gate (L1 - Go)
* **Mechanism:** Base64 Decoding & Unicode Normalization.
* **Latency:** ~0.1ms.

### 3. Lexical Scanner (L2 - Go)
* **Mechanism:** High-speed Regex Pattern Matching.
* **Purpose:** Deterministic blocking of SQLi and Prompt Injection.
* **Latency:** ~0.5ms.

### 4. Risk Aggregator & Watchdog (L3 - Go)
* **Mechanism:** Context-aware scanning (Heuristics).
* **Safety:** Enforced by a **9ms `context.WithTimeout`**.
* **Decision:** Fail-Closed (PASS/BLOCK).
