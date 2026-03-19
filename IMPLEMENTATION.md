## Implementation Strategy 
- Sidecar: Go 1.26 (Point 8: Centralized Enforcement) 
- SDK: Python 3.13 (Point 7: SDK-First Integration) 
- Transport: UDS (Point 3: Minimal Overhead) 
## Updated Pipeline Flow (Ref: Issue #3) 
1. SDK Interceptor (Python) - Pipe 
2. Policy-as-Code Engine (Go/YAML) - **Entry Point** 
3. Normalization Gate (Deterministic Logic) 
4. Heuristic/Semantic Scans 
5. Risk Aggregator - Decision (PASS/BLOCK) 
