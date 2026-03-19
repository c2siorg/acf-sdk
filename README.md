# ACF-SDK | Phase 1: Go Sidecar Listener

This fork implements the high-performance **Sidecar Kernel** architecture.

## ?? Status: Phase 1 (Baseline Implementation)
- **Transport Layer:** Go-based Sidecar (v1.1 Binary Handshake)
- **IPC Protocol:** Windows Named Pipes (\\\\.\\pipe\\acf_pipe)
- **Latency Goal:** <1ms IPC overhead (Verified)

### ??? How to run the Sidecar (Go 1.26+)
```cmd
go run cmd/sidecar/main.go
```

### ?? Project Structure
- `/cmd/sidecar`: Go Security Kernel (The "PDP")
- `/python/src/acf_sdk`: Python Interceptor (The "PEP")
