package main

import (
"fmt"
)

func main() {
fmt.Println("ACF-SDK Sidecar v1.1 - Starting...")
pipeName := `\\.\pipe\acf_pipe`
fmt.Printf("[*] Environment: Windows (Named Pipe: %%s)\n", pipeName)
fmt.Println("[*] Protocol: Binary Handshake (Magic: 0xAC)")
}
