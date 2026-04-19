//go:build windows

package main

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio" 
	"github.com/eddymontana/acf-sdk/internal/kernel"
)

func main() {
	pipePath := `\\.\pipe\acf_security_pipe`
	fmt.Println("=== ACF Security Sidecar (Go-PDP) v1.6 Running ===")
	
	// 1. Start the Listener
	l, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer l.Close()

	fmt.Println("[STATUS] Listening for Python SDK on Named Pipe...")

	// 2. The Service Loop (This keeps the program from exiting)
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		
		// Handle each request in a separate "thread" (Goroutine)
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	
	// Read from Python
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	payload := string(buf[:n])

	// Security Logic
	cleanText, l1Flags := kernel.HygieneCheck(payload)
	l2Flags := kernel.LexicalScan(cleanText)
	finalMask := uint16(l1Flags | l2Flags)

	// Send 2-byte response back to Python
	res := []byte{byte(finalMask), byte(finalMask >> 8)}
	conn.Write(res)
	
	fmt.Printf("[LOG] Handled Request. Flags: %016b\n", finalMask)
}