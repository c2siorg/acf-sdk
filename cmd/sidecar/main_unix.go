//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"github.com/eddymontana/acf-sdk/internal/kernel"
)

func main() {
	socketPath := "/tmp/acf.sock"

	// Clean up the socket if it already exists
	os.Remove(socketPath)

	fmt.Println("=== ACF Security Sidecar (Go-PDP) v1.6 [UNIX] Running ===")

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Printf("Socket Error: %v\n", err)
		return
	}
	defer l.Close()

	// Ensure the socket is accessible
	os.Chmod(socketPath, 0666)

	fmt.Println("[STATUS] Listening on Unix Socket /tmp/acf.sock...")

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	payload := string(buf[:n])

	cleanText, l1Flags := kernel.HygieneCheck(payload)
	l2Flags := kernel.LexicalScan(cleanText)
	finalMask := uint16(l1Flags | l2Flags)

	res := []byte{byte(finalMask), byte(finalMask >> 8)}
	conn.Write(res)
}