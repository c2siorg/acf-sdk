//go:build windows

package main

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// dial connects over a Windows named pipe, waiting up to 5s for a free
// pipe instance when the sidecar is busy.
func dial(address string) (net.Conn, error) {
	timeout := 5 * time.Second
	return winio.DialPipe(address, &timeout)
}
