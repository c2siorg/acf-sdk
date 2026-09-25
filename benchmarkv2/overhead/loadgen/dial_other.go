//go:build !windows

package main

import "net"

// dial connects over a Unix domain socket.
func dial(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}
