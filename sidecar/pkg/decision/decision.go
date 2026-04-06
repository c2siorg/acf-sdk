// Package decision defines the wire protocol decision constants shared between
// the transport and pipeline packages, avoiding import cycles.
package decision

const (
	// Allow indicates the request may proceed unchanged.
	Allow = byte(0x00)
	// Sanitise indicates the request should be sanitised before proceeding.
	Sanitise = byte(0x01)
	// Block indicates the request must be rejected.
	Block = byte(0x02)
)
