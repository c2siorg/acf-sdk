package decision

import "testing"

func TestDecisionConstants_UniqueValues(t *testing.T) {
	if Allow == Sanitise || Allow == Block || Sanitise == Block {
		t.Fatal("decision constants must have unique values")
	}
}

func TestDecisionConstants_ExpectedBytes(t *testing.T) {
	tests := []struct {
		name     string
		got      byte
		expected byte
	}{
		{"Allow", Allow, 0x00},
		{"Sanitise", Sanitise, 0x01},
		{"Block", Block, 0x02},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = 0x%02x, want 0x%02x", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestDecisionConstants_SingleByte(t *testing.T) {
	// Verify all decisions fit in a single byte (wire protocol requirement)
	for _, d := range []byte{Allow, Sanitise, Block} {
		if d > 0xFF {
			t.Errorf("decision 0x%02x exceeds single byte", d)
		}
	}
}
