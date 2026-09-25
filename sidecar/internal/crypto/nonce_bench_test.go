package crypto

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

// BenchmarkNonceStoreSeen measures the replay check for a fresh nonce, with
// the store empty and holding 100k live nonces (about 5 minutes at 330 req/s).
func BenchmarkNonceStoreSeen(b *testing.B) {
	for _, stored := range []int{0, 100_000} {
		b.Run(fmt.Sprintf("stored=%d", stored), func(b *testing.B) {
			ns := NewNonceStore(5 * time.Minute)
			defer ns.Stop()
			var nonce [16]byte
			for i := 0; i < stored; i++ {
				binary.BigEndian.PutUint64(nonce[8:], uint64(i))
				ns.Seen(nonce[:])
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// The high half is never zero here, so no prefilled nonce repeats.
				binary.BigEndian.PutUint64(nonce[:8], uint64(i)+1)
				if ns.Seen(nonce[:]) {
					b.Fatal("fresh nonce reported as a replay")
				}
			}
		})
	}
}
