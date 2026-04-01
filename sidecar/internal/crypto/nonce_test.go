package crypto

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNonceStore_FirstUse(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	defer ns.Stop()

	nonce := []byte("0123456789abcdef") // 16 bytes
	if ns.Seen(nonce) {
		t.Error("Seen returned true on first use — expected false")
	}
}

func TestNonceStore_Replay(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	defer ns.Stop()

	nonce := []byte("0123456789abcdef")
	ns.Seen(nonce) // first use — records it
	if !ns.Seen(nonce) {
		t.Error("Seen returned false on replay — expected true")
	}
}

func TestNonceStore_DifferentNonces(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	defer ns.Stop()

	n1 := []byte("nonce-one-111111")
	n2 := []byte("nonce-two-222222")
	if ns.Seen(n1) {
		t.Error("nonce1 first use should return false")
	}
	if ns.Seen(n2) {
		t.Error("nonce2 first use should return false")
	}
}

func TestNonceStore_Expiry(t *testing.T) {
	ttl := 50 * time.Millisecond
	ns := NewNonceStore(ttl)
	defer ns.Stop()

	nonce := []byte("expiring-nonce!!")
	ns.Seen(nonce) // record it

	// Wait for TTL + eviction cycle to pass
	time.Sleep(ttl * 3)

	if ns.Seen(nonce) {
		t.Error("Seen returned true after TTL expired — expected false")
	}
}

func TestNonceStore_Concurrent(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	defer ns.Stop()

	var wg sync.WaitGroup
	const goroutines = 100
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			nonce := []byte(fmt.Sprintf("nonce-%016d", i))
			ns.Seen(nonce)
		}()
	}
	wg.Wait()
}

func TestNonceStore_SeenString(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	defer ns.Stop()

	if ns.SeenString("string-nonce") {
		t.Fatal("SeenString returned true on first use")
	}
	if !ns.SeenString("string-nonce") {
		t.Fatal("SeenString returned false on replay")
	}
}