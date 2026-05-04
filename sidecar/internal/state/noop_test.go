package state

import "testing"

func TestNoopStore_GetReturnsNil(t *testing.T) {
	store := &NoopStore{}
	result := store.Get("any-session-id")
	if result != nil {
		t.Errorf("NoopStore.Get should return nil, got %v", result)
	}
}

func TestNoopStore_GetDifferentKeys(t *testing.T) {
	store := &NoopStore{}
	keys := []string{"session-1", "session-2", "", "abc-123"}
	for _, key := range keys {
		if store.Get(key) != nil {
			t.Errorf("NoopStore.Get(%q) should return nil", key)
		}
	}
}

func TestNoopStore_SetDoesNotPanic(t *testing.T) {
	store := &NoopStore{}
	// Set should be a no-op — must not panic on any input
	store.Set("session-1", "some-value")
	store.Set("", nil)
	store.Set("key", map[string]any{"score": 0.5})
}

func TestNoopStore_SetThenGetReturnsNil(t *testing.T) {
	store := &NoopStore{}
	store.Set("session-1", "stored-value")
	result := store.Get("session-1")
	if result != nil {
		t.Errorf("NoopStore is stateless — Get after Set should still return nil, got %v", result)
	}
}

func TestNoopStore_Stateless(t *testing.T) {
	// Verify that NoopStore maintains no state between calls
	store := &NoopStore{}
	store.Set("s1", "val1")
	store.Set("s2", "val2")
	store.Set("s3", "val3")

	for _, key := range []string{"s1", "s2", "s3"} {
		if store.Get(key) != nil {
			t.Errorf("NoopStore should be stateless, Get(%q) returned non-nil", key)
		}
	}
}
