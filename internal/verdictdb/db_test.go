package verdictdb

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/attach-dev/attach-open-score/pkg/schema"
)

func TestPutEvictsOldestBeyondCap(t *testing.T) {
	original := maxEntries
	maxEntries = 20
	t.Cleanup(func() { maxEntries = original })

	db := New(filepath.Join(t.TempDir(), "scores.json"))

	total := maxEntries + 10
	for i := 0; i < total; i++ {
		key := NormalizeKey("npm", fmt.Sprintf("pkg-%d", i), "1.0.0", "default")
		if err := db.Put(key, schema.Verdict{Decision: schema.DecisionAllow}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}

	data, err := db.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != maxEntries {
		t.Fatalf("entries = %d, want capped at %d", len(data.Entries), maxEntries)
	}

	// The 10 oldest should have been evicted; the newest must still be present.
	if _, ok, _ := db.Get(NormalizeKey("npm", "pkg-0", "1.0.0", "default")); ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok, _ := db.Get(NormalizeKey("npm", fmt.Sprintf("pkg-%d", total-1), "1.0.0", "default")); !ok {
		t.Fatal("newest entry should be retained")
	}
}

func TestPutUpdateDoesNotGrow(t *testing.T) {
	db := New(filepath.Join(t.TempDir(), "scores.json"))
	key := NormalizeKey("npm", "left-pad", "1.3.0", "default")
	for i := 0; i < 5; i++ {
		if err := db.Put(key, schema.Verdict{Decision: schema.DecisionAllow}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := db.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (updates replace in place)", len(data.Entries))
	}
}
