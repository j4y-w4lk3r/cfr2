package secret

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
)

func TestAgentCachesAndRefusesUnknownRefs(t *testing.T) {
	dir, err := os.MkdirTemp("", "cfr2a")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	count := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "kh")
	os.WriteFile(fake, []byte("#!/bin/sh\necho x >> "+count+"\necho AKID >&2\nprintf 'SEC\\n'\n"), 0o700)

	srv := New(&config.Config{Keyhole: config.Keyhole{Command: fake}})
	srv.Stderr, srv.InAgent = &bytes.Buffer{}, true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeAgent(ctx, srv, map[string]bool{"keyhole:r2-a": true}, time.Minute)
	for i := 0; i < 50 && !AgentAlive(); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !AgentAlive() {
		t.Fatal("agent did not start")
	}
	for i := 0; i < 2; i++ {
		cl := New(&config.Config{}) // no keyhole command: only the agent can answer
		p, err := cl.Pair(ctx, "keyhole:r2-a")
		if err != nil || p.AccessKeyID != "AKID" || p.SecretAccessKey != "SEC" {
			t.Fatalf("via agent: %+v %v", p, err)
		}
	}
	b, _ := os.ReadFile(count)
	if n := strings.Count(string(b), "x"); n != 1 {
		t.Fatalf("keyhole ran %d times, want 1", n)
	}
	if _, err := New(&config.Config{}).Pair(ctx, "keyhole:other"); err == nil || !strings.Contains(err.Error(), "not in the config") {
		t.Fatalf("unknown ref must be refused, got %v", err)
	}
	st, _ := os.Stat(filepath.Dir(AgentSocket()))
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("socket folder mode %v, want 0700", st.Mode().Perm())
	}
	if err := StopAgent(); err != nil {
		t.Fatal(err)
	}
}
