package secret

import (
	"os"
	"testing"
)

// TestMain points the agent socket at a private folder so tests never talk
// to a real cfr2 agent that may be running for the user.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfr2t")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_RUNTIME_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
