package secret

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
)

// fakeKeyhole behaves like `keyhole get` with stdout as a pipe: the
// password on stdout, the username on stderr, plus an age touch prompt.
func fakeKeyhole(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-keyhole")
	script := `#!/bin/sh
echo "age: fido2-hmac plugin: Please touch your token..." >&2
case "$1" in
  r2-test) echo "AKID123" >&2; printf 'SECRET456\n' ;;
  r2-label) echo "username: AKID789" >&2; printf 'SECRET000\n' ;;
  *) echo "keyhole: no entry $1" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeyholePair(t *testing.T) {
	cfg := &config.Config{Keyhole: config.Keyhole{Command: fakeKeyhole(t)}}
	r := New(cfg)
	var prompts bytes.Buffer
	r.Stderr = &prompts
	p, err := r.Pair(context.Background(), "keyhole:r2-test")
	if err != nil {
		t.Fatal(err)
	}
	if p.AccessKeyID != "AKID123" || p.SecretAccessKey != "SECRET456" {
		t.Fatalf("got %+v", p)
	}
	if !strings.Contains(prompts.String(), "touch your token") {
		t.Fatal("touch prompt should reach the user")
	}
	if strings.Contains(prompts.String(), "SECRET456") || strings.Contains(prompts.String(), "AKID123") {
		t.Fatal("values must not be printed")
	}
}

func TestKeyholeUsernameLabel(t *testing.T) {
	r := New(&config.Config{Keyhole: config.Keyhole{Command: fakeKeyhole(t)}})
	r.Stderr = &bytes.Buffer{}
	p, err := r.Pair(context.Background(), "keyhole:r2-label")
	if err != nil || p.AccessKeyID != "AKID789" {
		t.Fatalf("want AKID789 without the label, got %q %v", p.AccessKeyID, err)
	}
}

func TestKeyholeMissingEntry(t *testing.T) {
	r := New(&config.Config{Keyhole: config.Keyhole{Command: fakeKeyhole(t)}})
	r.Stderr = &bytes.Buffer{}
	if _, err := r.Pair(context.Background(), "keyhole:nope"); err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("want 'no entry' error, got %v", err)
	}
}

func TestKeyholeRejectsShellInName(t *testing.T) {
	r := New(&config.Config{Keyhole: config.Keyhole{Command: fakeKeyhole(t)}})
	if _, err := r.Pair(context.Background(), "keyhole:x; rm -rf ~"); err == nil {
		t.Fatal("names with shell characters must be refused")
	}
}

func TestEnvPair(t *testing.T) {
	t.Setenv("T_ACCESS_KEY_ID", "a")
	t.Setenv("T_SECRET_ACCESS_KEY", "b")
	p, err := New(&config.Config{}).Pair(context.Background(), "env:T")
	if err != nil || p.AccessKeyID != "a" || p.SecretAccessKey != "b" {
		t.Fatalf("%+v %v", p, err)
	}
}
