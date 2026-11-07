package crypt

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
)

func TestAgeRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age not installed")
	}
	dir := t.TempDir()
	id := filepath.Join(dir, "id.txt")
	out, err := exec.Command("age-keygen", "-o", id).CombinedOutput()
	if err != nil {
		t.Fatalf("age-keygen: %v %s", err, out)
	}
	pub, err := exec.Command("age-keygen", "-y", id).Output()
	if err != nil {
		t.Fatal(err)
	}
	e := config.Encrypt{AgeRecipients: []string{strings.TrimSpace(string(pub))}, AgeIdentities: []string{id}}
	roundTrip(t, Age, e)
}

func TestGPGRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	home := t.TempDir()
	os.Chmod(home, 0o700)
	t.Setenv("GNUPGHOME", home)
	gen := exec.Command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", "cfr2 test <cfr2-test@example.invalid>", "ed25519", "default", "never")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("gpg keygen: %v %s", err, out)
	}
	sub := exec.Command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-add-key", fingerprint(t), "cv25519", "encr", "never")
	if out, err := sub.CombinedOutput(); err != nil {
		t.Fatalf("gpg subkey: %v %s", err, out)
	}
	roundTrip(t, GPG, config.Encrypt{GPGRecipients: []string{"cfr2-test@example.invalid"}})
}

func fingerprint(t *testing.T) string {
	out, err := exec.Command("gpg", "--batch", "--with-colons", "--list-keys", "cfr2-test@example.invalid").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "fpr:") {
			return strings.Split(l, ":")[9]
		}
	}
	t.Fatal("no fingerprint")
	return ""
}

func roundTrip(t *testing.T, s Scheme, e config.Encrypt) {
	t.Helper()
	plain := []byte("secret notes\nline two\n")
	var ct, back bytes.Buffer
	if err := Encrypt(s, e, bytes.NewReader(plain), &ct); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct.Bytes(), []byte("secret notes")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	if err := Decrypt(s, e, &ct, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Bytes(), plain) {
		t.Fatalf("round trip changed the data: %q", back.String())
	}
}

func TestFromName(t *testing.T) {
	for name, want := range map[string]Scheme{"a.age": Age, "b.gpg": GPG, "c.pgp": GPG, "d.txt": None} {
		if got := FromName(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}

func TestMissingRecipientsIsAnError(t *testing.T) {
	if _, err := EncryptArgs(Age, config.Encrypt{}); err == nil {
		t.Fatal("age without recipients must fail")
	}
	if _, err := EncryptArgs(GPG, config.Encrypt{}); err == nil {
		t.Fatal("gpg without recipients must fail")
	}
}
