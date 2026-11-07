// Package crypt encrypts and decrypts streams with the age or gpg
// command-line tools. age is the default (it works with plugins such as
// age-plugin-fido2-hmac, so a hardware key can hold the identity); gpg
// is kept as a second option.
//
// Plaintext only ever flows through pipes. Nothing here writes a file.
package crypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
)

// Scheme is age, gpg or none.
type Scheme string

const (
	Age  Scheme = "age"
	GPG  Scheme = "gpg"
	None Scheme = "none"
)

// Suffix is the object-name suffix for a scheme.
func (s Scheme) Suffix() string {
	switch s {
	case Age:
		return ".age"
	case GPG:
		return ".gpg"
	}
	return ""
}

// FromName guesses the scheme from an object or file name.
func FromName(name string) Scheme {
	switch {
	case strings.HasSuffix(name, ".age"):
		return Age
	case strings.HasSuffix(name, ".gpg"), strings.HasSuffix(name, ".pgp"):
		return GPG
	}
	return None
}

// Parse turns a config/flag value into a Scheme.
func Parse(s string) (Scheme, error) {
	switch s {
	case "age", "":
		return Age, nil
	case "gpg":
		return GPG, nil
	case "none", "no", "off":
		return None, nil
	}
	return "", fmt.Errorf("unknown encryption %q (want age, gpg or none)", s)
}

// EncryptArgs returns the command for encrypting with scheme s.
func EncryptArgs(s Scheme, e config.Encrypt) ([]string, error) {
	switch s {
	case Age:
		if len(e.AgeRecipients) == 0 {
			return nil, errors.New("age: set [encrypt] age_recipients (age1... keys or recipient files)")
		}
		args := []string{"age", "--encrypt"}
		for _, r := range e.AgeRecipients {
			if isAgeKey(r) {
				args = append(args, "-r", r)
			} else {
				args = append(args, "-R", config.ExpandPath(r))
			}
		}
		return args, nil
	case GPG:
		if len(e.GPGRecipients) == 0 {
			return nil, errors.New("gpg: set [encrypt] gpg_recipients")
		}
		args := []string{"gpg", "--batch", "--yes", "--quiet", "--trust-model", "always", "--encrypt"}
		for _, r := range e.GPGRecipients {
			args = append(args, "--recipient", r)
		}
		return append(args, "--output", "-"), nil
	}
	return nil, fmt.Errorf("no encryption for scheme %q", s)
}

// DecryptArgs returns the command for decrypting with scheme s.
func DecryptArgs(s Scheme, e config.Encrypt) ([]string, error) {
	switch s {
	case Age:
		if len(e.AgeIdentities) == 0 {
			return nil, errors.New("age: set [encrypt] age_identities to decrypt")
		}
		args := []string{"age", "--decrypt"}
		for _, id := range e.AgeIdentities {
			args = append(args, "-i", config.ExpandPath(id))
		}
		return args, nil
	case GPG:
		return []string{"gpg", "--quiet", "--decrypt"}, nil
	}
	return nil, fmt.Errorf("no decryption for scheme %q", s)
}

func isAgeKey(s string) bool {
	return strings.HasPrefix(s, "age1") || strings.HasPrefix(s, "ssh-ed25519 ") || strings.HasPrefix(s, "ssh-rsa ")
}

// Pipe runs argv with in as stdin and out as stdout. stderr goes to the
// terminal so touch / PIN prompts are visible.
func Pipe(argv []string, in io.Reader, out io.Writer) error {
	if _, err := exec.LookPath(argv[0]); err != nil {
		return fmt.Errorf("%s is not installed", argv[0])
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = in
	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %v", argv[0], err)
	}
	return nil
}

// Encrypt streams in through the encryptor into out.
func Encrypt(s Scheme, e config.Encrypt, in io.Reader, out io.Writer) error {
	if s == None {
		_, err := io.Copy(out, in)
		return err
	}
	argv, err := EncryptArgs(s, e)
	if err != nil {
		return err
	}
	return Pipe(argv, in, out)
}

// Decrypt streams in through the decryptor into out.
func Decrypt(s Scheme, e config.Encrypt, in io.Reader, out io.Writer) error {
	if s == None {
		_, err := io.Copy(out, in)
		return err
	}
	argv, err := DecryptArgs(s, e)
	if err != nil {
		return err
	}
	return Pipe(argv, in, out)
}
