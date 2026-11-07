// Package config loads ~/.config/cfr2/config.toml.
//
// The file never holds a secret. Credentials are references that the
// secret package resolves at run time:
//
//	keyhole:NAME          keyhole entry: username = access key id, password = secret
//	bao:MOUNT/PATH        OpenBao KV v2 entry with access_key_id / secret_access_key
//	env:PREFIX            PREFIX_ACCESS_KEY_ID / PREFIX_SECRET_ACCESS_KEY
//
// A literal key in the file is refused.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// ErrNoConfig means no config file was found.
var ErrNoConfig = errors.New("no cfr2 config found")

// Bucket is one [buckets.NAME] table.
type Bucket struct {
	Name        string `toml:"-"`
	Credentials string `toml:"credentials"` // keyhole:/bao:/env: reference
	Share       *bool  `toml:"share"`       // presigned share links allowed (default true)
	Encrypt     string `toml:"encrypt"`     // default encryption for push: age | gpg | none
}

// ShareAllowed reports whether `cfr2 share` may sign links for this bucket.
func (b Bucket) ShareAllowed() bool { return b.Share == nil || *b.Share }

// Keyhole says how to run keyhole. NAME is appended to Command.
type Keyhole struct {
	Command string `toml:"command"`
}

// Bao says where OpenBao is and which token file to use.
type Bao struct {
	AddrFile  string `toml:"addr_file"`
	TokenFile string `toml:"token_file"`
}

// Encrypt holds the recipients and identities for age and gpg.
type Encrypt struct {
	Default       string   `toml:"default"`        // age | gpg | none (default age)
	AgeRecipients []string `toml:"age_recipients"` // age1... / ssh keys, or paths to recipient files
	AgeIdentities []string `toml:"age_identities"` // identity files for decrypt
	GPGRecipients []string `toml:"gpg_recipients"` // key ids / fingerprints / emails
}

// Usage holds the Cloudflare API token reference for `cfr2 usage`.
type Usage struct {
	Token string `toml:"token"` // keyhole:/bao:/env: reference to an Account Analytics Read token
}

// Sync maps a local folder to a bucket folder for `cfr2 status`.
type Sync struct {
	Local  string `toml:"local"`  // local folder, ~ allowed
	Remote string `toml:"remote"` // BUCKET:PREFIX/
}

// Config is the whole file.
type Config struct {
	AccountID     string            `toml:"account_id"`
	Endpoint      string            `toml:"endpoint"` // optional; derived from account_id
	Jurisdiction  string            `toml:"jurisdiction"`
	DefaultBucket string            `toml:"default_bucket"`
	Admin         string            `toml:"admin_credentials"` // optional, for bucket create/delete/rules
	Keyhole       Keyhole           `toml:"keyhole"`
	Bao           Bao               `toml:"bao"`
	Encrypt       Encrypt           `toml:"encrypt"`
	Usage         Usage             `toml:"usage"`
	Buckets       map[string]Bucket `toml:"buckets"`
	Sync          []Sync            `toml:"sync"`

	Path string `toml:"-"`
}

// DefaultPath is $XDG_CONFIG_HOME/cfr2/config.toml or ~/.config/cfr2/config.toml.
func DefaultPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "cfr2", "config.toml")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".config", "cfr2", "config.toml")
}

// Load reads path (or CFR2_CONFIG, or the default path) and validates it.
func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("CFR2_CONFIG")
	}
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w (looked at %s; run `cfr2 init`)", ErrNoConfig, path)
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if _, err := toml.Decode(string(data), &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	for name, b := range c.Buckets {
		b.Name = name
		c.Buckets[name] = b
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Parse is Load for an in-memory document (tests).
func Parse(doc string) (*Config, error) {
	var c Config
	if _, err := toml.Decode(doc, &c); err != nil {
		return nil, err
	}
	for name, b := range c.Buckets {
		b.Name = name
		c.Buckets[name] = b
	}
	return &c, c.validate()
}

// IsReference reports whether s is a secret reference rather than a literal.
func IsReference(s string) bool {
	for _, p := range []string{"keyhole:", "bao:", "env:"} {
		if strings.HasPrefix(s, p) && len(s) > len(p) {
			return true
		}
	}
	return false
}

func (c *Config) validate() error {
	if c.AccountID == "" && c.Endpoint == "" {
		return errors.New("account_id (or endpoint) is required")
	}
	if len(c.Buckets) == 0 {
		return errors.New("at least one [buckets.NAME] table is required")
	}
	for name, b := range c.Buckets {
		if b.Credentials == "" {
			return fmt.Errorf("buckets.%s: credentials is required", name)
		}
		if !IsReference(b.Credentials) {
			return fmt.Errorf("buckets.%s: credentials must be keyhole:NAME, bao:PATH or env:PREFIX, never a literal key", name)
		}
		switch b.Encrypt {
		case "", "age", "gpg", "none":
		default:
			return fmt.Errorf("buckets.%s: encrypt must be age, gpg or none", name)
		}
	}
	for field, v := range map[string]string{"admin_credentials": c.Admin, "usage.token": c.Usage.Token} {
		if v != "" && !IsReference(v) {
			return fmt.Errorf("%s must be keyhole:NAME, bao:PATH or env:PREFIX, never a literal", field)
		}
	}
	for i, m := range c.Sync {
		b, _, ok := strings.Cut(m.Remote, ":")
		if m.Local == "" || !ok {
			return fmt.Errorf("sync[%d]: want local = \"DIR\" and remote = \"BUCKET:PREFIX/\"", i)
		}
		if _, known := c.Buckets[b]; !known {
			return fmt.Errorf("sync[%d]: bucket %q is not configured", i, b)
		}
	}
	switch c.Encrypt.Default {
	case "", "age", "gpg", "none":
	default:
		return errors.New("encrypt.default must be age, gpg or none")
	}
	if c.DefaultBucket != "" {
		if _, ok := c.Buckets[c.DefaultBucket]; !ok {
			return fmt.Errorf("default_bucket %q has no [buckets.%s] table", c.DefaultBucket, c.DefaultBucket)
		}
	}
	return nil
}

// S3Endpoint returns the R2 S3 endpoint for this account.
func (c *Config) S3Endpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	if c.Jurisdiction != "" {
		return fmt.Sprintf("https://%s.%s.r2.cloudflarestorage.com", c.AccountID, c.Jurisdiction)
	}
	return fmt.Sprintf("https://%s.r2.cloudflarestorage.com", c.AccountID)
}

// Bucket returns the named bucket, or the default one when name is empty.
func (c *Config) Bucket(name string) (Bucket, error) {
	if name == "" {
		name = c.DefaultBucket
	}
	if name == "" {
		if len(c.Buckets) == 1 {
			for _, b := range c.Buckets {
				return b, nil
			}
		}
		return Bucket{}, fmt.Errorf("no bucket given and no default_bucket set (have: %s)", strings.Join(c.BucketNames(), ", "))
	}
	b, ok := c.Buckets[name]
	if !ok {
		return Bucket{}, fmt.Errorf("bucket %q is not in the config (have: %s)", name, strings.Join(c.BucketNames(), ", "))
	}
	return b, nil
}

// BucketNames returns the configured bucket names, sorted.
func (c *Config) BucketNames() []string {
	out := make([]string, 0, len(c.Buckets))
	for n := range c.Buckets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// EncryptionFor returns the push encryption for bucket b.
func (c *Config) EncryptionFor(b Bucket) string {
	if b.Encrypt != "" {
		return b.Encrypt
	}
	if c.Encrypt.Default != "" {
		return c.Encrypt.Default
	}
	return "age"
}

// ExpandPath expands a leading ~/.
func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return filepath.Join(h, p[2:])
	}
	return p
}
