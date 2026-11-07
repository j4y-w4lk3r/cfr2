// Package app implements the cfr2 subcommands.
package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
	"github.com/j4y-w4lk3r/cfr2/internal/secret"
	"github.com/j4y-w4lk3r/cfr2/internal/storage"
)

// App holds the loaded config and the secret resolver for one run.
type App struct {
	Cfg    *config.Config
	Sec    *secret.Resolver
	Out    io.Writer
	Err    io.Writer
	In     io.Reader
	Bucket string // from -b / --bucket (empty = default)
}

// Open loads the config.
func Open(path, bucket string) (*App, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return &App{Cfg: cfg, Sec: secret.New(cfg), Out: os.Stdout, Err: os.Stderr, In: os.Stdin, Bucket: bucket}, nil
}

// Client returns an R2 client for bucket (or the default bucket).
func (a *App) Client(ctx context.Context, bucket string) (*storage.Client, config.Bucket, error) {
	if bucket == "" {
		bucket = a.Bucket
	}
	b, err := a.Cfg.Bucket(bucket)
	if err != nil {
		return nil, b, err
	}
	p, err := a.Sec.Pair(ctx, b.Credentials)
	if err != nil {
		return nil, b, err
	}
	return storage.New(a.Cfg.S3Endpoint(), b.Name, p.AccessKeyID, p.SecretAccessKey), b, nil
}

// AdminClient returns a client with the admin credentials (bucket admin, rules).
func (a *App) AdminClient(ctx context.Context, bucket string) (*storage.Client, error) {
	if a.Cfg.Admin == "" {
		return nil, errors.New("set admin_credentials in the config for bucket admin (an R2 token with Admin Read & Write)")
	}
	p, err := a.Sec.Pair(ctx, a.Cfg.Admin)
	if err != nil {
		return nil, err
	}
	return storage.New(a.Cfg.S3Endpoint(), bucket, p.AccessKeyID, p.SecretAccessKey), nil
}

// SplitTarget accepts "bucket:key" or "key" and returns (bucket, key).
func (a *App) SplitTarget(s string) (string, string) {
	if b, k, ok := strings.Cut(s, ":"); ok {
		if _, known := a.Cfg.Buckets[b]; known {
			return b, k
		}
	}
	return "", s
}

func (a *App) printJSON(v any) error {
	enc := json.NewEncoder(a.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (a *App) confirm(prompt string) bool {
	fmt.Fprintf(a.Err, "%s [y/N]: ", prompt)
	line, _ := bufio.NewReader(a.In).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func newFlags(name string, errw io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("cfr2 "+name, flag.ContinueOnError)
	fs.SetOutput(errw)
	return fs
}

// hashingWriter counts and hashes everything written through it.
type hashingWriter struct {
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
	n int64
}

func newHasher() *hashingWriter { return &hashingWriter{h: sha256.New()} }

func (w *hashingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return w.h.Write(p)
}

func (w *hashingWriter) Hex() string { return hex.EncodeToString(w.h.Sum(nil)) }

// HumanSize formats bytes like du -h.
func HumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(n)/float64(div), "KMGTPE"[exp])
}
