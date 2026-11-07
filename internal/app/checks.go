package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/j4y-w4lk3r/cfr2/internal/crypt"
	"github.com/j4y-w4lk3r/cfr2/internal/storage"
)

// Verify downloads objects and compares them with the sha256 stored at upload.
func (a *App) Verify(ctx context.Context, args []string) error {
	fs := newFlags("verify", a.Err)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: cfr2 verify [BUCKET:]KEY|PREFIX/")
	}
	bucket, key := a.SplitTarget(fs.Arg(0))
	c, _, err := a.Client(ctx, bucket)
	if err != nil {
		return err
	}
	keys := []string{key}
	if strings.HasSuffix(key, "/") || key == "" {
		page, err := c.List(ctx, key, "", 0)
		if err != nil {
			return err
		}
		keys = keys[:0]
		for _, o := range page.Objects {
			if !strings.HasPrefix(o.Key, storage.TrashPrefix) {
				keys = append(keys, o.Key)
			}
		}
	}
	var good, bad, unknown int
	for _, k := range keys {
		body, info, err := c.Get(ctx, k)
		if err != nil {
			return err
		}
		h := newHasher()
		_, err = io.Copy(h, body)
		body.Close()
		if err != nil {
			return err
		}
		switch want := info.Meta[storage.MetaSHA256]; {
		case want == "":
			unknown++
			fmt.Fprintf(a.Out, "?   %s (no checksum: uploaded without cfr2)\n", k)
		case want == h.Hex():
			good++
			fmt.Fprintf(a.Out, "ok  %s\n", k)
		default:
			bad++
			fmt.Fprintf(a.Out, "BAD %s (stored bytes changed since upload)\n", k)
		}
	}
	fmt.Fprintf(a.Out, "%d ok, %d bad, %d without checksum\n", good, bad, unknown)
	if bad > 0 {
		return fmt.Errorf("%d object(s) failed verification", bad)
	}
	return nil
}

// Drill proves a backup can be restored: it downloads the object,
// decrypts it in a pipe (the plaintext is only hashed, never written
// anywhere) and compares the result with the checksum taken at upload.
func (a *App) Drill(ctx context.Context, args []string) error {
	fs := newFlags("drill", a.Err)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: cfr2 drill [BUCKET:]KEY")
	}
	bucket, key := a.SplitTarget(fs.Arg(0))
	c, _, err := a.Client(ctx, bucket)
	if err != nil {
		return err
	}
	start := time.Now()
	body, info, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	stored, plain := newHasher(), newHasher()
	scheme := schemeOf(info, key)
	if err := crypt.Decrypt(scheme, a.Cfg.Encrypt, io.TeeReader(body, stored), plain); err != nil {
		return fmt.Errorf("RESTORE FAILED: %s could not be decrypted: %w", key, err)
	}
	took := time.Since(start).Round(time.Millisecond)
	fmt.Fprintf(a.Out, "object:     %s:%s\n", c.Bucket, key)
	fmt.Fprintf(a.Out, "encryption: %s\n", scheme)
	fmt.Fprintf(a.Out, "downloaded: %s, decrypted: %s, in %s\n", HumanSize(stored.n), HumanSize(plain.n), took)
	if want := info.Meta[storage.MetaSHA256]; want != "" && want != stored.Hex() {
		return errors.New("RESTORE FAILED: stored bytes do not match the upload checksum")
	}
	want := info.Meta[storage.MetaPlainSHA256]
	if want == "" {
		fmt.Fprintln(a.Out, "result:     decrypts fine, but there is no upload checksum to compare (pushed without cfr2)")
		return nil
	}
	if want != plain.Hex() {
		return errors.New("RESTORE FAILED: decrypted content does not match the checksum taken at upload")
	}
	fmt.Fprintln(a.Out, "result:     RESTORE WORKS (decrypted content matches the upload checksum)")
	return nil
}
