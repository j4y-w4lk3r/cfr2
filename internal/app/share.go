package app

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// MaxShareTTL is the longest a share link may live.
const MaxShareTTL = 24 * time.Hour

// Share prints a presigned download link for one object. The bucket stays
// private; the link works for that one key until it expires. Buckets with
// share = false in the config are refused.
func (a *App) Share(ctx context.Context, args []string) error {
	fs := newFlags("share", a.Err)
	ttl := fs.Duration("ttl", time.Hour, "how long the link works (max 24h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: cfr2 share [--ttl 1h] [BUCKET:]KEY")
	}
	if *ttl <= 0 || *ttl > MaxShareTTL {
		return fmt.Errorf("--ttl must be between 1s and %s", MaxShareTTL)
	}
	bucket, key := a.SplitTarget(fs.Arg(0))
	c, b, err := a.Client(ctx, bucket)
	if err != nil {
		return err
	}
	if !b.ShareAllowed() {
		return fmt.Errorf("bucket %s does not allow share links (share = false in the config)", b.Name)
	}
	if _, err := c.Head(ctx, key); err != nil {
		return err
	}
	url, err := c.Presign(ctx, key, *ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Err, "link for %s:%s, valid until %s\n", c.Bucket, key, time.Now().Add(*ttl).Format("2006-01-02 15:04"))
	fmt.Fprintln(a.Out, url)
	return nil
}
