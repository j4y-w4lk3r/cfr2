package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
	"github.com/j4y-w4lk3r/cfr2/internal/crypt"
	"github.com/j4y-w4lk3r/cfr2/internal/storage"
)

// Ls lists one folder level (or everything with -r).
func (a *App) Ls(ctx context.Context, args []string) error {
	fs := newFlags("ls", a.Err)
	rec := fs.Bool("r", false, "recursive: every key under the prefix")
	asJSON := fs.Bool("json", false, "JSON output (for scripts and the yazi plugin)")
	all := fs.Bool("a", false, "also show .trash/")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bucket, prefix := "", ""
	if fs.NArg() > 0 {
		bucket, prefix = a.SplitTarget(fs.Arg(0))
	}
	c, _, err := a.Client(ctx, bucket)
	if err != nil {
		return err
	}
	delim := "/"
	if *rec {
		delim = ""
	}
	page, err := c.List(ctx, prefix, delim, 0)
	if err != nil {
		return err
	}
	if !*all {
		page.Prefixes = filterOut(page.Prefixes, storage.TrashPrefix)
		var objs []storage.Object
		for _, o := range page.Objects {
			if !strings.HasPrefix(o.Key, storage.TrashPrefix) {
				objs = append(objs, o)
			}
		}
		page.Objects = objs
	}
	if *asJSON {
		return a.printJSON(page)
	}
	for _, p := range page.Prefixes {
		fmt.Fprintf(a.Out, "%8s  %-16s  %s\n", "-", "", p)
	}
	for _, o := range page.Objects {
		fmt.Fprintf(a.Out, "%8s  %-16s  %s\n", HumanSize(o.Size), o.LastModified.Local().Format("2006-01-02 15:04"), o.Key)
	}
	return nil
}

func filterOut(xs []string, prefix string) []string {
	var out []string
	for _, x := range xs {
		if !strings.HasPrefix(x, prefix) {
			out = append(out, x)
		}
	}
	return out
}

// Push uploads files or folders, encrypting by default.
func (a *App) Push(ctx context.Context, args []string) error {
	fs := newFlags("push", a.Err)
	enc := fs.String("enc", "", "encryption: age (default), gpg or none")
	to := fs.String("to", "", "key prefix (folder) in the bucket")
	dated := fs.Bool("dated", false, "put the files under a YYYY-MM-DD/ folder")
	bucketFlag := fs.String("b", "", "bucket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: cfr2 push [-b BUCKET] [--enc age|gpg|none] [--to PREFIX] [--dated] FILE|DIR...")
	}
	c, b, err := a.Client(ctx, *bucketFlag)
	if err != nil {
		return err
	}
	schemeName := *enc
	if schemeName == "" {
		schemeName = a.Cfg.EncryptionFor(b)
	}
	scheme, err := crypt.Parse(schemeName)
	if err != nil {
		return err
	}
	prefix := strings.TrimPrefix(*to, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if *dated {
		prefix += time.Now().Format("2006-01-02") + "/"
	}
	for _, src := range fs.Args() {
		files, err := walkFiles(src)
		if err != nil {
			return err
		}
		for _, f := range files {
			cc, key := c, prefix+filepath.ToSlash(f.rel)+scheme.Suffix()
			// Inside a [[sync]] folder and no --to/-b given: mirror the folder layout,
			// so `cfr2 status` and the yazi markers line up with the upload.
			if *to == "" && *bucketFlag == "" && a.Bucket == "" {
				if m, ok := a.syncFor(f.path); ok {
					sb, sp, _ := strings.Cut(m.Remote, ":")
					if sp != "" && !strings.HasSuffix(sp, "/") {
						sp += "/"
					}
					root, _ := filepath.Abs(config.ExpandPath(m.Local))
					abs, _ := filepath.Abs(f.path)
					rel, _ := filepath.Rel(root, abs)
					dir := path.Dir(filepath.ToSlash(rel))
					if dir == "." {
						dir = ""
					} else {
						dir += "/"
					}
					if *dated {
						dir += time.Now().Format("2006-01-02") + "/"
					}
					if cc, _, err = a.Client(ctx, sb); err != nil {
						return err
					}
					key = sp + dir + path.Base(filepath.ToSlash(f.rel)) + scheme.Suffix()
				}
			}
			if err := a.pushOne(ctx, cc, f.path, key, scheme); err != nil {
				return err
			}
		}
	}
	return nil
}

type localFile struct{ path, rel string }

func walkFiles(src string) ([]localFile, error) {
	st, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []localFile{{src, filepath.Base(src)}}, nil
	}
	base := filepath.Dir(filepath.Clean(src))
	var out []localFile
	err = filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(base, p)
			out = append(out, localFile{p, rel})
		}
		return nil
	})
	return out, err
}

// pushOne encrypts src into a private temp file (ciphertext only), hashes
// both sides, and uploads with the checksums as metadata. An existing
// object with the same key is moved to .trash/ first.
func (a *App) pushOne(ctx context.Context, c *storage.Client, src, key string, scheme crypt.Scheme) error {
	plain := newHasher()
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(plain, f); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if info, err := c.Head(ctx, key); err == nil && info.Meta[storage.MetaPlainSHA256] == plain.Hex() {
		fmt.Fprintf(a.Out, "unchanged %s:%s (same content already there, skipped)\n", c.Bucket, key)
		return nil
	}
	stored := newHasher()
	var body io.ReadSeeker = f
	if scheme != crypt.None {
		tmp, err := os.CreateTemp("", "cfr2-push-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		if err := crypt.Encrypt(scheme, a.Cfg.Encrypt, f, io.MultiWriter(tmp, stored)); err != nil {
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		body = tmp
	} else {
		stored = plain
	}
	if _, err := c.Head(ctx, key); err == nil {
		if err := a.trashOne(ctx, c, key); err != nil {
			return fmt.Errorf("%s exists and could not be moved to trash: %w", key, err)
		}
		fmt.Fprintf(a.Err, "  old %s moved to %s\n", key, storage.TrashPrefix)
	}
	meta := map[string]string{
		storage.MetaSHA256:      stored.Hex(),
		storage.MetaPlainSHA256: plain.Hex(),
		storage.MetaScheme:      string(scheme),
		storage.MetaSize:        fmt.Sprint(plain.n),
	}
	if err := c.Put(ctx, key, body, meta); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "pushed %s -> %s:%s (%s, %s)\n", src, c.Bucket, key, HumanSize(stored.n), scheme)
	return nil
}

// Pull downloads (and decrypts) a key or a whole prefix ending in "/".
func (a *App) Pull(ctx context.Context, args []string) error {
	fs := newFlags("pull", a.Err)
	raw := fs.Bool("raw", false, "keep it encrypted (no decrypt)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("usage: cfr2 pull [--raw] [BUCKET:]KEY|PREFIX/ [DEST]")
	}
	bucket, key := a.SplitTarget(fs.Arg(0))
	dest := "."
	if fs.NArg() == 2 {
		dest = fs.Arg(1)
	}
	c, _, err := a.Client(ctx, bucket)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(key, "/") {
		out := dest
		if st, err := os.Stat(dest); err == nil && st.IsDir() {
			out = filepath.Join(dest, path.Base(key))
		}
		return a.pullOne(ctx, c, key, out, *raw)
	}
	page, err := c.List(ctx, key, "", 0)
	if err != nil {
		return err
	}
	for _, o := range page.Objects {
		rel := strings.TrimPrefix(o.Key, key)
		out := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		if err := a.pullOne(ctx, c, o.Key, out, *raw); err != nil {
			return err
		}
	}
	return nil
}

// pullOne downloads key into out, checking the stored checksum while
// downloading and the plaintext checksum after decrypting.
func (a *App) pullOne(ctx context.Context, c *storage.Client, key, out string, raw bool) error {
	body, info, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	scheme := schemeOf(info, key)
	if !raw && scheme != crypt.None {
		out = strings.TrimSuffix(strings.TrimSuffix(out, ".age"), ".gpg")
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("%s already exists, not overwriting", out)
	}
	tmp := out + ".cfr2-part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(tmp)
		}
	}()
	stored := newHasher()
	plain := newHasher()
	src := io.TeeReader(body, stored)
	if raw || scheme == crypt.None {
		_, err = io.Copy(io.MultiWriter(f, plain), src)
	} else {
		err = crypt.Decrypt(scheme, a.Cfg.Encrypt, src, io.MultiWriter(f, plain))
	}
	if err != nil {
		return err
	}
	if want := info.Meta[storage.MetaSHA256]; want != "" && want != stored.Hex() {
		return fmt.Errorf("%s: checksum mismatch: stored object is damaged (want %s…, got %s…)", key, want[:12], stored.Hex()[:12])
	}
	if want := info.Meta[storage.MetaPlainSHA256]; !raw && want != "" && want != plain.Hex() {
		return fmt.Errorf("%s: decrypted content does not match the checksum taken at upload", key)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, out); err != nil {
		return err
	}
	ok = true
	fmt.Fprintf(a.Out, "pulled %s:%s -> %s (%s)\n", c.Bucket, key, out, HumanSize(plain.n))
	return nil
}

func schemeOf(info storage.Info, key string) crypt.Scheme {
	if s := info.Meta[storage.MetaScheme]; s != "" {
		if sc, err := crypt.Parse(s); err == nil {
			return sc
		}
	}
	return crypt.FromName(key)
}

// Cat decrypts a key to stdout.
func (a *App) Cat(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: cfr2 cat [BUCKET:]KEY")
	}
	bucket, key := a.SplitTarget(args[0])
	c, _, err := a.Client(ctx, bucket)
	if err != nil {
		return err
	}
	body, info, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	defer body.Close()
	return crypt.Decrypt(schemeOf(info, key), a.Cfg.Encrypt, body, a.Out)
}

// Rm moves keys to .trash/DATE/ (or deletes them for good with --purge).
func (a *App) Rm(ctx context.Context, args []string) error {
	fs := newFlags("rm", a.Err)
	purge := fs.Bool("purge", false, "delete for good instead of moving to .trash/")
	yes := fs.Bool("y", false, "do not ask (only with --purge)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: cfr2 rm [--purge [-y]] [BUCKET:]KEY|PREFIX/ ...")
	}
	for _, t := range fs.Args() {
		bucket, key := a.SplitTarget(t)
		c, _, err := a.Client(ctx, bucket)
		if err != nil {
			return err
		}
		keys := []string{key}
		if strings.HasSuffix(key, "/") {
			page, err := c.List(ctx, key, "", 0)
			if err != nil {
				return err
			}
			keys = keys[:0]
			for _, o := range page.Objects {
				keys = append(keys, o.Key)
			}
		}
		if *purge && !*yes && !a.confirm(fmt.Sprintf("delete %d object(s) in %s for good?", len(keys), c.Bucket)) {
			return errors.New("aborted")
		}
		for _, k := range keys {
			if *purge {
				err = c.Delete(ctx, k)
			} else {
				err = a.trashOne(ctx, c, k)
			}
			if err != nil {
				return err
			}
			verb := "trashed"
			if *purge {
				verb = "deleted"
			}
			fmt.Fprintf(a.Out, "%s %s:%s\n", verb, c.Bucket, k)
		}
	}
	return nil
}

func (a *App) trashOne(ctx context.Context, c *storage.Client, key string) error {
	if strings.HasPrefix(key, storage.TrashPrefix) {
		return fmt.Errorf("%s is already in the trash (use --purge)", key)
	}
	if _, err := c.Head(ctx, key); err != nil {
		return err
	}
	dst := storage.TrashPrefix + time.Now().UTC().Format("2006-01-02T150405Z") + "/" + key
	if err := c.Copy(ctx, key, dst); err != nil {
		return err
	}
	return c.Delete(ctx, key)
}

// Trash lists, restores or empties .trash/.
func (a *App) Trash(ctx context.Context, args []string) error {
	fs := newFlags("trash", a.Err)
	bucketFlag := fs.String("b", "", "bucket")
	yes := fs.Bool("y", false, "do not ask")
	if err := fs.Parse(args); err != nil {
		return err
	}
	verb := "ls"
	if fs.NArg() > 0 {
		verb = fs.Arg(0)
	}
	c, _, err := a.Client(ctx, *bucketFlag)
	if err != nil {
		return err
	}
	page, err := c.List(ctx, storage.TrashPrefix, "", 0)
	if err != nil {
		return err
	}
	sort.Slice(page.Objects, func(i, j int) bool { return page.Objects[i].Key > page.Objects[j].Key })
	switch verb {
	case "ls", "list":
		days, _ := c.TrashRule(ctx)
		if days > 0 {
			fmt.Fprintf(a.Err, "(R2 deletes trash after %d days)\n", days)
		} else {
			fmt.Fprintln(a.Err, "(no trash rule yet: `cfr2 bucket trash-rule` makes R2 empty it after 30 days)")
		}
		for _, o := range page.Objects {
			fmt.Fprintf(a.Out, "%8s  %s\n", HumanSize(o.Size), strings.TrimPrefix(o.Key, storage.TrashPrefix))
		}
	case "restore":
		if fs.NArg() != 2 {
			return errors.New("usage: cfr2 trash restore KEY   (the original key; the newest trashed copy comes back)")
		}
		want := fs.Arg(1)
		for _, o := range page.Objects {
			_, orig, _ := strings.Cut(strings.TrimPrefix(o.Key, storage.TrashPrefix), "/")
			if orig != want {
				continue
			}
			if _, err := c.Head(ctx, want); err == nil {
				return fmt.Errorf("%s exists again; move it away first", want)
			}
			if err := c.Copy(ctx, o.Key, want); err != nil {
				return err
			}
			if err := c.Delete(ctx, o.Key); err != nil {
				return err
			}
			fmt.Fprintf(a.Out, "restored %s:%s\n", c.Bucket, want)
			return nil
		}
		return fmt.Errorf("%s is not in the trash", want)
	case "empty":
		if !*yes && !a.confirm(fmt.Sprintf("delete %d trashed object(s) in %s for good?", len(page.Objects), c.Bucket)) {
			return errors.New("aborted")
		}
		for _, o := range page.Objects {
			if err := c.Delete(ctx, o.Key); err != nil {
				return err
			}
		}
		fmt.Fprintf(a.Out, "emptied %d object(s)\n", len(page.Objects))
	default:
		return errors.New("usage: cfr2 trash [ls | restore KEY | empty]")
	}
	return nil
}
