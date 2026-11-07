package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
	"github.com/j4y-w4lk3r/cfr2/internal/storage"
)

// File states reported by `cfr2 status`.
const (
	StateSynced  = "synced"  // same content locally and in R2
	StateChanged = "changed" // both exist, content differs
	StateLocal   = "local"   // only here: not backed up
	StateRemote  = "remote"  // only in R2
	StateUnknown = "unknown" // both exist, R2 copy has no cfr2 checksum
)

// StatusEntry is one file in the status report.
type StatusEntry struct {
	Path  string `json:"path"` // relative to the sync folder
	State string `json:"state"`
	Key   string `json:"key,omitempty"`
}

// StatusReport is the result for one sync mapping.
type StatusReport struct {
	Local   string         `json:"local"`
	Remote  string         `json:"remote"`
	Files   []StatusEntry  `json:"files"`
	Summary map[string]int `json:"summary"`
}

// Status compares sync folders with their bucket folders.
func (a *App) Status(ctx context.Context, args []string) error {
	fs := newFlags("status", a.Err)
	asJSON := fs.Bool("json", false, "JSON output (the yazi plugin reads this)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	maps := a.Cfg.Sync
	if fs.NArg() == 2 {
		maps = []config.Sync{{Local: fs.Arg(0), Remote: fs.Arg(1)}}
	} else if fs.NArg() == 1 {
		m, ok := a.syncFor(fs.Arg(0))
		if !ok {
			return fmt.Errorf("%s is not inside any [[sync]] folder", fs.Arg(0))
		}
		maps = []config.Sync{m}
	}
	if len(maps) == 0 {
		return errors.New("no [[sync]] folders in the config; or run: cfr2 status LOCALDIR BUCKET:PREFIX/")
	}
	cache := loadHeadCache()
	defer cache.save()
	var reports []StatusReport
	for _, m := range maps {
		r, err := a.statusOne(ctx, m, cache)
		if err != nil {
			return err
		}
		reports = append(reports, r)
	}
	if *asJSON {
		return a.printJSON(reports)
	}
	marks := map[string]string{StateSynced: "  ", StateChanged: "M ", StateLocal: "+ ", StateRemote: "R ", StateUnknown: "? "}
	for _, r := range reports {
		fmt.Fprintf(a.Out, "%s  <->  %s\n", r.Local, r.Remote)
		for _, e := range r.Files {
			if e.State != StateSynced {
				fmt.Fprintf(a.Out, "  %s%s\n", marks[e.State], e.Path)
			}
		}
		fmt.Fprintf(a.Out, "  %d synced, %d changed, %d only here, %d only in R2, %d unknown\n",
			r.Summary[StateSynced], r.Summary[StateChanged], r.Summary[StateLocal], r.Summary[StateRemote], r.Summary[StateUnknown])
	}
	return nil
}

func (a *App) syncFor(p string) (config.Sync, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return config.Sync{}, false
	}
	for _, m := range a.Cfg.Sync {
		l, _ := filepath.Abs(config.ExpandPath(m.Local))
		if abs == l || strings.HasPrefix(abs, l+string(os.PathSeparator)) {
			return m, true
		}
	}
	return config.Sync{}, false
}

func (a *App) statusOne(ctx context.Context, m config.Sync, cache *headCache) (StatusReport, error) {
	local := config.ExpandPath(m.Local)
	bucket, prefix, _ := strings.Cut(m.Remote, ":")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	rep := StatusReport{Local: m.Local, Remote: m.Remote, Summary: map[string]int{}}
	c, _, err := a.Client(ctx, bucket)
	if err != nil {
		return rep, err
	}
	page, err := c.List(ctx, prefix, "", 0)
	if err != nil {
		return rep, err
	}
	remote := map[string]storage.Object{} // plaintext-relative path -> object
	for _, o := range page.Objects {
		rel := strings.TrimPrefix(o.Key, prefix)
		rel = strings.TrimSuffix(strings.TrimSuffix(rel, ".age"), ".gpg")
		remote[rel] = o
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(local, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && p != local {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(local, p)
		rel = filepath.ToSlash(rel)
		seen[rel] = true
		o, ok := remote[rel]
		if !ok {
			rep.add(StatusEntry{Path: rel, State: StateLocal})
			return nil
		}
		want, err := cache.plainSHA(ctx, c, o)
		if err != nil {
			return err
		}
		if want == "" {
			rep.add(StatusEntry{Path: rel, State: StateUnknown, Key: o.Key})
			return nil
		}
		got, err := fileSHA(p)
		if err != nil {
			return err
		}
		st := StateSynced
		if got != want {
			st = StateChanged
		}
		rep.add(StatusEntry{Path: rel, State: st, Key: o.Key})
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return rep, err
	}
	for rel, o := range remote {
		if !seen[rel] {
			rep.add(StatusEntry{Path: rel, State: StateRemote, Key: o.Key})
		}
	}
	sort.Slice(rep.Files, func(i, j int) bool { return rep.Files[i].Path < rep.Files[j].Path })
	return rep, nil
}

func (r *StatusReport) add(e StatusEntry) {
	r.Files = append(r.Files, e)
	r.Summary[e.State]++
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// headCache remembers plain-sha256 per bucket/key/etag so status does not
// HEAD every object every time. It holds checksums only.
type headCache struct {
	path  string
	Items map[string]string `json:"items"`
	dirty bool
}

func loadHeadCache() *headCache {
	dir, err := os.UserCacheDir()
	hc := &headCache{Items: map[string]string{}}
	if err != nil {
		return hc
	}
	hc.path = filepath.Join(dir, "cfr2", "heads.json")
	if b, err := os.ReadFile(hc.path); err == nil {
		json.Unmarshal(b, hc)
		if hc.Items == nil {
			hc.Items = map[string]string{}
		}
	}
	return hc
}

func (hc *headCache) plainSHA(ctx context.Context, c *storage.Client, o storage.Object) (string, error) {
	k := c.Bucket + "/" + o.Key + "@" + o.ETag
	if v, ok := hc.Items[k]; ok {
		return v, nil
	}
	info, err := c.Head(ctx, o.Key)
	if err != nil {
		return "", err
	}
	v := info.Meta[storage.MetaPlainSHA256]
	hc.Items[k] = v
	hc.dirty = true
	return v, nil
}

func (hc *headCache) save() {
	if !hc.dirty || hc.path == "" {
		return
	}
	os.MkdirAll(filepath.Dir(hc.path), 0o700)
	if b, err := json.Marshal(hc); err == nil {
		os.WriteFile(hc.path, b, 0o600)
	}
}
