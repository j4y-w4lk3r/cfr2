package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/j4y-w4lk3r/cfr2/internal/crypt"
	"github.com/j4y-w4lk3r/cfr2/internal/storage"
)

// Edit decrypts an object into a RAM-only folder, opens $EDITOR, and when
// the file changed, encrypts and uploads it again (the old version goes to
// .trash/). The plaintext never touches a disk.
func (a *App) Edit(ctx context.Context, args []string) error {
	fs := newFlags("edit", a.Err)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: cfr2 edit [BUCKET:]KEY   (KEY may not exist yet: then a new file is created)")
	}
	bucket, key := a.SplitTarget(fs.Arg(0))
	c, b, err := a.Client(ctx, bucket)
	if err != nil {
		return err
	}
	scheme := crypt.FromName(key)
	if scheme == crypt.None {
		if scheme, err = crypt.Parse(a.Cfg.EncryptionFor(b)); err != nil {
			return err
		}
		if scheme == crypt.None {
			return errors.New("edit is for encrypted objects; give a key ending in .age or .gpg")
		}
		key += scheme.Suffix()
	}
	dir, cleanup, err := ramDir()
	if err != nil {
		return err
	}
	defer cleanup()
	name := strings.TrimSuffix(path.Base(key), scheme.Suffix())
	plainPath := filepath.Join(dir, name)
	f, err := os.OpenFile(plainPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	var before []byte
	body, info, err := c.Get(ctx, key)
	switch {
	case err == nil:
		scheme = schemeOf(info, key)
		var buf bytes.Buffer
		derr := crypt.Decrypt(scheme, a.Cfg.Encrypt, body, io.MultiWriter(f, &buf))
		body.Close()
		if derr != nil {
			f.Close()
			return derr
		}
		before = buf.Bytes()
	case errors.Is(err, storage.ErrNotFound):
		fmt.Fprintf(a.Err, "%s does not exist yet: starting a new file\n", key)
	default:
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command("sh", "-c", editor+` "$1"`, "cfr2-edit", plainPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}
	after, err := os.ReadFile(plainPath)
	if err != nil {
		return err
	}
	if bytes.Equal(before, after) {
		fmt.Fprintln(a.Out, "no changes, nothing uploaded")
		return nil
	}
	if err := a.pushOne(ctx, c, plainPath, key, scheme); err != nil {
		return fmt.Errorf("upload failed (your edit is lost when this exits): %w", err)
	}
	return nil
}

// ramDir returns a private folder that lives in RAM, and a cleanup that
// overwrites and removes everything in it.
func ramDir() (string, func(), error) {
	switch runtime.GOOS {
	case "linux":
		for _, base := range []string{os.Getenv("XDG_RUNTIME_DIR"), "/dev/shm"} {
			if base == "" {
				continue
			}
			if st, err := os.Stat(base); err == nil && st.IsDir() {
				d, err := os.MkdirTemp(base, "cfr2-edit-")
				if err != nil {
					continue
				}
				return d, func() { wipe(d) }, nil
			}
		}
		return "", nil, errors.New("no RAM folder found ($XDG_RUNTIME_DIR or /dev/shm)")
	case "darwin":
		// 32 MiB RAM disk, no sudo needed.
		out, err := exec.Command("hdiutil", "attach", "-nomount", "ram://65536").Output()
		if err != nil {
			return "", nil, fmt.Errorf("hdiutil ram disk: %w", err)
		}
		dev := strings.TrimSpace(string(out))
		vol := "cfr2-edit-" + fmt.Sprint(os.Getpid())
		if err := exec.Command("diskutil", "erasevolume", "HFS+", vol, dev).Run(); err != nil {
			exec.Command("hdiutil", "detach", dev).Run()
			return "", nil, fmt.Errorf("ram disk format: %w", err)
		}
		mnt := "/Volumes/" + vol
		os.Chmod(mnt, 0o700)
		return mnt, func() { wipe(mnt); exec.Command("hdiutil", "detach", "-force", dev).Run() }, nil
	}
	return "", nil, fmt.Errorf("cfr2 edit needs a RAM folder; not supported on %s", runtime.GOOS)
}

func wipe(dir string) {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if st, err := os.Stat(p); err == nil {
				if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
					f.Write(make([]byte, st.Size()))
					f.Close()
				}
			}
		}
		return nil
	})
	os.RemoveAll(dir)
}
