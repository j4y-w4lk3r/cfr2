package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
)

// BucketCmd: list | create NAME | delete NAME | trash-rule [NAME] [--days N].
func (a *App) BucketCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	verb, rest := args[0], args[1:]
	fs := newFlags("bucket "+verb, a.Err)
	days := fs.Int("days", 30, "trash-rule: delete trashed objects after this many days")
	yes := fs.Bool("y", false, "do not ask")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	switch verb {
	case "list", "ls":
		c, err := a.AdminClient(ctx, "")
		if err != nil {
			for _, n := range a.Cfg.BucketNames() {
				fmt.Fprintln(a.Out, n, "(configured)")
			}
			return nil
		}
		bs, err := c.ListBuckets(ctx)
		if err != nil {
			return err
		}
		for _, b := range bs {
			mark := ""
			if _, ok := a.Cfg.Buckets[b.Name]; ok {
				mark = " (configured)"
			}
			fmt.Fprintf(a.Out, "%-28s %s%s\n", b.Name, b.CreatedAt.Format("2006-01-02"), mark)
		}
	case "create":
		if fs.NArg() != 1 {
			return errors.New("usage: cfr2 bucket create NAME")
		}
		c, err := a.AdminClient(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		if err := c.CreateBucket(ctx, fs.Arg(0)); err != nil {
			return err
		}
		if err := c.SetTrashRule(ctx, 30); err != nil {
			fmt.Fprintf(a.Err, "created, but the trash rule failed: %v\n", err)
		}
		fmt.Fprintf(a.Out, "created %s (private; .trash/ empties after 30 days). Add [buckets.%s] to the config.\n", fs.Arg(0), fs.Arg(0))
	case "delete":
		if fs.NArg() != 1 {
			return errors.New("usage: cfr2 bucket delete NAME   (must be empty)")
		}
		if !*yes && !a.confirm("delete bucket "+fs.Arg(0)+"?") {
			return errors.New("aborted")
		}
		c, err := a.AdminClient(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		if err := c.DeleteBucket(ctx, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "deleted", fs.Arg(0))
	case "trash-rule":
		name := ""
		if fs.NArg() == 1 {
			name = fs.Arg(0)
		}
		b, err := a.Cfg.Bucket(name)
		if err != nil {
			return err
		}
		c, err := a.AdminClient(ctx, b.Name)
		if err != nil {
			return err
		}
		if err := c.SetTrashRule(ctx, *days); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "%s: R2 now deletes .trash/ objects after %d days\n", b.Name, *days)
	default:
		return errors.New("usage: cfr2 bucket [list | create NAME | delete NAME | trash-rule [NAME] [--days N]]")
	}
	return nil
}

// Doctor checks tools, credentials, listing and the trash rule per bucket.
func (a *App) Doctor(ctx context.Context, args []string) error {
	ok := true
	check := func(name string, err error) {
		if err != nil {
			ok = false
			fmt.Fprintf(a.Out, "FAIL %-28s %v\n", name, err)
		} else {
			fmt.Fprintf(a.Out, "ok   %s\n", name)
		}
	}
	fmt.Fprintf(a.Out, "config: %s\nendpoint: R2 account %s\n", a.Cfg.Path, maskID(a.Cfg.AccountID))
	for _, tool := range []string{"age", "gpg"} {
		_, err := exec.LookPath(tool)
		if tool == "gpg" && err != nil {
			fmt.Fprintln(a.Out, "--   gpg not installed (only needed for --enc gpg)")
			continue
		}
		check(tool+" installed", err)
	}
	for _, id := range a.Cfg.Encrypt.AgeIdentities {
		_, err := os.Stat(config.ExpandPath(id))
		check("age identity "+filepath.Base(id), err)
	}
	for _, n := range a.Cfg.BucketNames() {
		c, _, err := a.Client(ctx, n)
		if err != nil {
			check("bucket "+n+" credentials", err)
			continue
		}
		_, err = c.List(ctx, "", "/", 1)
		check("bucket "+n+" list", err)
		if days, err := c.TrashRule(ctx); err == nil && days == 0 {
			fmt.Fprintf(a.Out, "--   bucket %s has no trash rule (cfr2 bucket trash-rule %s)\n", n, n)
		}
	}
	if !ok {
		return errors.New("doctor found problems")
	}
	return nil
}

func maskID(s string) string {
	if len(s) <= 6 {
		return s
	}
	return s[:4] + "…" + s[len(s)-2:]
}

// Init writes a commented example config (with references, no secrets).
func Init(path string, args []string) error {
	if path == "" {
		path = config.DefaultPath()
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(ExampleConfig), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s: fill in account_id, the bucket names and the keyhole entry names, then run `cfr2 doctor`\n", path)
	return nil
}

// ExampleConfig is what `cfr2 init` writes (and config.example.toml holds).
const ExampleConfig = `# cfr2 config. No secrets in here: credentials are references.
#   keyhole:NAME   keyhole entry, username = R2 access key id, password = secret access key
#   bao:MOUNT/PATH OpenBao KV v2 entry with access_key_id and secret_access_key
#   env:PREFIX     PREFIX_ACCESS_KEY_ID and PREFIX_SECRET_ACCESS_KEY

account_id     = "your-cloudflare-account-id"
default_bucket = "my-backup"
# jurisdiction = "eu"          # only for EU-jurisdiction buckets

# for bucket create/delete and the trash rule (an R2 token with Admin Read & Write)
# admin_credentials = "keyhole:r2-admin"

[keyhole]
# NAME is appended. "keyhole ask" uses a running keyhole daemon (one touch per session).
command = "keyhole get /path/to/vault.age -i /path/to/identity.txt"

[bao]
addr_file  = "~/.config/openbao.addr"
token_file = "~/.config/openbao.token"

[encrypt]
default        = "age"                      # age | gpg | none
age_recipients = ["age1yourrecipient..."]  # or paths to recipient files
age_identities = ["~/.config/age/identity.txt"]
gpg_recipients = []                         # key ids, only for --enc gpg

[usage]
token = "keyhole:cf-analytics-read"         # Cloudflare API token: Account Analytics Read

[buckets.my-backup]
credentials = "keyhole:r2-my-backup-rw"

[buckets.my-secrets]
credentials = "keyhole:r2-my-secrets-rw"
share       = false                         # never sign share links here

# [[sync]]                                  # folders that cfr2 status / the yazi markers compare
# local  = "~/notes"
# remote = "my-backup:notes/"
`
