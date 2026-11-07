// Command cfr2 is a small Cloudflare R2 tool: encrypted push and pull
// (age by default, gpg optional), credentials from keyhole or OpenBao,
// a trash instead of delete, checksums, restore drills, share links,
// safe editing of encrypted files, sync status and a cost report.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/j4y-w4lk3r/cfr2/internal/app"
	"github.com/j4y-w4lk3r/cfr2/internal/config"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `cfr2 - Cloudflare R2 from the terminal

Usage: cfr2 [-c CONFIG] [-b BUCKET] <command> [flags] [args]

Objects (KEY may be written BUCKET:KEY):
  ls [-r] [-json] [PREFIX]        list one folder level (-r: everything)
  push [--enc age|gpg|none] [--to PREFIX] [--dated] FILE|DIR...
                                  encrypt (age by default) and upload, with checksums
  pull [--raw] KEY|PREFIX/ [DEST] download and decrypt, checking the checksums
  cat KEY                         decrypt to stdout
  edit KEY                        decrypt into RAM, open $EDITOR, re-encrypt and upload
  rm [--purge] KEY|PREFIX/        move to .trash/ (--purge: delete for good)
  trash [ls | restore KEY | empty]

Safety:
  verify KEY|PREFIX/              compare stored bytes with the upload checksum
  drill KEY                       restore test: download, decrypt in a pipe, compare
  status [DIR | LOCALDIR BUCKET:PREFIX/]
                                  like git status: synced / changed / only here / only in R2

Sharing and account:
  share [--ttl 1h] KEY            temporary download link for one object (max 24h)
  usage [--short] [--cached]      storage per bucket, operations, monthly estimate
  bucket [list | create NAME | delete NAME | trash-rule [NAME]]
  doctor                          check tools, credentials and buckets
  agent [start | stop | status]  keep keys in memory for a while (one touch, then none)
  init                            write an example config
  version
`

func main() {
	gfs := flag.NewFlagSet("cfr2", flag.ContinueOnError)
	gfs.SetOutput(os.Stderr)
	gfs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	cfgPath := gfs.String("c", "", "config file (default ~/.config/cfr2/config.toml or $CFR2_CONFIG)")
	bucket := gfs.String("b", "", "bucket (default: default_bucket)")
	showV := gfs.Bool("v", false, "print version and exit")
	showVersion := gfs.Bool("version", false, "print version and exit")
	if err := gfs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	if *showV || *showVersion {
		fmt.Printf("cfr2 %s (commit %s, built %s)\n", version, commit, date)
		return
	}
	if gfs.NArg() == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := gfs.Arg(0), gfs.Args()[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	case "version", "-v", "--version":
		fmt.Printf("cfr2 %s (commit %s, built %s)\n", version, commit, date)
		return
	case "init":
		exit(app.Init(*cfgPath, args))
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	a, err := app.Open(*cfgPath, *bucket)
	if err != nil {
		exit(err)
	}
	run := map[string]func(context.Context, []string) error{
		"ls": a.Ls, "list": a.Ls,
		"push": a.Push, "put": a.Push,
		"pull": a.Pull, "get": a.Pull,
		"cat": a.Cat, "edit": a.Edit,
		"rm": a.Rm, "trash": a.Trash,
		"verify": a.Verify, "drill": a.Drill, "status": a.Status,
		"share": a.Share, "usage": a.Usage,
		"bucket": a.BucketCmd, "doctor": a.Doctor, "agent": a.Agent,
	}
	f, ok := run[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "cfr2: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	exit(f(ctx, args))
}

func exit(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, config.ErrNoConfig) {
		fmt.Fprintln(os.Stderr, "cfr2:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "cfr2:", err)
	os.Exit(1)
}
