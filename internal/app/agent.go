package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/j4y-w4lk3r/cfr2/internal/secret"
)

// Agent: start [--idle 15m] | run | stop | status.
func (a *App) Agent(ctx context.Context, args []string) error {
	verb := "status"
	if len(args) > 0 {
		verb, args = args[0], args[1:]
	}
	fs := newFlags("agent "+verb, a.Err)
	idle := fs.Duration("idle", 15*time.Minute, "forget the keys after this long without use")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch verb {
	case "status":
		if secret.AgentAlive() {
			fmt.Fprintln(a.Out, "agent running:", secret.AgentSocket())
		} else {
			fmt.Fprintln(a.Out, "no agent running")
		}
	case "stop":
		if err := secret.StopAgent(); err != nil {
			return errors.New("no agent running")
		}
		fmt.Fprintln(a.Out, "agent stopped, keys forgotten")
	case "start":
		if secret.AgentAlive() {
			fmt.Fprintln(a.Out, "agent already running")
			return nil
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		argv := []string{"agent", "run", "--idle", idle.String()}
		if a.Cfg.Path != "" {
			argv = append([]string{"-c", a.Cfg.Path}, argv...)
		}
		cmd := exec.Command(self, argv...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		for i := 0; i < 20 && !secret.AgentAlive(); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Fprintf(a.Out, "agent started (forgets the keys after %s idle)\n", *idle)
	case "run":
		allowed := map[string]bool{}
		for _, b := range a.Cfg.Buckets {
			allowed[b.Credentials] = true
		}
		for _, ref := range []string{a.Cfg.Admin, a.Cfg.Usage.Token} {
			if ref != "" {
				allowed[ref] = true
			}
		}
		a.Sec.InAgent = true
		return secret.ServeAgent(ctx, a.Sec, allowed, *idle)
	default:
		return errors.New("usage: cfr2 agent [start [--idle 15m] | stop | status]")
	}
	return nil
}
