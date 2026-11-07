package secret

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The agent keeps resolved credentials in memory so a burst of cfr2
// commands (the yazi plugin) costs one keyhole touch instead of one per
// command. It listens on a unix socket inside a 0700 folder that only
// the user can reach, answers only references that appear in the
// config, and exits after an idle timeout. Nothing is written to disk.

type agentReq struct {
	Op  string `json:"op"` // pair | token | ping | stop
	Ref string `json:"ref"`
}

type agentResp struct {
	ID     string `json:"id,omitempty"`
	Secret string `json:"secret,omitempty"`
	Err    string `json:"err,omitempty"`
}

// AgentSocket is the socket path for this user.
func AgentSocket() string {
	if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" {
		return filepath.Join(base, "cfr2", "agent.sock")
	}
	// macOS has no XDG_RUNTIME_DIR and $TMPDIR differs between Terminal and ssh;
	// the user cache folder is the same for every process of the user.
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "cfr2", "agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("cfr2-%d", os.Getuid()), "agent.sock")
}

// ServeAgent runs the agent until idle passes without a request, or ctx ends.
func ServeAgent(ctx context.Context, r *Resolver, allowed map[string]bool, idle time.Duration) error {
	sock := AgentSocket()
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(sock), 0o700); err != nil {
		return err
	}
	if AgentAlive() {
		return errors.New("an agent is already running")
	}
	os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer os.Remove(sock)
	os.Chmod(sock, 0o600)
	var mu sync.Mutex
	last := time.Now()
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done); l.Close() }) }
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				stop()
				return
			case <-done:
				return
			case <-t.C:
				mu.Lock()
				expired := time.Since(last) > idle
				mu.Unlock()
				if expired {
					stop()
					return
				}
			}
		}
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-done:
				return nil
			default:
				return err
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(150 * time.Second))
			var req agentReq
			if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
				return
			}
			mu.Lock()
			last = time.Now()
			mu.Unlock()
			var resp agentResp
			switch {
			case req.Op == "ping":
			case req.Op == "stop":
				defer stop()
			case !allowed[req.Ref]:
				resp.Err = "reference not in the config"
			case req.Op == "pair":
				mu.Lock()
				p, err := r.Pair(ctx, req.Ref)
				mu.Unlock()
				if err != nil {
					resp.Err = err.Error()
				} else {
					resp.ID, resp.Secret = p.AccessKeyID, p.SecretAccessKey
				}
			case req.Op == "token":
				mu.Lock()
				v, err := r.tokenCached(ctx, req.Ref)
				mu.Unlock()
				if err != nil {
					resp.Err = err.Error()
				} else {
					resp.Secret = v
				}
			default:
				resp.Err = "unknown op"
			}
			json.NewEncoder(c).Encode(resp)
		}(conn)
	}
}

func agentCall(req agentReq) (agentResp, error) {
	c, err := net.DialTimeout("unix", AgentSocket(), 500*time.Millisecond)
	if err != nil {
		return agentResp{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(150 * time.Second))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return agentResp{}, err
	}
	var resp agentResp
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return agentResp{}, err
	}
	if resp.Err != "" {
		return resp, errors.New(resp.Err)
	}
	return resp, nil
}

// AgentAlive reports whether an agent answers.
func AgentAlive() bool {
	_, err := agentCall(agentReq{Op: "ping"})
	return err == nil
}

// StopAgent asks a running agent to exit (it forgets everything).
func StopAgent() error {
	_, err := agentCall(agentReq{Op: "stop"})
	return err
}

func (r *Resolver) tokenCached(ctx context.Context, ref string) (string, error) {
	key := "token:" + ref
	if p, ok := r.cache[key]; ok {
		return p.SecretAccessKey, nil
	}
	v, err := r.Token(ctx, ref)
	if err != nil {
		return "", err
	}
	r.cache[key] = Pair{SecretAccessKey: v}
	return v, nil
}

// viaAgent tries the agent first; ok is false when no agent runs.
func viaAgent(op, ref string) (agentResp, bool, error) {
	if os.Getenv("CFR2_NO_AGENT") != "" || strings.HasPrefix(ref, "env:") {
		return agentResp{}, false, nil
	}
	resp, err := agentCall(agentReq{Op: op, Ref: ref})
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) || errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "connect") {
			return agentResp{}, false, nil
		}
		return agentResp{}, true, err
	}
	return resp, true, nil
}
