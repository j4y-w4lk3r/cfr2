// Package secret resolves credential references from the config:
//
//	keyhole:NAME   runs the configured keyhole command with NAME appended.
//	               keyhole writes the password on stdout and the username on
//	               stderr when stdout is a pipe. Lines on stderr that start
//	               with "age:" (touch prompts) are passed through to the user.
//	bao:PATH       reads an OpenBao KV v2 secret (MOUNT/rest/of/path) with the
//	               token in the configured token file.
//	env:PREFIX     reads PREFIX_ACCESS_KEY_ID and PREFIX_SECRET_ACCESS_KEY
//	               (or PREFIX_TOKEN for single-value secrets).
//
// Values are never logged, never written to disk and never put in argv.
package secret

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/j4y-w4lk3r/cfr2/internal/config"
)

// Pair is an S3 key pair.
type Pair struct {
	AccessKeyID     string
	SecretAccessKey string
}

// Resolver resolves references using one config.
type Resolver struct {
	Cfg    *config.Config
	Stderr io.Writer // where keyhole touch prompts go (default os.Stderr)
	cache  map[string]Pair
	// InAgent is set inside the agent itself, so it never calls itself.
	InAgent bool
}

// New returns a Resolver that caches results for the life of the process.
func New(cfg *config.Config) *Resolver {
	return &Resolver{Cfg: cfg, Stderr: os.Stderr, cache: map[string]Pair{}}
}

// Pair resolves an S3 key pair reference.
func (r *Resolver) Pair(ctx context.Context, ref string) (Pair, error) {
	if p, ok := r.cache[ref]; ok {
		return p, nil
	}
	if !r.InAgent {
		if resp, ok, err := viaAgent("pair", ref); ok {
			if err != nil {
				return Pair{}, err
			}
			p := Pair{AccessKeyID: resp.ID, SecretAccessKey: resp.Secret}
			r.cache[ref] = p
			return p, nil
		}
	}
	if !r.InAgent && os.Getenv("CFR2_AGENT_ONLY") != "" {
		return Pair{}, errors.New("no cfr2 agent running (CFR2_AGENT_ONLY is set, so no keyhole touch is asked for)")
	}
	var p Pair
	var err error
	switch {
	case strings.HasPrefix(ref, "keyhole:"):
		p.AccessKeyID, p.SecretAccessKey, err = r.keyhole(ctx, strings.TrimPrefix(ref, "keyhole:"))
	case strings.HasPrefix(ref, "bao:"):
		var m map[string]string
		m, err = r.bao(ctx, strings.TrimPrefix(ref, "bao:"))
		p.AccessKeyID, p.SecretAccessKey = m["access_key_id"], m["secret_access_key"]
	case strings.HasPrefix(ref, "env:"):
		pre := strings.TrimPrefix(ref, "env:")
		p.AccessKeyID, p.SecretAccessKey = os.Getenv(pre+"_ACCESS_KEY_ID"), os.Getenv(pre+"_SECRET_ACCESS_KEY")
	default:
		return Pair{}, errors.New("credentials must be keyhole:, bao: or env:")
	}
	if err != nil {
		return Pair{}, err
	}
	if p.AccessKeyID == "" || p.SecretAccessKey == "" {
		return Pair{}, fmt.Errorf("%s: no access key id / secret access key found", ref)
	}
	r.cache[ref] = p
	return p, nil
}

// Token resolves a single-value reference (an API token).
func (r *Resolver) Token(ctx context.Context, ref string) (string, error) {
	if !r.InAgent {
		if resp, ok, err := viaAgent("token", ref); ok {
			return resp.Secret, err
		}
		if os.Getenv("CFR2_AGENT_ONLY") != "" {
			return "", errors.New("no cfr2 agent running (CFR2_AGENT_ONLY is set)")
		}
	}
	switch {
	case strings.HasPrefix(ref, "keyhole:"):
		_, v, err := r.keyhole(ctx, strings.TrimPrefix(ref, "keyhole:"))
		return v, err
	case strings.HasPrefix(ref, "bao:"):
		m, err := r.bao(ctx, strings.TrimPrefix(ref, "bao:"))
		if err != nil {
			return "", err
		}
		for _, k := range []string{"token", "value", "password"} {
			if m[k] != "" {
				return m[k], nil
			}
		}
		return "", fmt.Errorf("%s: no token/value/password field", ref)
	case strings.HasPrefix(ref, "env:"):
		v := os.Getenv(strings.TrimPrefix(ref, "env:") + "_TOKEN")
		if v == "" {
			return "", fmt.Errorf("%s_TOKEN is not set", strings.TrimPrefix(ref, "env:"))
		}
		return v, nil
	}
	return "", errors.New("token must be keyhole:, bao: or env:")
}

// keyhole runs `<command> NAME` and returns (username, password).
func (r *Resolver) keyhole(ctx context.Context, name string) (string, string, error) {
	if !validName(name) {
		return "", "", fmt.Errorf("keyhole: bad entry name %q", name)
	}
	cmdline := strings.TrimSpace(r.Cfg.Keyhole.Command)
	if cmdline == "" {
		cmdline = os.Getenv("CFR2_KEYHOLE_COMMAND")
	}
	if cmdline == "" {
		return "", "", errors.New("keyhole: set [keyhole] command in the config (e.g. \"keyhole ask\" or \"keyhole get VAULT -i IDENTITY\")")
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdline+" "+name)
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &out
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("keyhole: %w", err)
	}
	var user string
	var other []string
	sc := bufio.NewScanner(errPipe)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		switch {
		case strings.HasPrefix(line, "age:") || strings.HasPrefix(line, ">>"):
			fmt.Fprintln(r.Stderr, line) // touch prompt
		case strings.HasPrefix(line, "keyhole:") || strings.HasPrefix(line, "Error") || strings.HasPrefix(line, "error"):
			other = append(other, line)
		case line != "":
			// keyhole prints "username: VALUE"; older builds print the bare value
			if v, ok := strings.CutPrefix(line, "username:"); ok {
				line = strings.TrimSpace(v)
			}
			user = line
		}
	}
	if err := cmd.Wait(); err != nil {
		msg := strings.Join(other, "; ")
		if msg == "" {
			msg = err.Error()
		}
		return "", "", fmt.Errorf("keyhole %s: %s", name, msg)
	}
	pass := strings.TrimRight(out.String(), "\r\n")
	if pass == "" {
		return "", "", fmt.Errorf("keyhole %s: empty secret (wrong key touched?)", name)
	}
	return user, pass, nil
}

// bao reads a KV v2 secret: "mount/rest" -> GET /v1/mount/data/rest.
func (r *Resolver) bao(ctx context.Context, path string) (map[string]string, error) {
	mount, rest, ok := strings.Cut(strings.Trim(path, "/"), "/")
	if !ok || rest == "" {
		return nil, fmt.Errorf("bao:%s: want MOUNT/PATH", path)
	}
	addr := os.Getenv("BAO_ADDR")
	if addr == "" && r.Cfg.Bao.AddrFile != "" {
		b, err := os.ReadFile(config.ExpandPath(r.Cfg.Bao.AddrFile))
		if err != nil {
			return nil, fmt.Errorf("bao: %w", err)
		}
		addr = strings.TrimSpace(string(b))
	}
	if addr == "" {
		return nil, errors.New("bao: set BAO_ADDR or [bao] addr_file")
	}
	tok := os.Getenv("BAO_TOKEN")
	if tok == "" && r.Cfg.Bao.TokenFile != "" {
		b, err := os.ReadFile(config.ExpandPath(r.Cfg.Bao.TokenFile))
		if err != nil {
			return nil, fmt.Errorf("bao: %w", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		return nil, errors.New("bao: set BAO_TOKEN or [bao] token_file")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(addr, "/")+"/v1/"+mount+"/data/"+rest, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", tok)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("bao: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bao:%s: HTTP %d", path, resp.StatusCode)
	}
	var body struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("bao: %w", err)
	}
	m := map[string]string{}
	for k, v := range body.Data.Data {
		if s, ok := v.(string); ok {
			m[k] = s
		}
	}
	return m, nil
}

func validName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c == '_' || c == '.' || c == '/' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
