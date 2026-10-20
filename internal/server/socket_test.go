package server

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

func startListener(t *testing.T, e *env, uid int) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "prov")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	l, err := NewListener(e.svc, e.cfg.API, []int{uid})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ListenPath(sock); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = l.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v %v", st.Mode(), err)
	}
	return sock
}

func TestSocketCall(t *testing.T) {
	e := newEnv(t, "")
	sock := startListener(t, e, os.Getuid())
	req, err := provapi.NewRequest(provapi.NewRequestID(), provapi.OpStatus, admin, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := provapi.Call(ctx, sock, req)
	if err != nil {
		t.Fatal(err)
	}
	var st provapi.StatusResult
	if err := provapi.DecodeResult(resp, &st); err != nil {
		t.Fatal(err)
	}
	if st.Account != "svc-conductor-prov" || len(st.ScopeOUs) != 1 || st.Limits.TokenIssues.Ceiling != 200 {
		t.Fatalf("%+v", st)
	}
	// An error comes back as *provapi.Error.
	req, _ = provapi.NewRequest(provapi.NewRequestID(), provapi.OpUserCheck, admin, &provapi.UserCheckParams{SID: "S-1-5-21-9-9-9-1"})
	if _, err := provapi.Call(ctx, sock, req); provapi.ErrorCodeOf(err) != provapi.CodeNotFound {
		t.Fatalf("want not_found, got %v", err)
	}
}

func TestSocketPeerRefused(t *testing.T) {
	e := newEnv(t, "")
	sock := startListener(t, e, os.Getuid()+1)
	req, _ := provapi.NewRequest(provapi.NewRequestID(), provapi.OpStatus, admin, nil)
	_, err := provapi.Call(context.Background(), sock, req)
	if provapi.ErrorCodeOf(err) != provapi.CodeUnavailable {
		t.Fatalf("want unavailable, got %v", err)
	}
	if !strings.Contains(e.logs.String(), "peer not allowed") {
		t.Fatal("refusal not logged")
	}
}

func TestSocketOversized(t *testing.T) {
	e := newEnv(t, "")
	sock := startListener(t, e, os.Getuid())
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	big := `{"version":1,"id":"req-12345678","op":"status","params":{"x":"` + strings.Repeat("a", provapi.MaxMessageSize) + `"}}` + "\n"
	go func() { _, _ = c.Write([]byte(big)) }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var resp provapi.Response
	if err := provapi.ReadMessage(bufio.NewReader(c), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Error.Code != provapi.CodeInvalidParams || !strings.Contains(resp.Error.Message, "larger") {
		t.Fatalf("%+v", resp)
	}
	if ev := e.lastAudit(); ev.Result != "invalid_params" || ev.Op != "invalid" {
		t.Fatalf("audit %+v", ev)
	}
}
