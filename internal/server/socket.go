package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-provisioner/internal/config"
	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// Listener serves the Service on a Unix socket:
//   - no network listener; the socket is handed over by systemd socket
//     activation, or created with mode 0660 and api.socket_group;
//   - every connection's peer is checked with SO_PEERCRED: only the
//     configured UIDs (conductor's user) are served;
//   - one request and one response per connection, size-bounded, with
//     read and write deadlines.
type Listener struct {
	svc     *Service
	log     *slog.Logger
	api     config.API
	allowed map[int]bool
	ln      *net.UnixListener
	sem     chan struct{}
	wg      sync.WaitGroup
	// peerCred is replaced in tests.
	peerCred func(*net.UnixConn) (uid int, err error)
}

// NewListener builds a listener for svc (not listening yet). allowedUIDs
// overrides the configuration (tests).
func NewListener(svc *Service, api config.API, allowedUIDs []int) (*Listener, error) {
	l := &Listener{svc: svc, log: svc.log, api: api, allowed: map[int]bool{}, sem: make(chan struct{}, 8), peerCred: peerCredentials}
	uids := allowedUIDs
	if uids == nil {
		var err error
		if uids, err = resolveUIDs(api); err != nil {
			return nil, err
		}
	}
	for _, u := range uids {
		l.allowed[u] = true
	}
	if len(l.allowed) == 0 {
		return nil, errors.New("server: no peer is allowed (api.allowed_users / api.allowed_uids)")
	}
	return l, nil
}

func resolveUIDs(c config.API) ([]int, error) {
	out := append([]int(nil), c.AllowedUIDs...)
	for _, name := range c.AllowedUsers {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("api.allowed_users: %q: %w", name, err)
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, err
		}
		if uid == 0 {
			return nil, fmt.Errorf("api.allowed_users: %q is root", name)
		}
		out = append(out, uid)
	}
	return out, nil
}

// Listen opens the socket: the one passed by systemd socket activation
// (LISTEN_FDS) when present, else api.socket created with mode 0660.
func (l *Listener) Listen() error {
	if ln, ok, err := activationListener(); err != nil {
		return err
	} else if ok {
		l.ln = ln
		l.log.Info("API on the socket passed by systemd")
		return nil
	}
	return l.ListenPath(l.api.Socket)
}

// ListenPath creates the socket at path (mode 0660, api.socket_group).
func (l *Listener) ListenPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("server: socket path must be absolute")
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("server: %s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	old := syscall.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if g := l.api.SocketGroup; g != "" {
		gid, err := lookupGroup(g)
		if err != nil {
			_ = ln.Close()
			return err
		}
		if err := os.Chown(path, -1, gid); err != nil {
			_ = ln.Close()
			return fmt.Errorf("server: socket group %s: %w (the service user must be a member)", g, err)
		}
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return err
	}
	l.ln = ln
	l.log.Info("API listening", "socket", path)
	return nil
}

func lookupGroup(g string) (int, error) {
	if n, err := strconv.Atoi(g); err == nil {
		return n, nil
	}
	grp, err := user.LookupGroup(g)
	if err != nil {
		return 0, fmt.Errorf("api.socket_group %q: %w", g, err)
	}
	return strconv.Atoi(grp.Gid)
}

// activationListener returns the first socket passed by systemd.
func activationListener() (*net.UnixListener, bool, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, false, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil, false, nil
	}
	f := os.NewFile(3, "systemd-socket")
	ln, err := net.FileListener(f)
	_ = f.Close()
	if err != nil {
		return nil, false, fmt.Errorf("server: socket activation: %w", err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, false, errors.New("server: socket activation passed a non-Unix socket")
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	return ul, true, nil
}

// peerCredentials reads SO_PEERCRED of the connection.
func peerCredentials(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}

// Serve accepts connections until ctx ends, then waits for the running
// requests.
func (l *Listener) Serve(ctx context.Context) error {
	if l.ln == nil {
		return errors.New("server: not listening")
	}
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()
	for {
		c, err := l.ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			l.log.Warn("accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.serveConn(ctx, c)
		}()
	}
	l.wg.Wait()
	return nil
}

func (l *Listener) serveConn(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	uid, err := l.peerCred(c)
	if err != nil || !l.allowed[uid] {
		l.log.Warn("connection refused: peer not allowed", "uid", uid, "err", err)
		return
	}
	select {
	case l.sem <- struct{}{}:
		defer func() { <-l.sem }()
	case <-ctx.Done():
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	var req provapi.Request
	if err := provapi.ReadMessage(bufio.NewReaderSize(c, 16<<10), &req); err != nil {
		pe := &provapi.Error{Code: provapi.CodeInvalidParams, Message: "unreadable request"}
		if errors.Is(err, provapi.ErrTooLarge) {
			pe.Message = "the request is larger than the maximum message size"
		}
		l.svc.audit(ctx, &call{op: "", actor: "unknown", detail: []string{pe.Message}}, pe)
		_ = provapi.WriteMessage(c, provapi.ErrorResponse("", pe))
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(90 * time.Second))
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp := l.svc.Handle(rctx, req)
	if err := provapi.WriteMessage(c, resp); err != nil {
		l.log.Warn("writing the response failed", "op", req.Op, "err", err)
	}
}
