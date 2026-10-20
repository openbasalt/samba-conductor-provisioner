package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/privilege"
	"github.com/openbasalt/samba-conductor-ad/sid"
	"github.com/openbasalt/samba-conductor-provisioner/internal/directory"
)

// fakeIndex is a privilege index given by the test.
type fakeIndex struct {
	reasons map[string][]privilege.Reason
	built   time.Time
}

func (x *fakeIndex) PrivilegedSID(s sid.SID) []privilege.Reason { return x.reasons[s.String()] }
func (x *fakeIndex) BuiltAt() time.Time                         { return x.built }

// fakeDir is an in-memory directory: objects by DN, their token groups,
// the privilege index content, and the writes applied.
type fakeDir struct {
	mu      sync.Mutex
	now     func() time.Time
	objs    map[string]*fakeObj // key: normalized DN
	priv    map[string][]privilege.Reason
	builds  int
	applied []ad.Preview
	// applyErr, when set, is returned by the next Apply.
	applyErr error
	// readErr, when set, is returned by every read.
	readErr error
	tick    int64
}

type fakeObj struct {
	entry  directory.Entry
	groups []sid.SID
}

func newFakeDir(now func() time.Time) *fakeDir {
	return &fakeDir{now: now, objs: map[string]*fakeObj{}, priv: map[string][]privilege.Reason{}}
}

var ridCounter uint32 = 1100

// addUser adds a user (disabled when disabled is true) and returns it.
func (d *fakeDir) addUser(dn, sam, mail string, disabled bool, classes ...string) *fakeObj {
	d.mu.Lock()
	defer d.mu.Unlock()
	ridCounter++
	s := sid.MustParse("S-1-5-21-1-2-3-" + strconv.Itoa(int(ridCounter)))
	var g sid.GUID
	copy(g[:], fmt.Sprintf("guid-%010d", ridCounter))
	if len(classes) == 0 {
		classes = []string{"top", "person", "organizationalPerson", "user"}
	}
	uac := ad.UACNormalAccount
	if disabled {
		uac |= ad.UACAccountDisable
	}
	o := &fakeObj{entry: directory.Entry{User: ad.User{DN: dn, SID: s, GUID: g, SAMAccountName: sam, Mail: mail, UAC: uac,
		PwdLastSet: ad.FileTime(1000)}, Classes: classes}}
	d.objs[escape.NormalizeDN(dn)] = o
	return o
}

func (d *fakeDir) FindBySID(_ context.Context, s sid.SID) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.readErr != nil {
		return "", d.readErr
	}
	for _, o := range d.objs {
		if o.entry.SID.Equal(s) {
			return o.entry.DN, nil
		}
	}
	return "", fmt.Errorf("%w: SID %s", ad.ErrNotFound, s)
}

func (d *fakeDir) FindUsers(_ context.Context, v string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.readErr != nil {
		return nil, d.readErr
	}
	var out []string
	for _, o := range d.objs {
		if o.entry.IsUser() && (strings.EqualFold(o.entry.SAMAccountName, v) || strings.EqualFold(o.entry.Mail, v)) {
			out = append(out, o.entry.DN)
		}
	}
	return out, nil
}

func (d *fakeDir) Get(_ context.Context, dn string) (directory.Entry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.readErr != nil {
		return directory.Entry{}, d.readErr
	}
	o, ok := d.objs[escape.NormalizeDN(dn)]
	if !ok {
		return directory.Entry{}, fmt.Errorf("%w: %s", ad.ErrNotFound, dn)
	}
	return o.entry, nil
}

func (d *fakeDir) TokenGroups(_ context.Context, dn string) ([]sid.SID, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	o, ok := d.objs[escape.NormalizeDN(dn)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ad.ErrNotFound, dn)
	}
	return append([]sid.SID{sid.MustParse("S-1-5-21-1-2-3-513")}, o.groups...), nil
}

func (d *fakeDir) BuildIndex(_ context.Context, opt privilege.Options) (directory.Index, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.readErr != nil {
		return nil, d.readErr
	}
	d.builds++
	x := &fakeIndex{reasons: map[string][]privilege.Reason{}, built: d.now()}
	for k, v := range d.priv {
		x.reasons[k] = v
	}
	for _, g := range opt.ExtraGroupSIDs {
		x.reasons[g.String()] = append(x.reasons[g.String()], privilege.Reason{Kind: privilege.KindGroup, Detail: g.String()})
	}
	return x, nil
}

// Apply interprets the writes the service sends: unicodePwd (a new
// pwdLastSet), lockoutTime and userAccountControl.
func (d *fakeDir) Apply(_ context.Context, op *ad.Operation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.applyErr; err != nil {
		d.applyErr = nil
		return err
	}
	p := op.Preview()
	for _, ch := range p.Changes {
		o, ok := d.objs[escape.NormalizeDN(ch.DN)]
		if !ok {
			return fmt.Errorf("%w: %s", ad.ErrNotFound, ch.DN)
		}
		for _, a := range ch.Attrs {
			switch strings.ToLower(a.Name) {
			case "unicodepwd":
				d.tick++
				o.entry.PwdLastSet = ad.FileTimeFrom(d.now()) + ad.FileTime(d.tick)
			case "lockouttime":
				o.entry.LockoutTime = 0
				o.entry.ComputedUAC &^= ad.UACLockout
			case "useraccountcontrol":
				v, err := strconv.ParseUint(a.Values[0], 10, 32)
				if err != nil {
					return err
				}
				o.entry.UAC = ad.UAC(v)
			default:
				return errors.New("fake: unexpected attribute " + a.Name)
			}
		}
	}
	d.applied = append(d.applied, p)
	return nil
}
