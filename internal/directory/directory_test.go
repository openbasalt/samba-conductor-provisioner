package directory

import (
	"context"
	"errors"
	"slices"
	"testing"

	ad "github.com/openbasalt/samba-conductor-ad"
)

func TestMatchKinds(t *testing.T) {
	q := ConflictQuery{SAM: "ana", UPN: "ana@example.com", Mail: "ana@example.com", Marker: "google-first:1"}
	cases := []struct {
		sam, upn, mail, marker string
		proxies                []string
		want                   []string
	}{
		{"ANA", "", "", "", nil, []string{"sam"}},
		{"x", "Ana@Example.com", "", "", nil, []string{"upn", "mail"}},
		{"x", "", "ana@example.com", "", nil, []string{"mail"}},
		{"x", "", "", "", []string{"X400:c=x", "SMTP:ana@EXAMPLE.com"}, []string{"mail"}},
		{"x", "", "", "", []string{"sip:ana@example.com"}, nil},
		{"x", "", "", "google-first:1", nil, []string{"marker"}},
		{"x", "", "", "google-first:12", nil, nil},
	}
	for i, c := range cases {
		if got := MatchKinds(q, c.sam, c.upn, c.mail, c.marker, c.proxies); !slices.Equal(got, c.want) {
			t.Errorf("%d: %v, want %v", i, got, c.want)
		}
	}
	if got := MatchKinds(ConflictQuery{}, "", "", "", "", nil); got != nil {
		t.Fatalf("empty query matched %v", got)
	}
}

func TestEntryValues(t *testing.T) {
	e := Entry{User: ad.User{GivenName: "Ana", Surname: "Silva", Mail: "a@b"}, EmployeeID: "E1",
		ProxyAddresses: []string{"smtp:x@b"}, Classes: []string{"top", "organizationalUnit"}}
	if !slices.Equal(e.Values("givenName"), []string{"Ana"}) || !slices.Equal(e.Values("employeeID"), []string{"E1"}) ||
		e.Values("title") != nil || !slices.Equal(e.Values("proxyAddresses"), []string{"smtp:x@b"}) || !e.IsOU() || e.IsUser() {
		t.Fatalf("%+v", e)
	}
}

func TestADUnsupportedWritesRefuseBeforeWriting(t *testing.T) {
	d := &AD{}
	if err := d.CreateUser(context.Background(), NewUser{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("create: %v", err)
	}
	for _, ch := range []AttrChange{{Name: "employeeID", After: []string{"1"}}, {Name: "proxyAddresses", After: []string{"smtp:a@b"}}} {
		err := d.ModifyUser(context.Background(), "CN=A,OU=P,DC=example,DC=com", []AttrChange{{Name: "sn", After: []string{"x"}}, ch})
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s: %v", ch.Name, err)
		}
	}
}
