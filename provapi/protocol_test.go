package provapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var actor = Actor{User: "helpdesk", SID: "S-1-5-21-1-2-3-1500", Session: "s1", IP: "192.0.2.1"}

func TestNewRequestAndDecode(t *testing.T) {
	tok := strings.Repeat("A", 43)
	ok := map[Op]Params{
		OpStatus:         nil,
		OpUserCheck:      &UserCheckParams{SID: "S-1-5-21-1-2-3-1100"},
		OpUserFind:       &UserFindParams{UsernameOrMail: "ana@example.com"},
		OpTokenIssue:     &TokenIssueParams{SID: "S-1-5-21-1-2-3-1100", Purpose: PurposeInvite, Reference: "q-1"},
		OpTokenCheck:     &TokenCheckParams{Token: tok},
		OpPasswordSet:    &PasswordSetParams{Token: tok, NewPassword: "pw with spaces and ünïcode", Unlock: true},
		OpInviteComplete: &InviteCompleteParams{Token: tok},
		OpTokenRevoke:    &TokenRevokeParams{SID: "S-1-5-21-1-2-3-1100", Reason: "admin"},
		OpTokenList:      &TokenListParams{SID: "S-1-5-21-1-2-3-1100"},
	}
	if len(ok) != len(Allowlist) {
		t.Fatalf("test covers %d of %d operations", len(ok), len(Allowlist))
	}
	for op, p := range ok {
		req, err := NewRequest(NewRequestID(), op, actor, p)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if _, err := req.Decode(); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
	}
	public := Actor{User: PublicUser, Session: "link-1"}
	if _, err := NewRequest(NewRequestID(), OpTokenCheck, public, &TokenCheckParams{Token: tok}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRefusals(t *testing.T) {
	base := Request{Version: ProtocolVersion, ID: "abcdefgh", Op: OpStatus, Actor: actor}
	cases := map[string]Request{}
	add := func(name string, mod func(r *Request)) {
		r := base
		mod(&r)
		cases[name] = r
	}
	add("version", func(r *Request) { r.Version = 0 })
	add("id", func(r *Request) { r.ID = "a b" })
	add("op", func(r *Request) { r.Op = "ldap.modify" })
	add("actor user", func(r *Request) { r.Actor.User = "" })
	add("actor session", func(r *Request) { r.Actor.Session = strings.Repeat("s", 129) })
	add("actor sid", func(r *Request) { r.Actor.SID = "" })
	add("public sid", func(r *Request) { r.Actor.User, r.Actor.SID = PublicUser, "S-1-5-21-1" })
	add("unknown field", func(r *Request) { r.Params = json.RawMessage(`{"x":1}`) })
	add("bad sid", func(r *Request) { r.Op, r.Params = OpUserCheck, json.RawMessage(`{"sid":"S-1-5-(21)"}`) })
	add("long password", func(r *Request) {
		r.Op = OpPasswordSet
		r.Params, _ = json.Marshal(PasswordSetParams{Token: strings.Repeat("A", 43), NewPassword: strings.Repeat("x", 1025)})
	})
	add("revoke no reason", func(r *Request) { r.Op, r.Params = OpTokenRevoke, json.RawMessage(`{"sid":"S-1-5-21-1"}`) })
	add("reference newline", func(r *Request) {
		r.Op, r.Params = OpTokenIssue, json.RawMessage(`{"sid":"S-1-5-21-1","purpose":"reset","reference":"a\nb"}`)
	})
	for name, r := range cases {
		_, err := r.Decode()
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != CodeInvalidParams {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPasswordNeverInErrors(t *testing.T) {
	p := PasswordSetParams{Token: strings.Repeat("A", 43), NewPassword: "secret\x00value"}
	if err := p.Validate(); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("%v", err)
	}
}

func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	req, _ := NewRequest("abcdefgh", OpStatus, actor, nil)
	if err := WriteMessage(&buf, req); err != nil {
		t.Fatal(err)
	}
	var got Request
	if err := ReadMessage(bufio.NewReader(&buf), &got); err != nil || got.ID != "abcdefgh" {
		t.Fatal(got, err)
	}
	big := `{"id":"` + strings.Repeat("a", MaxMessageSize) + `"}` + "\n"
	if err := ReadMessage(bufio.NewReader(strings.NewReader(big)), &got); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if err := WriteMessage(&buf, map[string]string{"x": strings.Repeat("a", MaxMessageSize)}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if err := ReadMessage(bufio.NewReader(strings.NewReader(`{"id":"x","extra":1}`+"\n")), &got); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := ReadMessage(bufio.NewReader(strings.NewReader(`{"id":"x"} {"id":"y"}`+"\n")), &got); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestDecodeResultStrict(t *testing.T) {
	resp, _ := OKResponse("abcdefgh", map[string]any{"revoked": 1, "extra": true})
	var r TokenRevokeResult
	if err := DecodeResult(resp, &r); err == nil {
		t.Fatal("unknown result field accepted")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"version":1,"id":"abcdefgh","op":"token.check","actor":{"user":"-public-","session":"s"},"params":{"token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`))
	f.Add([]byte(`{"version":1,"id":"abcdefgh","op":"password.set","actor":{"user":"a","sid":"S-1-5-21-1","session":"s"},"params":{"token":"x","new_password":"y"}}`))
	f.Add([]byte(`{"version":1,"id":"abcdefgh","op":"user.find","actor":{"user":"a","sid":"S-1-5-21-1","session":"s"},"params":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Request
		if err := ReadMessage(bufio.NewReader(bytes.NewReader(append(b, '\n'))), &r); err != nil {
			return
		}
		p, err := r.Decode()
		if err == nil {
			if p == nil {
				t.Fatal("nil params without error")
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("decoded params do not validate: %v", err)
			}
			return
		}
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != CodeInvalidParams {
			t.Fatalf("decode error is not invalid_params: %v", err)
		}
	})
}

func FuzzReadMessage(f *testing.F) {
	f.Add([]byte(`{"version":1,"id":"abcdefgh","ok":true,"result":{"revoked":1}}`))
	f.Add([]byte(`{"version":1,"id":"abcdefgh","ok":false,"error":{"code":"password_policy","message":"m","reason":"history"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var resp Response
		_ = ReadMessage(bufio.NewReader(bytes.NewReader(b)), &resp)
		var r TokenRevokeResult
		_ = DecodeResult(resp, &r)
	})
}
