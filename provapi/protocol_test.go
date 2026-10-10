package provapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"slices"
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
		OpUserCreate:     &validCreate,
		OpUserUpdate: &UserUpdateParams{SID: "S-1-5-21-1-2-3-1100", Marker: Marker("1234"), Changes: []UserChange{
			{Attr: "sn", Before: "Silva", After: "Souza"},
			{Attr: "proxyAddresses", Before: "", After: JoinValues([]string{"smtp:b@example.com", "smtp:a@example.com"})},
		}},
		OpUserSetEnabled: &UserSetEnabledParams{SID: "S-1-5-21-1-2-3-1100", Marker: Marker("1234"), Reference: "run-1"},
		OpUserMove:       &UserMoveParams{SID: "S-1-5-21-1-2-3-1100", ToOU: "OU=Quarantine,OU=People,DC=example,DC=com", Marker: Marker("1234")},
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

var validCreate = UserCreateParams{ScopeOU: "OU=People,DC=example,DC=com", SAM: "ana.silva", UPN: "ana.silva@example.com",
	CN: "Ana Silva", Mail: "ana@example.com", GivenName: "Ana", Sn: "Silva", DisplayName: "Ana Silva",
	Fields: map[string]string{"title": "Engineer", "employeeID": "E-1"}, Marker: Marker("108234567890123456789"), Reference: "run-1"}

func TestPlanParamRefusals(t *testing.T) {
	create := func(mod func(p *UserCreateParams)) Params {
		p := validCreate
		p.Fields = map[string]string{"title": "Engineer"}
		mod(&p)
		return p
	}
	sid := "S-1-5-21-1-2-3-1100"
	update := func(ch ...UserChange) Params { return UserUpdateParams{SID: sid, Marker: Marker("1"), Changes: ch} }
	cases := map[string]Params{
		"create no scope":       create(func(p *UserCreateParams) { p.ScopeOU = "" }),
		"create sam long":       create(func(p *UserCreateParams) { p.SAM = strings.Repeat("a", 21) }),
		"create sam char":       create(func(p *UserCreateParams) { p.SAM = "a@b" }),
		"create sam dot":        create(func(p *UserCreateParams) { p.SAM = "ana." }),
		"create sam space":      create(func(p *UserCreateParams) { p.SAM = " ana" }),
		"create upn":            create(func(p *UserCreateParams) { p.UPN = "ana" }),
		"create upn two at":     create(func(p *UserCreateParams) { p.UPN = "a@b@c" }),
		"create cn empty":       create(func(p *UserCreateParams) { p.CN = "" }),
		"create cn long":        create(func(p *UserCreateParams) { p.CN = strings.Repeat("c", 65) }),
		"create cn newline":     create(func(p *UserCreateParams) { p.CN = "a\nb" }),
		"create mail":           create(func(p *UserCreateParams) { p.Mail = "not an address" }),
		"create mail empty":     create(func(p *UserCreateParams) { p.Mail = "" }),
		"create given long":     create(func(p *UserCreateParams) { p.GivenName = strings.Repeat("g", 65) }),
		"create field":          create(func(p *UserCreateParams) { p.Fields = map[string]string{"adminCount": "1"} }),
		"create field marker":   create(func(p *UserCreateParams) { p.Fields = map[string]string{MarkerAttribute: "x"} }),
		"create employeeID":     create(func(p *UserCreateParams) { p.Fields = map[string]string{"employeeID": strings.Repeat("9", 17)} }),
		"create marker":         create(func(p *UserCreateParams) { p.Marker = "managed-by-ad-first:1" }),
		"create marker empty":   create(func(p *UserCreateParams) { p.Marker = MarkerPrefix }),
		"create marker chars":   create(func(p *UserCreateParams) { p.Marker = Marker("1)(cn=*") }),
		"create reference":      create(func(p *UserCreateParams) { p.Reference = "a\nb" }),
		"update none":           update(),
		"update attr":           update(UserChange{Attr: "userAccountControl", Before: "512", After: "514"}),
		"update marker attr":    update(UserChange{Attr: MarkerAttribute, Before: "", After: Marker("2")}),
		"update cn":             update(UserChange{Attr: "cn", Before: "a", After: "b"}),
		"update upn":            update(UserChange{Attr: "userPrincipalName", Before: "a@b", After: "c@b"}),
		"update case":           update(UserChange{Attr: "GivenName", Before: "a", After: "b"}),
		"update equal":          update(UserChange{Attr: "sn", Before: "a", After: "a"}),
		"update twice":          update(UserChange{Attr: "sn", Before: "a", After: "b"}, UserChange{Attr: "sn", Before: "b", After: "c"}),
		"update mail removed":   update(UserChange{Attr: "mail", Before: "a@b", After: ""}),
		"update mail shape":     update(UserChange{Attr: "mail", Before: "a@b", After: "ab"}),
		"update newline":        update(UserChange{Attr: "sn", Before: "a", After: "b\nc"}),
		"update proxy empty":    update(UserChange{Attr: "proxyAddresses", Before: "", After: "smtp:a@b\n\nsmtp:c@d"}),
		"update proxy dup":      update(UserChange{Attr: "proxyAddresses", Before: "", After: "smtp:a@b\nSMTP:A@B"}),
		"update proxy too many": update(UserChange{Attr: "proxyAddresses", Before: "", After: strings.Repeat("smtp:x\n", MaxProxyAddresses) + "smtp:y"}),
		"update bad sid":        UserUpdateParams{SID: "x", Marker: Marker("1"), Changes: []UserChange{{Attr: "sn", Before: "a", After: "b"}}},
		"update bad marker":     UserUpdateParams{SID: sid, Marker: "1", Changes: []UserChange{{Attr: "sn", Before: "a", After: "b"}}},
		"enable bad marker":     UserSetEnabledParams{SID: sid, Marker: ""},
		"enable bad sid":        UserSetEnabledParams{SID: "", Marker: Marker("1")},
		"move no ou":            UserMoveParams{SID: sid, Marker: Marker("1")},
		"move bad marker":       UserMoveParams{SID: sid, ToOU: "OU=X,DC=example,DC=com", Marker: "google-first:"},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The protocol form of a multi-valued attribute is sorted.
	if JoinValues([]string{"b", "a"}) != "a\nb" || len(SplitValues("")) != 0 || len(SplitValues("a\nb")) != 2 {
		t.Fatal("JoinValues/SplitValues")
	}
	if !OpUserMove.Mutating() || !OpUserCreate.Mutating() || !OpUserUpdate.Mutating() || !OpUserSetEnabled.Mutating() {
		t.Fatal("plan operations must be mutating")
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
	f.Add([]byte(`{"version":1,"id":"abcdefgh","op":"user.create","actor":{"user":"a","sid":"S-1-5-21-1","session":"s"},"params":{"scope_ou":"OU=P,DC=example,DC=com","sam":"ana","upn":"ana@example.com","cn":"Ana","mail":"ana@example.com","given_name":"Ana","fields":{"title":"T","mobile":"1"},"marker":"google-first:123","reference":"r"}}`))
	f.Add([]byte(`{"version":1,"id":"abcdefgh","op":"user.update","actor":{"user":"a","sid":"S-1-5-21-1","session":"s"},"params":{"sid":"S-1-5-21-1-2","changes":[{"attr":"mail","before":"a@b","after":"c@b"},{"attr":"proxyAddresses","before":"","after":"smtp:a@b\nsmtp:x@b"}],"marker":"google-first:123"}}`))
	f.Add([]byte(`{"version":1,"id":"abcdefgh","op":"user.set_enabled","actor":{"user":"a","sid":"S-1-5-21-1","session":"s"},"params":{"sid":"S-1-5-21-1-2","enabled":false,"marker":"google-first:123"}}`))
	f.Add([]byte(`{"version":1,"id":"abcdefgh","op":"user.move","actor":{"user":"a","sid":"S-1-5-21-1","session":"s"},"params":{"sid":"S-1-5-21-1-2","to_ou":"OU=Q,OU=P,DC=example,DC=com","marker":"google-first:123"}}`))
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
	f.Add([]byte(`{"version":1,"id":"abcdefgh","ok":true,"result":{"sid":"S-1-5-21-1-2","object_guid":"g","sam":"ana","dn":"CN=Ana,OU=P,DC=x"}}`))
	f.Add([]byte(`{"version":1,"id":"abcdefgh","ok":false,"error":{"code":"exists","message":"m","kinds":["sam","mail"]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var resp Response
		_ = ReadMessage(bufio.NewReader(bytes.NewReader(b)), &resp)
		var r TokenRevokeResult
		_ = DecodeResult(resp, &r)
		var c UserCreateResult
		_ = DecodeResult(resp, &c)
		var w UserWriteResult
		_ = DecodeResult(resp, &w)
	})
}

// FuzzPlanParams feeds arbitrary parameters to the plan operations: a
// decode either fails with invalid_params or yields parameters whose
// values stay one line (proxyAddresses aside), allowlisted and bounded.
func FuzzPlanParams(f *testing.F) {
	f.Add("user.create", []byte(`{"scope_ou":"OU=P,DC=example,DC=com","sam":"ana","upn":"ana@example.com","cn":"Ana","mail":"ana@example.com","fields":{"title":"T"},"marker":"google-first:1"}`))
	f.Add("user.update", []byte(`{"sid":"S-1-5-21-1-2","changes":[{"attr":"proxyAddresses","before":"smtp:a@b","after":"smtp:a@b\nsmtp:c@d"}],"marker":"google-first:1"}`))
	f.Add("user.set_enabled", []byte(`{"sid":"S-1-5-21-1-2","enabled":true,"marker":"google-first:1"}`))
	f.Add("user.move", []byte(`{"sid":"S-1-5-21-1-2","to_ou":"OU=Q,DC=example,DC=com","marker":"google-first:1"}`))
	f.Fuzz(func(t *testing.T, op string, params []byte) {
		req := Request{Version: ProtocolVersion, ID: "abcdefgh", Op: Op(op), Actor: actor, Params: params}
		p, err := req.Decode()
		if err != nil {
			var pe *Error
			if !errors.As(err, &pe) || pe.Code != CodeInvalidParams {
				t.Fatalf("decode error is not invalid_params: %v", err)
			}
			return
		}
		switch v := p.(type) {
		case *UserCreateParams:
			if !ValidMarker(v.Marker) || !ValidSAM(v.SAM) || strings.ContainsAny(v.CN+v.Mail+v.UPN+v.ScopeOU, "\n\r\x00") {
				t.Fatalf("invalid create accepted: %+v", v)
			}
			for k := range v.Fields {
				if !slices.Contains(CreateFields, k) {
					t.Fatalf("field %q accepted", k)
				}
			}
		case *UserUpdateParams:
			if !ValidMarker(v.Marker) || len(v.Changes) == 0 {
				t.Fatalf("invalid update accepted: %+v", v)
			}
			for _, c := range v.Changes {
				if !slices.Contains(UpdateAttributes, c.Attr) || c.Before == c.After {
					t.Fatalf("change %+v accepted", c)
				}
				if !MultiValued(c.Attr) && strings.ContainsAny(c.Before+c.After, "\n\r") {
					t.Fatalf("multi-line value accepted: %+v", c)
				}
			}
		case *UserSetEnabledParams:
			if !ValidMarker(v.Marker) {
				t.Fatalf("invalid marker accepted: %+v", v)
			}
		case *UserMoveParams:
			if !ValidMarker(v.Marker) || v.ToOU == "" {
				t.Fatalf("invalid move accepted: %+v", v)
			}
		}
	})
}
