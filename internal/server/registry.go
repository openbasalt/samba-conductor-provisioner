package server

import (
	"context"

	"github.com/openbasalt/samba-conductor-provisioner/provapi"
)

// handler is one typed operation. run receives the decoded, validated
// parameters (the provapi type of the operation) and fills the call's
// audit fields. Operations that change tokens or the directory are
// mutating: they run one at a time and are always audited. Every handler
// that names a target goes through readTarget and requireEligible.
type handler struct {
	mutating bool
	run      func(ctx context.Context, s *Service, c *call, p provapi.Params) (any, *provapi.Error)
}

// typed adapts a handler written for one parameter type.
func typed[P provapi.Params](fn func(ctx context.Context, s *Service, c *call, p P) (any, *provapi.Error)) func(context.Context, *Service, *call, provapi.Params) (any, *provapi.Error) {
	return func(ctx context.Context, s *Service, c *call, p provapi.Params) (any, *provapi.Error) {
		v, ok := p.(P)
		if !ok {
			return nil, fail(provapi.CodeInternal, "parameter type mismatch")
		}
		return fn(ctx, s, c, v)
	}
}

// registry maps each allowlisted operation to its handler. A test checks
// that it covers provapi.Allowlist exactly.
var registry = map[provapi.Op]handler{
	provapi.OpStatus:         {run: typed(opStatus)},
	provapi.OpUserCheck:      {run: typed(opUserCheck)},
	provapi.OpUserFind:       {run: typed(opUserFind)},
	provapi.OpTokenCheck:     {run: typed(opTokenCheck)},
	provapi.OpTokenList:      {run: typed(opTokenList)},
	provapi.OpTokenIssue:     {mutating: true, run: typed(opTokenIssue)},
	provapi.OpPasswordSet:    {mutating: true, run: typed(opPasswordSet)},
	provapi.OpInviteComplete: {mutating: true, run: typed(opInviteComplete)},
	provapi.OpTokenRevoke:    {mutating: true, run: typed(opTokenRevoke)},
	provapi.OpUserCreate:     {mutating: true, run: typed(opUserCreate)},
	provapi.OpUserUpdate:     {mutating: true, run: typed(opUserUpdate)},
	provapi.OpUserSetEnabled: {mutating: true, run: typed(opUserSetEnabled)},
	provapi.OpUserMove:       {mutating: true, run: typed(opUserMove)},
}
