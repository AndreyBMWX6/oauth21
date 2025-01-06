package openid

import (
	"context"

	"github.com/AndreyBMWX6/oauth21"
)

type OpenIDConnectRequestStorage interface {
	// CreateOpenIDConnectSession creates an open id connect session
	// for a given authorize code. This is relevant for explicit open id connect flow.
	CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester oauth21.Requester) error

	// GetOpenIDConnectSession returns error
	// - nil if a session was found,
	// - ErrNoSessionFound if no session was found
	// - or an arbitrary error if an error occurred.
	GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester oauth21.Requester) (oauth21.Requester, error)

	// DeleteOpenIDConnectSession removes an open id connect session from the store.
	DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error
}
