package oauth2

import (
	"context"

	"github.com/AndreyBMWX6/oauth21"
)

type CoreStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

// AuthorizeCodeStorage handles storage requests related to authorization codes.
type AuthorizeCodeStorage interface {
	// GetAuthorizeCodeSession stores the authorization request for a given authorization code.
	CreateAuthorizeCodeSession(ctx context.Context, code string, request oauth21.Requester) (err error)

	// GetAuthorizeCodeSession hydrates the session based on the given code and returns the authorization request.
	// If the authorization code has been invalidated with `InvalidateAuthorizeCodeSession`, this
	// method should return the ErrInvalidatedAuthorizeCode error.
	//
	// Make sure to also return the oauth21.Requester value when returning the oauth21.ErrInvalidatedAuthorizeCode error!
	GetAuthorizeCodeSession(ctx context.Context, code string, session oauth21.Session) (request oauth21.Requester, err error)

	// InvalidateAuthorizeCodeSession is called when an authorize code is being used. The state of the authorization
	// code should be set to invalid and consecutive requests to GetAuthorizeCodeSession should return the
	// ErrInvalidatedAuthorizeCode error.
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(ctx context.Context, signature string, request oauth21.Requester) (err error)

	GetAccessTokenSession(ctx context.Context, signature string, session oauth21.Session) (request oauth21.Requester, err error)

	DeleteAccessTokenSession(ctx context.Context, signature string) (err error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(ctx context.Context, signature string, request oauth21.Requester) (err error)

	GetRefreshTokenSession(ctx context.Context, signature string, session oauth21.Session) (request oauth21.Requester, err error)

	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)
}
