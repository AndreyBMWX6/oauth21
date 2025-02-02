package oauth21

import (
	"context"
)

type Storage interface {
	ClientManager
}

// PARStorage holds information needed to store and retrieve PAR context.
type PARStorage interface {
	// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
	CreatePARSession(ctx context.Context, requestURI string, request AuthorizeRequester) error
	// GetPARSession gets the push authorization request context. The caller is expected to merge the AuthorizeRequest.
	GetPARSession(ctx context.Context, requestURI string) (AuthorizeRequester, error)
	// DeletePARSession deletes the context.
	DeletePARSession(ctx context.Context, requestURI string) (err error)
}
