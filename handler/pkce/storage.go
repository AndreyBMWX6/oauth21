package pkce

import (
	"context"

	"github.com/AndreyBMWX6/oauth21"
)

type PKCERequestStorage interface {
	GetPKCERequestSession(ctx context.Context, signature string, session oauth21.Session) (oauth21.Requester, error)
	CreatePKCERequestSession(ctx context.Context, signature string, requester oauth21.Requester) error
	DeletePKCERequestSession(ctx context.Context, signature string) error
}
