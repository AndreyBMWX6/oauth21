package openid

import (
	"context"
	"time"

	"github.com/AndreyBMWX6/oauth21"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, lifespan time.Duration, requester oauth21.Requester) (token string, err error)
}
