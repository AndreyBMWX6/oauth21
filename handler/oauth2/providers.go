package oauth2

import "github.com/AndreyBMWX6/oauth21"

type LifespanConfigProvider interface {
	oauth21.AccessTokenLifespanProvider
	oauth21.RefreshTokenLifespanProvider
	oauth21.AuthorizeCodeLifespanProvider
}
