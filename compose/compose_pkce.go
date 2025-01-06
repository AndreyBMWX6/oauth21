package compose

import (
	"github.com/AndreyBMWX6/oauth21"
	"github.com/AndreyBMWX6/oauth21/handler/oauth2"
	"github.com/AndreyBMWX6/oauth21/handler/pkce"
)

// OAuth2PKCEFactory creates a PKCE handler.
func OAuth2PKCEFactory(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &pkce.Handler{
		AuthorizeCodeStrategy: strategy.(oauth2.AuthorizeCodeStrategy),
		Storage:               storage.(pkce.PKCERequestStorage),
		Config:                config,
	}
}
