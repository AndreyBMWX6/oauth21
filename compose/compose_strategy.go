package compose

import (
	"context"

	"github.com/AndreyBMWX6/oauth21"
	"github.com/AndreyBMWX6/oauth21/handler/oauth2"
	"github.com/AndreyBMWX6/oauth21/handler/openid"
	"github.com/AndreyBMWX6/oauth21/token/hmac"
	"github.com/AndreyBMWX6/oauth21/token/jwt"
)

type CommonStrategy struct {
	oauth2.CoreStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.Signer
}

type HMACSHAStrategyConfigurator interface {
	oauth21.AccessTokenLifespanProvider
	oauth21.RefreshTokenLifespanProvider
	oauth21.AuthorizeCodeLifespanProvider
	oauth21.TokenEntropyProvider
	oauth21.GlobalSecretProvider
	oauth21.RotatedGlobalSecretsProvider
	oauth21.HMACHashingProvider
}

func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *oauth2.HMACSHAStrategy {
	return oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config)
}

func NewOAuth2JWTStrategy(keyGetter func(context.Context) (interface{}, error), strategy oauth2.CoreStrategy, config oauth21.Configurator) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		Signer:          &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		HMACSHAStrategy: strategy,
		Config:          config,
	}
}

func NewOpenIDConnectStrategy(keyGetter func(context.Context) (interface{}, error), config oauth21.Configurator) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		Config: config,
	}
}
