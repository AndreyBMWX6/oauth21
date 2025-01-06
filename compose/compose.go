package compose

import (
	"context"

	"github.com/AndreyBMWX6/oauth21"
	"github.com/AndreyBMWX6/oauth21/token/jwt"
)

type Factory func(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{}

// Compose takes a config, a storage, a strategy and handlers to instantiate an OAuth2Provider:
//
//	 import "github.com/AndreyBMWX6/oauth21/compose"
//
//	 // var storage = new(MyOAuth21Storage)
//	 var config = Config {
//	 	AccessTokenLifespan: time.Minute * 30,
//			// check Config for further configuration options
//	 }
//
//	 var strategy = NewOAuth2HMACStrategy(config)
//
//	 var oauth2Provider = Compose(
//	 	config,
//			storage,
//			strategy,
//			NewOAuth2AuthorizeExplicitHandler,
//			OAuth2ClientCredentialsGrantFactory,
//			// for a complete list refer to the docs of this package
//	 )
//
// Compose makes use of interface{} types in order to be able to handle a all types of stores, strategies and handlers.
func Compose(config *oauth21.Config, storage interface{}, strategy interface{}, factories ...Factory) oauth21.OAuth2 {
	f := oauth21.NewOAuth2Provider(storage.(oauth21.Storage), config)
	for _, factory := range factories {
		res := factory(config, storage, strategy)
		if ah, ok := res.(oauth21.AuthorizeEndpointHandler); ok {
			config.AuthorizeEndpointHandlers.Append(ah)
		}
		if th, ok := res.(oauth21.TokenEndpointHandler); ok {
			config.TokenEndpointHandlers.Append(th)
		}
		if tv, ok := res.(oauth21.TokenIntrospector); ok {
			config.TokenIntrospectionHandlers.Append(tv)
		}
		if rh, ok := res.(oauth21.RevocationHandler); ok {
			config.RevocationHandlers.Append(rh)
		}
		if ph, ok := res.(oauth21.PushedAuthorizeEndpointHandler); ok {
			config.PushedAuthorizeEndpointHandlers.Append(ph)
		}
	}

	return f
}

// ComposeAllEnabled returns an oauth21 instance with all OAuth2.1 and OpenID Connect explicit flow handlers enabled.
func ComposeAllEnabled(config *oauth21.Config, storage interface{}, key interface{}) oauth21.OAuth2 {
	keyGetter := func(context.Context) (interface{}, error) {
		return key, nil
	}
	return Compose(
		config,
		storage,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		OAuth2AuthorizeExplicitFactory,
		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		RFC7523AssertionGrantFactory,

		OpenIDConnectExplicitFactory,
		OpenIDConnectRefreshFactory,

		OAuth2TokenIntrospectionFactory,
		OAuth2TokenRevocationFactory,

		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
	)
}
