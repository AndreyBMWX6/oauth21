package compose

import (
	"github.com/AndreyBMWX6/oauth21"
	"github.com/AndreyBMWX6/oauth21/handler/oauth2"
	"github.com/AndreyBMWX6/oauth21/token/jwt"
)

// OAuth2AuthorizeExplicitFactory creates an OAuth2 authorize code grant ("authorize explicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeExplicitFactory(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &oauth2.AuthorizeExplicitGrantHandler{
		AccessTokenStrategy:    strategy.(oauth2.AccessTokenStrategy),
		RefreshTokenStrategy:   strategy.(oauth2.RefreshTokenStrategy),
		AuthorizeCodeStrategy:  strategy.(oauth2.AuthorizeCodeStrategy),
		CoreStorage:            storage.(oauth2.CoreStorage),
		TokenRevocationStorage: storage.(oauth2.TokenRevocationStorage),
		Config:                 config,
	}
}

// OAuth2ClientCredentialsGrantFactory creates an OAuth2 client credentials grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2ClientCredentialsGrantFactory(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &oauth2.ClientCredentialsGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
			Config:              config,
		},
		Config: config,
	}
}

// OAuth2RefreshTokenGrantFactory creates an OAuth2 refresh grant handler and registers
// an access token, refresh token and authorize code validator.nmj
func OAuth2RefreshTokenGrantFactory(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &oauth2.RefreshTokenGrantHandler{
		AccessTokenStrategy:    strategy.(oauth2.AccessTokenStrategy),
		RefreshTokenStrategy:   strategy.(oauth2.RefreshTokenStrategy),
		TokenRevocationStorage: storage.(oauth2.TokenRevocationStorage),
		Config:                 config,
	}
}

// OAuth2TokenRevocationFactory creates an OAuth2 token revocation handler.
func OAuth2TokenRevocationFactory(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &oauth2.TokenRevocationHandler{
		TokenRevocationStorage: storage.(oauth2.TokenRevocationStorage),
		AccessTokenStrategy:    strategy.(oauth2.AccessTokenStrategy),
		RefreshTokenStrategy:   strategy.(oauth2.RefreshTokenStrategy),
	}
}

// OAuth2TokenIntrospectionFactory creates an OAuth2 token introspection handler and registers
// an access token and refresh token validator.
func OAuth2TokenIntrospectionFactory(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &oauth2.CoreValidator{
		CoreStrategy: strategy.(oauth2.CoreStrategy),
		CoreStorage:  storage.(oauth2.CoreStorage),
		Config:       config,
	}
}

// OAuth2StatelessJWTIntrospectionFactory creates an OAuth2 token introspection handler and
// registers an access token validator. This can only be used to validate JWTs and does so
// statelessly, meaning it uses only the data available in the JWT itself, and does not access the
// storage implementation at all.
//
// Due to the stateless nature of this factory, THE BUILT-IN REVOCATION MECHANISMS WILL NOT WORK.
// If you need revocation, you can validate JWTs statefully, using the other factories.
func OAuth2StatelessJWTIntrospectionFactory(config oauth21.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &oauth2.StatelessJWTValidator{
		Signer: strategy.(jwt.Signer),
		Config: config,
	}
}
