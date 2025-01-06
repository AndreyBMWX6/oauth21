package oauth21
type GrantType string

const (
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeJWTBearer         GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // this is not a hardcoded credential
)
