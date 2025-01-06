package oauth21

import (
	"net/http"
	"net/url"
	"time"
)

// AuthorizeResponder is an authorization endpoint's response.
type AuthorizeResponder interface {
	// GetCode returns the response's authorize code if set.
	GetCode() string

	// GetHeader returns the response's header
	GetHeader() (header http.Header)

	// AddHeader adds an header key value pair to the response
	AddHeader(key, value string)

	// GetParameters returns the response's parameters
	GetParameters() (query url.Values)

	// AddParameter adds key value pair to the response
	AddParameter(key, value string)
}

// AccessResponder is a token endpoint's response.
type AccessResponder interface {
	// SetExtra sets a key value pair for the access response.
	SetExtra(key string, value interface{})

	// GetExtra returns a key's value.
	GetExtra(key string) interface{}

	SetExpiresIn(time.Duration)

	SetScopes(scopes Arguments)

	// SetAccessToken sets the responses mandatory access token.
	SetAccessToken(token string)

	// SetTokenType set's the responses mandatory token type
	SetTokenType(tokenType string)

	// GetAccessToken returns the responses access token.
	GetAccessToken() (token string)

	// GetTokenType returns the responses token type.
	GetTokenType() (token string)

	// ToMap converts the response to a map.
	ToMap() map[string]interface{}
}

// IntrospectionResponder is the response object that will be returned when token introspection was successful,
// for example when the client is allowed to perform token introspection. Refer to
// https://tools.ietf.org/search/rfc7662#section-2.2 for more details.
type IntrospectionResponder interface {
	// IsActive returns true if the introspected token is active and false otherwise.
	IsActive() bool

	// AccessRequester returns nil when IsActive() is false and the original access request object otherwise.
	GetAccessRequester() AccessRequester

	// GetTokenUse optionally returns the type of the token that was introspected. This could be "access_token", "refresh_token",
	// or if the type can not be determined an empty string.
	GetTokenUse() TokenUse

	//GetAccessTokenType optionally returns the type of the access token that was introspected. This could be "bearer", "mac",
	// or empty string if the type of the token is refresh token.
	GetAccessTokenType() string
}

// PushedAuthorizeResponder is the response object for PAR
type PushedAuthorizeResponder interface {
	// GetRequestURI returns the request_uri
	GetRequestURI() string
	// SetRequestURI sets the request_uri
	SetRequestURI(requestURI string)
	// GetExpiresIn gets the expires_in
	GetExpiresIn() int
	// SetExpiresIn sets the expires_in
	SetExpiresIn(seconds int)

	// GetHeader returns the response's header
	GetHeader() (header http.Header)

	// AddHeader adds an header key value pair to the response
	AddHeader(key, value string)

	// SetExtra sets a key value pair for the response.
	SetExtra(key string, value interface{})

	// GetExtra returns a key's value.
	GetExtra(key string) interface{}

	// ToMap converts the response to a map.
	ToMap() map[string]interface{}
}
