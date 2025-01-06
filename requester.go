package oauth21

import (
	"net/url"
	"time"
)

// Requester is an abstract interface for handling requests in OAuth2.
type Requester interface {
	// SetID sets the unique identifier.
	SetID(id string)

	// GetID returns a unique identifier.
	GetID() string

	// GetRequestedAt returns the time the request was created.
	GetRequestedAt() (requestedAt time.Time)

	// GetClient returns the request's client.
	GetClient() (client Client)

	// GetRequestedScopes returns the request's scopes.
	GetRequestedScopes() (scopes Arguments)

	// GetRequestedAudience returns the requested audiences for this request.
	GetRequestedAudience() (audience Arguments)

	// SetRequestedScopes sets the request's scopes.
	SetRequestedScopes(scopes Arguments)

	// SetRequestedAudience sets the requested audience.
	SetRequestedAudience(audience Arguments)

	// AppendRequestedScope appends a scope to the request.
	AppendRequestedScope(scope string)

	// GetGrantScopes returns all granted scopes.
	GetGrantedScopes() (grantedScopes Arguments)

	// GetGrantedAudience returns all granted audiences.
	GetGrantedAudience() (grantedAudience Arguments)

	// GrantScope marks a request's scope as granted.
	GrantScope(scope string)

	// GrantAudience marks a request's audience as granted.
	GrantAudience(audience string)

	// GetSession returns a pointer to the request's session or nil if none is set.
	GetSession() (session Session)

	// SetSession sets the request's session pointer.
	SetSession(session Session)

	// GetRequestForm returns the request's form input.
	GetRequestForm() url.Values

	// Merge merges the argument into the method receiver.
	Merge(requester Requester)

	// Sanitize returns a sanitized clone of the request which can be used for storage.
	Sanitize(allowedParameters []string) Requester
}

// AuthorizeRequester is an authorize endpoint's request context.
type AuthorizeRequester interface {
	// GetResponseTypes returns the requested response types
	GetResponseTypes() (responseTypes Arguments)

	// SetResponseTypeHandled marks a response_type (e.g. token or code) as handled indicating that the response type
	// is supported.
	SetResponseTypeHandled(responseType string)

	// DidHandleAllResponseTypes returns if all requested response types have been handled correctly
	DidHandleAllResponseTypes() (didHandle bool)

	// GetRedirectURI returns the requested redirect URI
	GetRedirectURI() (redirectURL *url.URL)

	// IsRedirectURIValid returns false if the redirect is not rfc-conform (i.e. missing client, not on white list,
	// or malformed)
	IsRedirectURIValid() (isValid bool)

	// GetState returns the request's state.
	GetState() (state string)

	// GetResponseMode returns response_mode of the authorization request
	GetResponseMode() ResponseModeType

	// SetDefaultResponseMode sets default response mode for a response type in a flow
	SetDefaultResponseMode(responseMode ResponseModeType)

	// GetDefaultResponseMode gets default response mode for a response type in a flow
	GetDefaultResponseMode() ResponseModeType

	Requester
}

// AccessRequester is a token endpoint's request context.
type AccessRequester interface {
	// GetGrantTypes returns the requests grant types.
	GetGrantTypes() (grantTypes Arguments)

	Requester
}
