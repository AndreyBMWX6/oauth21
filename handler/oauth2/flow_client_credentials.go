package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/AndreyBMWX6/oauth21"
)

var _ oauth21.TokenEndpointHandler = (*ClientCredentialsGrantHandler)(nil)

type ClientCredentialsGrantHandler struct {
	*HandleHelper
	Config interface {
		oauth21.ScopeStrategyProvider
		oauth21.AudienceStrategyProvider
		oauth21.AccessTokenLifespanProvider
	}
}

// IntrospectTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.4.2
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth21.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth21.ErrUnknownRequest)
	}

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth21.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// This requirement is already fulfilled because fosite requires all token requests to be authenticated as described
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1
	if client.IsPublic() {
		return errorsx.WithStack(oauth21.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'client_credentials'."))
	}
	// if the client is not public, he has already been authenticated by the access request handler.

	atLifespan := oauth21.GetEffectiveLifespan(client, oauth21.GrantTypeClientCredentials, oauth21.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(oauth21.AccessToken, time.Now().UTC().Add(atLifespan))
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.4.3
func (c *ClientCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth21.AccessRequester, response oauth21.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth21.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("client_credentials") {
		return errorsx.WithStack(oauth21.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'."))
	}

	atLifespan := oauth21.GetEffectiveLifespan(request.GetClient(), oauth21.GrantTypeClientCredentials, oauth21.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	return c.IssueAccessToken(ctx, atLifespan, request, response)
}

func (c *ClientCredentialsGrantHandler) CanSkipClientAuth(ctx context.Context, requester oauth21.AccessRequester) bool {
	return false
}

func (c *ClientCredentialsGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth21.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	return requester.GetGrantTypes().ExactOne("client_credentials")
}
