package openid

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/AndreyBMWX6/oauth21"
)

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth21.AccessRequester) error {
	return errorsx.WithStack(oauth21.ErrUnknownRequest)
}

func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth21.AccessRequester, responder oauth21.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth21.ErrUnknownRequest)
	}

	authorizeCode := requester.GetRequestForm().Get("code")

	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, authorizeCode, requester)
	if errors.Is(err, ErrNoSessionFound) {
		return errorsx.WithStack(oauth21.ErrUnknownRequest.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(oauth21.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if !authorize.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(oauth21.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration."))
	}

	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(oauth21.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"authorization_code\"."))
	}

	sess, ok := authorize.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(oauth21.ErrServerError.WithDebug("Failed to generate id token because session must be of type fosite/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(oauth21.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	err = c.OpenIDConnectRequestStorage.DeleteOpenIDConnectSession(ctx, authorizeCode)
	if err != nil {
		return errorsx.WithStack(oauth21.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)

	// The response type `id_token` is only required when performing the implicit or hybrid flow, see:
	// https://openid.net/specs/openid-connect-registration-1_0.html
	//
	// if !requester.GetClient().GetResponseTypes().Has("id_token") {
	// 	return errorsx.WithStack(oauth21.ErrInvalidGrant.WithDebug("The client is not allowed to use response type id_token"))
	// }

	idTokenLifespan := oauth21.GetEffectiveLifespan(requester.GetClient(), oauth21.GrantTypeAuthorizationCode, oauth21.IDToken, c.Config.GetIDTokenLifespan(ctx))
	return c.IssueExplicitIDToken(ctx, idTokenLifespan, authorize, responder)
}

func (c *OpenIDConnectExplicitHandler) CanSkipClientAuth(ctx context.Context, requester oauth21.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectExplicitHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth21.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
