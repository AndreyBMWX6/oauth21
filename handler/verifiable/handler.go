package verifiable

import (
	"context"
	"time"

	"github.com/AndreyBMWX6/oauth21"
	"github.com/ory/x/errorsx"
)

const (
	draftScope         = "userinfo_credential_draft_00"
	draftNonceField    = "c_nonce_draft_00"
	draftNonceExpField = "c_nonce_expires_in_draft_00"
)

type Handler struct {
	Config interface {
		oauth21.VerifiableCredentialsNonceLifespanProvider
	}
	NonceManager
}

var _ oauth21.TokenEndpointHandler = (*Handler)(nil)

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request oauth21.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth21.ErrUnknownRequest)
	}

	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(
	ctx context.Context,
	request oauth21.AccessRequester,
	response oauth21.AccessResponder,
) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth21.ErrUnknownRequest)
	}

	lifespan := c.Config.GetVerifiableCredentialsNonceLifespan(ctx)
	expiry := time.Now().UTC().Add(lifespan)
	nonce, err := c.NewNonce(ctx, response.GetAccessToken(), expiry)
	if err != nil {
		return err
	}

	response.SetExtra(draftNonceField, nonce)
	response.SetExtra(draftNonceExpField, int64(lifespan.Seconds()))

	return nil
}

func (c *Handler) CanSkipClientAuth(context.Context, oauth21.AccessRequester) bool {
	return false
}

func (c *Handler) CanHandleTokenEndpointRequest(_ context.Context, requester oauth21.AccessRequester) bool {
	return requester.GetGrantedScopes().Has("openid", draftScope)
}
