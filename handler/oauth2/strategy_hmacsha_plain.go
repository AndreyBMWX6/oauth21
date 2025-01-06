package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/AndreyBMWX6/oauth21"
	enigma "github.com/AndreyBMWX6/oauth21/token/hmac"
)

var _ CoreStrategy = (*HMACSHAStrategyUnPrefixed)(nil)

type HMACSHAStrategyUnPrefixed struct {
	Enigma *enigma.HMACStrategy
	Config LifespanConfigProvider
}

func NewHMACSHAStrategyUnPrefixed(
	enigma *enigma.HMACStrategy,
	config LifespanConfigProvider,
) *HMACSHAStrategyUnPrefixed {
	return &HMACSHAStrategyUnPrefixed{
		Enigma: enigma,
		Config: config,
	}
}

func (h *HMACSHAStrategyUnPrefixed) AccessTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}
func (h *HMACSHAStrategyUnPrefixed) RefreshTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}
func (h *HMACSHAStrategyUnPrefixed) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategyUnPrefixed) GenerateAccessToken(ctx context.Context, _ oauth21.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return token, sig, nil
}

func (h *HMACSHAStrategyUnPrefixed) ValidateAccessToken(ctx context.Context, r oauth21.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth21.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth21.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth21.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, token)
}

func (h *HMACSHAStrategyUnPrefixed) GenerateRefreshToken(ctx context.Context, _ oauth21.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return token, sig, nil
}

func (h *HMACSHAStrategyUnPrefixed) ValidateRefreshToken(ctx context.Context, r oauth21.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth21.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(ctx, token)
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth21.ErrTokenExpired.WithHintf("Refresh token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, token)
}

func (h *HMACSHAStrategyUnPrefixed) GenerateAuthorizeCode(ctx context.Context, _ oauth21.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return token, sig, nil
}

func (h *HMACSHAStrategyUnPrefixed) ValidateAuthorizeCode(ctx context.Context, r oauth21.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(oauth21.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth21.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(oauth21.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, token)
}
