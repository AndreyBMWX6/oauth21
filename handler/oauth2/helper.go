package oauth2

import (
	"context"
	"time"

	"github.com/AndreyBMWX6/oauth21"
)

type HandleHelperConfigProvider interface {
	oauth21.AccessTokenLifespanProvider
	oauth21.RefreshTokenLifespanProvider
}

type HandleHelper struct {
	AccessTokenStrategy AccessTokenStrategy
	AccessTokenStorage  AccessTokenStorage
	Config              HandleHelperConfigProvider
}

func (h *HandleHelper) IssueAccessToken(ctx context.Context, defaultLifespan time.Duration, requester oauth21.AccessRequester, responder oauth21.AccessResponder) error {
	token, signature, err := h.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return err
	} else if err := h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, requester.Sanitize([]string{})); err != nil {
		return err
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, oauth21.AccessToken, defaultLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	return nil
}

func getExpiresIn(r oauth21.Requester, key oauth21.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
