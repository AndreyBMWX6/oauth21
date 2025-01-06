package oauth2

import (
	"context"
	"time"

	"github.com/AndreyBMWX6/oauth21"
	"github.com/AndreyBMWX6/oauth21/token/jwt"
)

type StatelessJWTValidator struct {
	jwt.Signer
	Config interface {
		oauth21.ScopeStrategyProvider
	}
}

// AccessTokenJWTToRequest tries to reconstruct oauth21.Request from a JWT.
func AccessTokenJWTToRequest(token *jwt.Token) oauth21.Requester {
	mapClaims := token.Claims
	claims := jwt.JWTClaims{}
	claims.FromMapClaims(mapClaims)

	requestedAt := claims.IssuedAt
	requestedAtClaim, ok := mapClaims["rat"]
	if ok {
		switch at := requestedAtClaim.(type) {
		case float64:
			requestedAt = time.Unix(int64(at), 0).UTC()
		case int64:
			requestedAt = time.Unix(at, 0).UTC()
		}
	}

	clientId := ""
	clientIdClaim, ok := mapClaims["client_id"]
	if ok {
		switch cid := clientIdClaim.(type) {
		case string:
			clientId = cid
		}
	}

	return &oauth21.Request{
		RequestedAt: requestedAt,
		Client: &oauth21.DefaultClient{
			ID: clientId,
		},
		// We do not really know which scopes were requested, so we set them to granted.
		RequestedScope: claims.Scope,
		GrantedScope:   claims.Scope,
		Session: &JWTSession{
			JWTClaims: &claims,
			JWTHeader: &jwt.Headers{
				Extra: token.Header,
			},
			ExpiresAt: map[oauth21.TokenType]time.Time{
				oauth21.AccessToken: claims.ExpiresAt,
			},
			Subject: claims.Subject,
		},
		// We do not really know which audiences were requested, so we set them to granted.
		RequestedAudience: claims.Audience,
		GrantedAudience:   claims.Audience,
	}
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenUse oauth21.TokenUse, accessRequest oauth21.AccessRequester, scopes []string) (oauth21.TokenUse, error) {
	t, err := validate(ctx, v.Signer, token)
	if err != nil {
		return "", err
	}

	// TODO: From here we assume it is an access token, but how do we know it is really and that is not an ID token?

	requester := AccessTokenJWTToRequest(t)

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return oauth21.AccessToken, err
	}

	accessRequest.Merge(requester)

	return oauth21.AccessToken, nil
}
