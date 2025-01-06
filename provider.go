package oauth21

import (
	"context"
)

// todo: uncomment
// compile-time check
//var _ OAuth2 = (*OAuth2Provider)(nil)

const MinParameterEntropy = 8

type OAuth2Provider struct {
	Storage Storage
	Config  Configurator
}

func NewOAuth2Provider(s Storage, c Configurator) *OAuth2Provider {
	return &OAuth2Provider{
		Storage: s,
		Config:  c,
	}
}

// GetMinParameterEntropy returns MinParameterEntropy if set. Defaults to fosite.MinParameterEntropy.
func (p *OAuth2Provider) GetMinParameterEntropy(ctx context.Context) int {
	if mp := p.Config.GetMinParameterEntropy(ctx); mp > 0 {
		return mp
	}

	return MinParameterEntropy
}

func (p *OAuth2Provider) ResponseModeHandler(ctx context.Context) ResponseModeHandler {
	if ext := p.Config.GetResponseModeHandlerExtension(ctx); ext != nil {
		return ext
	}
	return defaultResponseModeHandler
}
