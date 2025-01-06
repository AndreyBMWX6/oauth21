package compose

import (
	"github.com/AndreyBMWX6/oauth21"
	"github.com/AndreyBMWX6/oauth21/handler/verifiable"
)

// OIDCUserinfoVerifiableCredentialFactory creates a verifiable credentials
// handler.
func OIDCUserinfoVerifiableCredentialFactory(config oauth21.Configurator, storage, strategy any) any {
	return &verifiable.Handler{
		NonceManager: storage.(verifiable.NonceManager),
		Config:       config,
	}
}
