package oauth21

import (
	"context"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/otelx"
	"go.opentelemetry.io/otel/trace"

	"github.com/pkg/errors"
)

func (p *OAuth2Provider) NewAccessResponse(ctx context.Context, requester AccessRequester) (_ AccessResponder, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/AndreyBMWX6/oauth21").Start(ctx, "OAuth2Provider.NewAccessResponse")
	defer otelx.End(span, &err)

	var tk TokenEndpointHandler

	response := NewAccessResponse()

	ctx = context.WithValue(ctx, AccessRequestContextKey, requester)
	ctx = context.WithValue(ctx, AccessResponseContextKey, response)

	for _, tk = range p.Config.GetTokenEndpointHandlers(ctx) {
		if err = tk.PopulateTokenEndpointResponse(ctx, requester, response); err == nil {
			// do nothing
		} else if errors.Is(err, ErrUnknownRequest) {
			// do nothing
		} else if err != nil {
			return nil, err
		}
	}

	if response.GetAccessToken() == "" || response.GetTokenType() == "" {
		return nil, errorsx.WithStack(ErrServerError.
			WithHint("An internal server occurred while trying to complete the request.").
			WithDebug("Access token or token type not set by TokenEndpointHandlers.").
			WithLocalizer(p.Config.GetMessageCatalog(ctx), getLangFromRequester(requester)))
	}

	return response, nil
}
