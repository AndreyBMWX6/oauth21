package oauth21

import (
	"context"
	"net/http"
	"net/url"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/otelx"
	"go.opentelemetry.io/otel/trace"
)

func (p *OAuth2Provider) NewAuthorizeResponse(ctx context.Context, ar AuthorizeRequester, session Session) (_ AuthorizeResponder, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/AndreyBMWX6/oauth21").Start(ctx, "OAuth2Provider.NewAuthorizeResponse")
	defer otelx.End(span, &err)

	var resp = &AuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, ar)
	ctx = context.WithValue(ctx, AuthorizeResponseContextKey, resp)

	ar.SetSession(session)
	for _, h := range p.Config.GetAuthorizeEndpointHandlers(ctx) {
		if err := h.HandleAuthorizeEndpointRequest(ctx, ar, resp); err != nil {
			return nil, err
		}
	}

	if !ar.DidHandleAllResponseTypes() {
		return nil, errorsx.WithStack(ErrUnsupportedResponseType)
	}

	if ar.GetDefaultResponseMode() == ResponseModeFragment && ar.GetResponseMode() == ResponseModeQuery {
		return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", ar.GetResponseMode(), ar.GetResponseTypes())
	}

	return resp, nil
}
