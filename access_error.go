package oauth21

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (p *OAuth2Provider) WriteAccessError(ctx context.Context, rw http.ResponseWriter, req AccessRequester, err error) {
	p.writeJsonError(ctx, rw, req, err)
}

func (p *OAuth2Provider) writeJsonError(ctx context.Context, rw http.ResponseWriter, requester AccessRequester, err error) {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(p.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(p.Config.GetSendDebugMessagesToClients(ctx))

	if requester != nil {
		rfcerr = rfcerr.WithLocalizer(p.Config.GetMessageCatalog(ctx), getLangFromRequester(requester))
	}

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if p.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	// ignoring the error because the connection is broken when it happens
	_, _ = rw.Write(js)
}
