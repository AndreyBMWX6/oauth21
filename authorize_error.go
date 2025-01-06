package oauth21

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (p *OAuth2Provider) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	if p.ResponseModeHandler(ctx).ResponseModes().Has(ar.GetResponseMode()) {
		p.ResponseModeHandler(ctx).WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(p.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(p.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(p.Config.GetMessageCatalog(ctx), getLangFromRequester(ar))
	if !ar.IsRedirectURIValid() {
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

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
		_, _ = rw.Write(js)
		return
	}

	redirectURI := ar.GetRedirectURI()

	// The endpoint URI MUST NOT include a fragment component.
	redirectURI.Fragment = ""

	errors := rfcerr.ToValues()
	errors.Set("state", ar.GetState())

	var redirectURIString string
	if ar.GetResponseMode() == ResponseModeFormPost {
		rw.Header().Set("Content-Type", "text/html;charset=UTF-8")
		WriteAuthorizeFormPostResponse(redirectURI.String(), errors, GetPostFormHTMLTemplate(ctx, p), rw)
		return
	} else if ar.GetResponseMode() == ResponseModeFragment {
		redirectURIString = redirectURI.String() + "#" + errors.Encode()
	} else {
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				errors.Add(key, value)
			}
		}
		redirectURI.RawQuery = errors.Encode()
		redirectURIString = redirectURI.String()
	}

	rw.Header().Set("Location", redirectURIString)
	rw.WriteHeader(http.StatusSeeOther)
}
