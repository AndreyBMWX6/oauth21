package oauth21

import (
	"context"
	"encoding/json"
	"net/http"
)

func (p *OAuth2Provider) WriteAccessResponse(ctx context.Context, rw http.ResponseWriter, requester AccessRequester, responder AccessResponder) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	js, err := json.Marshal(responder.ToMap())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(js)
}
