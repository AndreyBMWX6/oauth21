package oauth21
type TokenType string

const (
	AccessToken   TokenType = "access_token"
	RefreshToken  TokenType = "refresh_token"
	AuthorizeCode TokenType = "authorize_code"
	IDToken       TokenType = "id_token"
	// PushedAuthorizeRequestContext represents the PAR context object
	PushedAuthorizeRequestContext TokenType = "par_context"

	BearerAccessToken string = "bearer"
)
