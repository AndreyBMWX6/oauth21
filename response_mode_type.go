package oauth21
type ResponseModeType string

const (
	ResponseModeDefault  = ResponseModeType("")
	ResponseModeFormPost = ResponseModeType("form_post")
	ResponseModeQuery    = ResponseModeType("query")
	ResponseModeFragment = ResponseModeType("fragment")
)

type ResponseModeTypes []ResponseModeType

func (rs ResponseModeTypes) Has(item ResponseModeType) bool {
	for _, r := range rs {
		if r == item {
			return true
		}
	}
	return false
}
