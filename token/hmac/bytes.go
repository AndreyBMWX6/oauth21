package hmac

import (
	"crypto/rand"
	"io"

	"github.com/ory/x/errorsx"
)

// RandomBytes returns n random bytes by reading from crypto/rand.Reader
func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return []byte{}, errorsx.WithStack(err)
	}
	return bytes, nil
}
