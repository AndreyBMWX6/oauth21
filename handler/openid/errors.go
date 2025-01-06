package openid

import (
	"github.com/AndreyBMWX6/oauth21"
	"github.com/pkg/errors"
)

var (
	ErrInvalidSession = errors.New("Session type mismatch")
	ErrNoSessionFound = oauth21.ErrNotFound
)
