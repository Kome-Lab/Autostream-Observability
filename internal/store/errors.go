package store

import "errors"

var ErrNotFound = errors.New("not found")
var ErrInvalidStatus = errors.New("invalid status")
var ErrInvalidTransition = errors.New("invalid incident status transition")
