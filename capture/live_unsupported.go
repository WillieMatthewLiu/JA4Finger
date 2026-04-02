//go:build !linux

package capture

import (
	"context"
	"errors"
)

// ErrLiveCaptureUnsupported is returned when live capture is not available on the current OS.
var ErrLiveCaptureUnsupported = errors.New("live capture requires Linux/AF_PACKET support")

func NewLiveSource(context.Context, string) (*Source, error) {
	return nil, ErrLiveCaptureUnsupported
}
