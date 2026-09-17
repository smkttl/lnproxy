//go:build !linux && !windows

package systemproxy

func New() SystemProxy {
	return Unsupported{Reason: ErrUnsupported.Error()}
}
