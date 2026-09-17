package systemproxy

import "context"

type Unsupported struct {
	Reason string
}

func (u Unsupported) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{Version: 1, Values: []byte("{}")}, nil
}

func (u Unsupported) Apply(context.Context, Endpoint) error {
	return ErrUnsupported
}

func (u Unsupported) Restore(context.Context, Snapshot) error {
	return nil
}

func (u Unsupported) Matches(context.Context, Snapshot, Endpoint) (bool, error) {
	return false, ErrUnsupported
}

func (u Unsupported) String() string {
	return u.Reason
}
