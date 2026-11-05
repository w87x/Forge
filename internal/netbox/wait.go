package netbox

import (
	"context"
	"errors"
	"time"
)

// WaitForLocalBudget waits only for Forge's local limiter. A NetBox 429 is
// returned immediately and its shared cooldown is respected by future calls.
// The attempt limit bounds work when other requests keep consuming the budget.
func WaitForLocalBudget[T any](ctx context.Context, call func() (T, error)) (T, error) {
	for attempt := 0; ; attempt++ {
		value, err := call()
		var rate *RateLimitError
		if !errors.As(err, &rate) || !rate.Local || attempt >= 3 {
			return value, err
		}
		delay := rate.RetryAfter
		if delay < time.Millisecond {
			delay = time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return value, ctx.Err()
		case <-timer.C:
		}
	}
}
