package netbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitForLocalBudget(t *testing.T) {
	attempts := 0
	result, err := WaitForLocalBudget(context.Background(), func() (string, error) {
		attempts++
		if attempts == 1 {
			return "", &RateLimitError{RetryAfter: time.Millisecond, Local: true}
		}
		return "ok", nil
	})
	if err != nil || result != "ok" || attempts != 2 {
		t.Fatalf("local wait: %q %v (%d calls)", result, err, attempts)
	}
	attempts = 0
	_, err = WaitForLocalBudget(context.Background(), func() (string, error) {
		attempts++
		return "", &RateLimitError{RetryAfter: time.Hour}
	})
	var rate *RateLimitError
	if !errors.As(err, &rate) || attempts != 1 {
		t.Fatalf("remote cooldown retried: %v (%d calls)", err, attempts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = WaitForLocalBudget(ctx, func() (string, error) { return "", &RateLimitError{RetryAfter: time.Hour, Local: true} })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}
