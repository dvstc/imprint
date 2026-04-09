package client

import (
	"context"
	"sync"
	"time"
)

// AutoRenewerConfig configures the background certificate auto-renewer.
type AutoRenewerConfig struct {
	RenewConfig   RenewConfig
	EnrollConfig  EnrollConfig
	CheckInterval time.Duration    // how often to check; default: 24h
	Threshold     time.Duration    // renew when cert expires within this; default: 30 days
	OnRenew       func(action string) // called on successful renewal with the action taken
	OnError       func(error)         // called on renewal failure
}

// AutoRenewer periodically checks certificate expiry and renews as needed.
type AutoRenewer struct {
	cfg AutoRenewerConfig
	mu  sync.Mutex
}

// NewAutoRenewer creates a new AutoRenewer with the given configuration.
func NewAutoRenewer(cfg AutoRenewerConfig) *AutoRenewer {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 24 * time.Hour
	}
	if cfg.Threshold == 0 {
		cfg.Threshold = DefaultRenewalThreshold
	}
	return &AutoRenewer{cfg: cfg}
}

// Start begins the auto-renewal loop. It blocks until the context is cancelled.
func (ar *AutoRenewer) Start(ctx context.Context) {
	ar.tryRenew(ctx)

	ticker := time.NewTicker(ar.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ar.tryRenew(ctx)
		}
	}
}

func (ar *AutoRenewer) tryRenew(ctx context.Context) {
	if !ar.mu.TryLock() {
		return
	}
	defer ar.mu.Unlock()

	action, err := RenewOrReenroll(ctx, ar.cfg.RenewConfig, ar.cfg.EnrollConfig, ar.cfg.Threshold)
	if err != nil {
		if ar.cfg.OnError != nil {
			ar.cfg.OnError(err)
		}
		return
	}
	if action != "none" && ar.cfg.OnRenew != nil {
		ar.cfg.OnRenew(action)
	}
}
