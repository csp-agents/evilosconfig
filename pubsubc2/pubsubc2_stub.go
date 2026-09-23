//go:build !pubsub

package pubsubc2

import (
	"context"
	"fmt"
)

// Client is a no-op stub when compiled without pubsub support.
type Client struct{}

// Available reports whether pubsub support was compiled in.
func Available() bool { return false }

// Start returns an error when pubsub is not compiled in.
func Start(ctx context.Context) (*Client, error) {
	return nil, fmt.Errorf("pubsub: not compiled with -tags pubsub")
}

// Stop is a no-op.
func (c *Client) Stop() {}
