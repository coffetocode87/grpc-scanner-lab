# gRPC scanner lab (isolated)

This is a deliberately vulnerable, disposable lab for validating gRPC discovery and scanner coverage. Run it only on a machine/network you control. Keep the ports private and firewall-restricted.

## What it contains

- TLS gRPC service on `localhost:50051`, with server reflection and downloadable `.proto` description.
- HTTP companion on `localhost:8080`, exposing OpenAPI at `/openapi.json` and an intentionally injectable `/api/users?name=` control endpoint.
- Deliberate gRPC access-control flaws: `GetTask` permits unauthenticated access to predictable task IDs and `ListTasks` is unauthenticated.
- Demo credentials: `admin` / `admin123`.

The gRPC flaws are primarily for manual/API-aware testing. Scanner detection depends on gRPC protocol support and access-control testing configuration. The SQL injection route provides a conventional HTTP DAST control. No named finding can be guaranteed across scanner builds, license levels, and profiles.

## Start

Requirements: Docker Engine with Compose. The Compose project is named `grpc-dast-lab`, and its host ports are **8101 (HTTP)** and **50053 (gRPC TLS)**. These do not conflict with the ports in the Docker list you provided.

```sh
docker compose -p grpc-dast-lab up --build -d
docker compose -p grpc-dast-lab ps
```

By default both ports bind to `127.0.0.1` on the VPS, so no external host can reach the deliberately vulnerable lab. The container creates a short-lived self-signed certificate. Stop/remove with `docker compose -p grpc-dast-lab down --volumes`.

To let a remote scanner reach it, first permit ports 8101 and 50053 only from the scanner's source IP (or a private VPN), then start with a public bind and a DNS hostname that resolves to this VPS:

```sh
LAB_BIND_IP=0.0.0.0 LAB_HOSTNAME=grpc-lab.example.net docker compose -p grpc-dast-lab up --build -d
```

Set `LAB_HOSTNAME` to the actual hostname used by the scanner. Recreate the container after changing it so the generated certificate SAN matches. The certificate is self-signed; configure the scanner to trust it or use a lab-issued certificate. Do not expose this intentionally vulnerable service to the whole Internet.

## Manual checks

```sh
curl http://localhost:8101/health
curl http://localhost:8101/openapi.json
grpcurl -insecure localhost:50053 list
grpcurl -insecure -d '{"task_id":1}' localhost:50053 invicti.v1.TaskService/GetTask
curl 'http://localhost:8101/api/users?name=%27%20OR%201%3D1--'
```

Unauthenticated `GetTask` should disclose the seeded Alice record. The SQLi tautology should return multiple rows.

## Scanner setup

### Invicti

1. Add `http://<reachable-lab-host>:8101` as a target and ensure the scan worker can reach it. The default bind is loopback-only; use the restricted remote-bind procedure above for remote/cloud scanning.
2. Import `/openapi.json` (or the included OpenAPI description) and run a full scan, not an import-only scan.
3. Add the gRPC endpoint `https://<reachable-lab-host>:50053` and import `proto/invicti.proto` if the product UI offers gRPC/proto import. Ensure certificate trust and hostname are configured.
4. Verify individual request/response evidence. HTTP 400 with `grpc-status: 13` and `Content-Type is missing from the request` is a malformed protocol probe, not proof a valid RPC is broken.

### Burp Suite

1. Scope only the lab host/ports. Use a Burp version or extension that can preserve/edit HTTP/2 gRPC traffic; normal site crawling may not discover or mutate protobuf calls.
2. Send valid calls through Burp Proxy, then inspect them in HTTP history/Repeater. Use the proto with a gRPC-capable client/extension and scan captured calls where supported.
3. For an automated baseline, scan the HTTP companion and its OpenAPI definition. Judge by finding evidence rather than the count of 400s.

## Diagnosis of the attached Invicti logs

Both logs are Invicti engine 26.9.0 runs on October 4, 2026. They contain 243,211 and 259,462 lines. Both report `api_detected` with `type: grpc`, successful proto import, and four RPCs: `AuthService/Login`, `TaskService/CreateTask`, `TaskService/GetTask`, and `TaskService/ListTasks`.

Each has roughly 577 HTTP/2 400 responses with gRPC status 13 and `Content-Type is missing from the request`. The logs show non-gRPC checks sent to RPC paths using form/XML content types; those probes are expected to fail protocol validation. In other words, the 400s show protocol-incompatible scanner probes, while the API itself was detected and its methods imported. Both scans completed; the first used `api-full-scan.profile`, the second `Default`. The second also crawled an HTML landing page that linked an OpenAPI URL. The logs alone do not prove which findings were reported—inspect the scan report and valid RPC response evidence.

Expected evidence: the sitemap includes four methods; reflection lists services; valid RPC calls return gRPC response/trailers; `GetTask(1)` returns another user's record without auth; SQLi tautology returns several rows. A scanner may still fail to automatically report gRPC authorization flaws.
