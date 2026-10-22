# nazr on AWS (Terraform)

Runs the nazr image on ECS Fargate behind an internet-facing **Network Load Balancer in TCP passthrough mode**, with RDS PostgreSQL 17, optional ElastiCache Redis, and a Let's Encrypt certificate issued through Route53 DNS-01 and stored in Secrets Manager.

The step-by-step guide (prerequisites, first key, renewal, costs) is [docs/deploy-aws.md](../../../docs/deploy-aws.md).

```
client ──TCP 443/80──▶ NLB (public subnets, cross-zone, client IP preserved)
                         │
                         ▼
             ECS Fargate tasks "nazr" (private subnets, container ports 8443/8080)
             terminate TLS themselves (JA4 + HTTP/2 fingerprints)
                 │                 │
                 ▼                 ▼
          RDS Postgres 17     ElastiCache Redis (optional)
```

## Layout

| Path | Contents |
| --- | --- |
| `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf` | Root module; configures the `aws` (from `region`) and `acme` (from `acme_server_url`) providers |
| `modules/network` | VPC `10.0.0.0/16`, 2 public + 2 private subnets in two AZs, one NAT gateway, interface endpoints for ECR (api, dkr), Secrets Manager and CloudWatch Logs, S3 gateway endpoint. Skipped when `vpc_id` is set |
| `modules/database` | RDS PostgreSQL 17, a secret holding the composed `NAZR_DATABASE_URL` (`sslmode=require`), optional single-node ElastiCache Redis, one security group open only to the task security group |
| `modules/cert` | ACME account + certificate (Route53 DNS-01, `min_days_remaining = 30`), stored as two secrets (chain, key). Skipped when `certificate_pem` is set; the root then stores the given PEMs in the same two-secret shape |
| `modules/service` | Optional ECR repository, ECS cluster, CloudWatch log group (30 days), IAM roles, Fargate task definition, service, NLB with TCP 443/80 listeners, Route53 `A` alias, security groups, optional EFS for `/data` |
| `examples/minimal` | Everything created by the module |
| `examples/existing-vpc` | Uses your VPC and subnets, with Redis enabled |

## Inputs

| Name | Default | Description |
| --- | --- | --- |
| `domain` | required | Hostname served, inside `route53_zone_id` |
| `route53_zone_id` | required | Hosted zone for the alias and DNS-01 |
| `region` | required | AWS region |
| `image_owner` | `georgeipsum` | GHCR owner for the default image `ghcr.io/georgeipsum/nazr`; must be lowercase. The package exists after the first `v*` release and starts private on GHCR (make it public once) |
| `image` | `""` → `ghcr.io/<image_owner>/nazr:latest` | Full reference used verbatim; a bare tag (no `/`) creates ECR repo `nazr` and uses `<account>.dkr.ecr.<region>.amazonaws.com/nazr:<tag>` |
| `cpu_architecture` | `ARM64` | `ARM64` (Graviton, cheaper) or `X86_64`; see the platform note below |
| `desired_count` | `2` | ECS tasks |
| `cpu` / `memory` | `512` / `1024` | Fargate task size |
| `db_instance_class` | `db.t4g.micro` | RDS class |
| `db_allocated_storage` | `20` | GiB |
| `enable_redis` | `false` | Single-node ElastiCache Redis, sets `NAZR_REDIS_URL` |
| `redis_node_type` | `cache.t4g.micro` | |
| `maxmind_account_id` | `""` | GeoLite2 account; empty disables GeoLite2 |
| `maxmind_license_key` | `""` (sensitive) | Set together with the account ID |
| `admin_token` | `""` (sensitive) | `NAZR_ADMIN_TOKEN`; empty generates a 48-character token |
| `certificate_pem` / `private_key_pem` | `""` (sensitive) | Bring your own certificate (full chain) and skip ACME |
| `acme_email` | `""` | ACME contact; required unless a PEM is given |
| `acme_server_url` | Let's Encrypt production | Use the staging directory while testing |
| `vpc_id` | `null` | Existing VPC; skips the network module |
| `private_subnet_ids` | `[]` | With `vpc_id`: ≥ 2 subnets in two AZs, outbound via NAT |
| `public_subnet_ids` | `[]` | With `vpc_id`: ≥ 2 public subnets in two AZs for the NLB |
| `enable_efs_data` | `false` | Persistent `/data` on EFS (see below) |
| `data_dir` | `""` → `/data` with EFS, else `/tmp/nazr` | `NAZR_DATA_DIR` override |
| `health_check_protocol` | `HTTPS` | `HTTPS` (`GET /healthz` on container port 8443, expects 200) or `TCP` |
| `event_retention` | `2160h` | `NAZR_EVENT_RETENTION` |
| `cors_origins` | `*` | `NAZR_CORS_ORIGINS` |
| `task_ingress_cidrs` | `[]` | Empty: tasks admit 8443/8080 from the NLB security group. Non-empty: CIDR rules instead (fallback `["0.0.0.0/0", "::/0"]`) |
| `wait_for_steady_state` | `true` | `apply` waits (up to 20 min) for healthy tasks and fails on a crash-looping deployment |
| `extra_env` | `{}` | Extra plain `NAZR_*` environment; overrides module values. No secrets |
| `tags` | `{}` | Added to every resource, plus `app = "nazr"` |

## Outputs

| Name | Description |
| --- | --- |
| `api_url` | `https://<domain>` |
| `nlb_dns_name` | NLB DNS name |
| `ecs_cluster_name` / `ecs_service_name` | For `aws ecs` commands |
| `ecr_repository_url` | Set only when `image` is a bare tag |
| `admin_token_secret_arn` | Secret holding the admin token (the value is never output) |
| `first_key_command` | `aws ecs execute-command ... /nazr keys create --label first` for the first running task |

## Container configuration

Environment: `NAZR_TLS_MODE=terminate`, `NAZR_DATA_DIR` (`/tmp/nazr`, or `/data` with EFS), `NAZR_EVENT_RETENTION`, `NAZR_CORS_ORIGINS`, `NAZR_METRICS_ADDR=127.0.0.1:9090` (metrics stay inside the task), `NAZR_REDIS_URL` when Redis is enabled (it carries no credential), then `extra_env`.

Secrets (Secrets Manager `valueFrom`): `NAZR_DATABASE_URL`, `NAZR_TLS_CERT_PEM`, `NAZR_TLS_KEY_PEM`, `NAZR_ADMIN_TOKEN`, and `NAZR_MAXMIND_ACCOUNT_ID` / `NAZR_MAXMIND_LICENSE_KEY` (keys of one JSON secret) when MaxMind is configured. `NAZR_ACME_*` is not used: Terraform owns the certificate.

## Ports

| Where | HTTPS | HTTP (308 redirect) |
| --- | --- | --- |
| NLB listener (clients) | TCP 443 | TCP 80 |
| Target group / container (`NAZR_LISTEN_ADDR`, `NAZR_HTTP_ADDR`) | 8443 | 8080 |
| Health check | 8443 (`/healthz` or TCP) | 8443 |

The image runs as uid 65532, and Fargate does not guarantee that a non-root process may bind ports below 1024, so the container listens on unprivileged ports and the NLB maps 443→8443 and 80→8080. The redirect uses the request's `Host` without a port, so clients are sent to `https://<domain>` on 443.

## Security groups and client IP preservation

The NLB is a pure TCP passthrough with `preserve_client_ip = true` on both target groups. nazr has to see the real client address and the raw TLS ClientHello, so nothing in front of it may proxy or terminate the connection. The consequence is that packets reach the task with the **client's** source IP, not the NLB's:

- **NLB SG**: ingress 443 and 80 from `0.0.0.0/0` and `::/0`; egress 8443 and 8080 only to the task SG (traffic and health checks).
- **Task SG**: ingress 8443 and 8080 from the NLB SG (`referenced_security_group_id`). A VPC-CIDR rule would block real clients, whose source addresses are on the internet, but NLB security groups are evaluated at the NLB's ENIs, so targets can reference the NLB SG regardless of client IP preservation ([AWS docs](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html)). If that does not hold in an account or region, `wait_for_steady_state` surfaces it on the first apply (targets never turn healthy); set `task_ingress_cidrs = ["0.0.0.0/0", "::/0"]` to use CIDR rules instead, which is safe because the tasks run in private subnets with `assign_public_ip = false`: the only route in is through the NLB listeners. Egress is open (RDS, Redis, EFS, VPC endpoints, and MaxMind/list downloads via NAT).
- **Database SG**: 5432 (and 6379 with Redis) only from the task SG.
- **EFS SG** (with `enable_efs_data`): 2049 only from the task SG.
- **Endpoint SG** (network module): 443 from the VPC CIDR.

## Data directory

The image runs as uid/gid 65532. How Fargate initialises the image's `VOLUME /data` (and who owns it) is not something the module relies on: a root-owned mount there would make every MaxMind and IP-list download fail, the same bug the compose stack once had. So by default **nothing is mounted and `NAZR_DATA_DIR=/tmp/nazr`**. Distroless `/tmp` is mode 1777 in the container's writable layer, so the nonroot process can create the directory itself. The writable layer lives on the task's 21 GiB ephemeral storage and is lost when the task stops: each new task downloads MaxMind and the IP lists again, which counts against MaxMind's daily download limit (30 per account at the time of writing).

`enable_efs_data = true` mounts an EFS access point at `/data` instead (posix user 65532:65532, root directory created 65532:65532 `0755`, TLS in transit, IAM-authorized), with a mount target in each private subnet, and `NAZR_DATA_DIR` becomes `/data`. Downloads then survive restarts and are shared across tasks. `data_dir` overrides either default. See [docs/deploy-aws.md](../../../docs/deploy-aws.md#data-persistence-and-the-maxmind-limit).

## Operational notes

- **Certificate renewal**: `terraform apply` renews the ACME certificate within 30 days of expiry and writes new secret versions, but running tasks keep the certificate they started with. Roll them with `aws ecs update-service --cluster <cluster> --service <service> --force-new-deployment`.
- **Apply time**: with `wait_for_steady_state = true` (default) `terraform apply` waits until the new tasks pass health checks, up to the provider's 20-minute timeout, and fails if they never do. Expect applies that touch the service to take several minutes.
- **Platform**: tasks default to ARM64 (Graviton). That needs the multi-arch (`linux/amd64` + `linux/arm64`) image the release workflow publishes; for an amd64-only image set `cpu_architecture = "X86_64"`.

## Development checks

```bash
for d in deploy/terraform/aws deploy/terraform/aws/examples/minimal deploy/terraform/aws/examples/existing-vpc; do
  terraform -chdir=$d init -backend=false -input=false >/dev/null && terraform -chdir=$d validate
done
terraform -chdir=deploy/terraform/aws fmt -check -recursive
tflint --chdir=deploy/terraform/aws --init
tflint --chdir=deploy/terraform/aws --recursive --config "$PWD/deploy/terraform/aws/.tflint.hcl"
```

Pass `--config` with an absolute path: in `--recursive` mode tflint otherwise looks for `.tflint.hcl` in each module directory and silently skips the AWS ruleset there.
