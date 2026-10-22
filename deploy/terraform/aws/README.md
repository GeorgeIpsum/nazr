# nazr on AWS (Terraform)

Runs the nazr image on ECS Fargate behind an internet-facing **Network Load Balancer in TCP passthrough mode**, with RDS PostgreSQL 17, optional ElastiCache Redis, and a Let's Encrypt certificate issued through Route53 DNS-01 and stored in Secrets Manager.

The step-by-step guide (prerequisites, first key, renewal, costs) is [docs/deploy-aws.md](../../../docs/deploy-aws.md).

```
client ──TCP 443/80──▶ NLB (public subnets, cross-zone, client IP preserved)
                         │
                         ▼
             ECS Fargate tasks "nazr" (private subnets)
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
| `image_owner` | `GeorgeIpsum` | GHCR owner for the default image |
| `image` | `""` → `ghcr.io/<image_owner>/nazr:latest` | Full reference used verbatim; a bare tag (no `/`) creates ECR repo `nazr` and uses `<account>.dkr.ecr.<region>.amazonaws.com/nazr:<tag>` |
| `cpu_architecture` | `ARM64` | `ARM64` (Graviton, cheaper) or `X86_64`; the image must exist for it |
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
| `public_subnet_ids` | `[]` | With `vpc_id`: ≥ 1 public subnet for the NLB |
| `enable_efs_data` | `false` | Persistent `/data` on EFS (see below) |
| `health_check_protocol` | `HTTPS` | `HTTPS` (`GET /healthz` on 443, expects 200) or `TCP` |
| `event_retention` | `2160h` | `NAZR_EVENT_RETENTION` |
| `cors_origins` | `*` | `NAZR_CORS_ORIGINS` |
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

Environment: `NAZR_TLS_MODE=terminate`, `NAZR_DATA_DIR=/data`, `NAZR_EVENT_RETENTION`, `NAZR_CORS_ORIGINS`, `NAZR_METRICS_ADDR=127.0.0.1:9090` (metrics stay inside the task), `NAZR_REDIS_URL` when Redis is enabled (it carries no credential), then `extra_env`.

Secrets (Secrets Manager `valueFrom`): `NAZR_DATABASE_URL`, `NAZR_TLS_CERT_PEM`, `NAZR_TLS_KEY_PEM`, `NAZR_ADMIN_TOKEN`, and `NAZR_MAXMIND_ACCOUNT_ID` / `NAZR_MAXMIND_LICENSE_KEY` (keys of one JSON secret) when MaxMind is configured. `NAZR_ACME_*` is not used: Terraform owns the certificate.

## Security groups and why the task group is open

The NLB is a pure TCP passthrough with `preserve_client_ip = true` on both target groups. nazr has to see the real client address and the raw TLS ClientHello, so nothing in front of it may proxy or terminate the connection. The consequence is that packets reach the task with the **client's** source IP, not the NLB's:

- **NLB SG**: ingress 443 and 80 from `0.0.0.0/0` and `::/0`; egress 443 and 80 only to the task SG (traffic and health checks).
- **Task SG**: ingress 443 and 80 from `0.0.0.0/0` and `::/0`. Restricting it to the VPC CIDR or to the NLB SG would drop every real client, because their source addresses are on the internet. The tasks still are not directly reachable: they run in private subnets with `assign_public_ip = false`, so the only route in is through the NLB listeners. Egress is open (RDS, Redis, EFS, VPC endpoints, and MaxMind/list downloads via NAT).
- **Database SG**: 5432 (and 6379 with Redis) only from the task SG.
- **EFS SG** (with `enable_efs_data`): 2049 only from the task SG.
- **Endpoint SG** (network module): 443 from the VPC CIDR.

## `/data`

The image runs as uid/gid 65532 and its `/data` is owned by that user. An empty task volume mounted at `/data` would be owned by root and every download would fail, so by default **no volume is mounted**: `/data` is the container's own writable layer on the task's 21 GiB ephemeral storage. It is lost when a task stops, so each new task downloads MaxMind and the IP lists again.

`enable_efs_data = true` mounts an EFS access point instead (posix user 65532:65532, root directory created 65532:65532 `0755`, TLS in transit, IAM-authorized), with a mount target in each private subnet. Downloads then survive restarts and are shared across tasks, which keeps you under MaxMind's daily download limit. See [docs/deploy-aws.md](../../../docs/deploy-aws.md#data-persistence-and-the-maxmind-limit).

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
