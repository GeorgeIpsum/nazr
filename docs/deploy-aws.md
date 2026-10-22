# Deploying on AWS with Terraform

The Terraform module in `deploy/terraform/aws` runs nazr on ECS Fargate behind a Network Load Balancer, with RDS PostgreSQL 17, optional ElastiCache Redis, and a Let's Encrypt certificate it issues and renews itself. The module reference (inputs, outputs, security groups) is [deploy/terraform/aws/README.md](../deploy/terraform/aws/README.md).

## Why an NLB in TCP passthrough mode

nazr fingerprints the TLS ClientHello (JA4) and the HTTP/2 connection preface, and those only exist on the connection the client opened. The module therefore uses an NLB with plain TCP listeners on 443 and 80, `preserve_client_ip = true`, and `NAZR_TLS_MODE=terminate`: the task terminates TLS itself and sees the client's real address. The NLB forwards 443 to container port 8443 and 80 to 8080, because the image runs as a non-root user (uid 65532) and Fargate does not guarantee it may bind ports below 1024.

**Do not put an ALB, CloudFront, API Gateway or a TLS listener on the NLB in front of it.** Any of these terminates TLS and replaces the client's handshake with its own, so every request would carry the proxy's fingerprint (or none), and the client IP would become the proxy's.

## Prerequisites

- Terraform 1.9 or newer and AWS credentials with rights to create VPC, ECS, RDS, ElastiCache, ELB, IAM, Route53 records and Secrets Manager secrets.
- A public **Route53 hosted zone** for the domain (or a parent of it). The module adds an `A` alias for `domain` and uses the zone for the ACME DNS-01 challenge.
- An **image** the tasks can pull:
  - default `ghcr.io/georgeipsum/nazr:latest` (forks set `image_owner`, lowercase: OCI references reject uppercase), pulled through the NAT gateway. It exists only after the first `v*` release has run the release workflow, and GHCR creates a new package as **private** on its first push: a maintainer must set it to public once (package settings, "Change visibility"), or the tasks cannot pull it. A fork must publish a release (and make its package public) or use the bare-tag ECR flow below before its first apply;
  - any other full reference via `image`;
  - or a bare tag (`image = "v1.0.0"`): the module creates an ECR repository named `nazr` and points the task at `<account>.dkr.ecr.<region>.amazonaws.com/nazr:v1.0.0`. The repository starts empty and the apply waits for healthy tasks (`wait_for_steady_state`), so create the repository first, push, then apply everything:

    ```bash
    terraform apply -target=module.nazr.module.service.aws_ecr_repository.this   # examples; drop "module.nazr." at the root
    REPO=$(aws ecr describe-repositories --repository-names nazr --query 'repositories[0].repositoryUri' --output text)
    aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
    docker buildx build --platform linux/arm64 -t "$REPO:v1.0.0" --push apps/api
    terraform apply
    ```

  Tasks run on **ARM64 (Graviton)** by default, which is about 20% cheaper per vCPU. This needs the multi-arch (`linux/amd64` + `linux/arm64`) image published by the release workflow; for an amd64-only image set `cpu_architecture = "X86_64"`.
- The AWS CLI with the Session Manager plugin for the first-key command ([install the plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)).
- Optional: a MaxMind account ID and license key for GeoLite2 City/ASN.

## Examples

`examples/minimal` creates everything, including the VPC:

```bash
cd deploy/terraform/aws/examples/minimal
terraform init
terraform apply \
  -var domain=nazr.example.com \
  -var route53_zone_id=Z0123456789ABC \
  -var acme_email=ops@example.com \
  -var maxmind_account_id=123456 -var maxmind_license_key=...
```

`examples/existing-vpc` deploys into your VPC and enables Redis. It additionally takes `vpc_id`, `private_subnet_ids` (at least two AZs, with a NAT route: the module creates no VPC endpoints in this mode) and `public_subnet_ids` (at least two AZs).

Both examples are thin wrappers; the root module itself can also be applied directly with `-var region=...`. State holds the database password, the admin token and the TLS private key, so use an encrypted remote backend (for example S3 with a DynamoDB or S3 lock) for anything real.

## What gets created

- **Network** (unless `vpc_id` is set): VPC `10.0.0.0/16`, two public and two private `/20` subnets in two AZs, one NAT gateway, interface endpoints for ECR API, ECR DKR, Secrets Manager and CloudWatch Logs plus an S3 gateway endpoint, so image pulls from ECR, secret reads and logs stay inside the VPC.
- **Database**: RDS PostgreSQL 17 (`db.t4g.micro`, 20 GiB gp3, encrypted, single-AZ, 7-day backups) in the private subnets. The master password is a random 32-character alphanumeric string; the composed `postgres://nazr:...@host:5432/nazr?sslmode=require` is stored in a Secrets Manager secret and injected as `NAZR_DATABASE_URL`. Migrations run on start (`NAZR_AUTO_MIGRATE` defaults to true). `deletion_protection` is **off** so evaluation stacks can be destroyed; `terraform destroy` takes a final snapshot named `<name>-final`, which you must delete before destroying a re-created stack with the same domain. Turn deletion protection on for production.
- **Redis** (`enable_redis = true`): one `cache.t4g.micro` node, Redis 7.1, no replica, plaintext inside the VPC and reachable only from the tasks. nazr uses it for the shared rate limiter and key cache and fails open if it is lost.
- **Service**: ECS cluster and service (`desired_count = 2`, 0.5 vCPU / 1 GiB, rolling deploys at 50–200% with circuit-breaker rollback; `apply` waits for a steady state, up to 20 minutes, and fails if the tasks never get healthy; set `wait_for_steady_state = false` to return immediately), Fargate tasks in the private subnets without public IPs, CloudWatch log group `/ecs/<name>` (30 days), NLB with cross-zone load balancing, TCP 443 and TCP 80 listeners to IP target groups on container ports 8443 and 8080, and a Route53 alias. `<name>` is `nazr-` plus six hex characters derived from the domain, so several deployments can share an account.
- **Health checks**: the NLB probes `GET /healthz` over HTTPS on container port 8443 and expects 200 (`health_check_protocol = "HTTPS"`; the NLB does not validate the certificate). `TCP` only checks that 8443 accepts connections. Both target groups probe 8443, since the HTTP port only answers with a redirect.

## Certificates

With no `certificate_pem`, the `cert` module registers an ACME account (`acme_server_url`, Let's Encrypt production by default) and requests a certificate for `domain` with a Route53 DNS-01 challenge. Issuance needs no open ports. The challenge is run by the lego Route53 provider using the AWS credentials of the machine running Terraform (environment, profile or SSO), not the `aws` provider configuration, so both must point at the account owning the zone. The chain (`certificate_pem` + `issuer_pem`) and the key go into two secrets that the tasks read as `NAZR_TLS_CERT_PEM` and `NAZR_TLS_KEY_PEM`.

While testing, use `acme_server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"` to avoid Let's Encrypt rate limits (browsers will not trust the staging certificate).

**Renewal** happens on `terraform apply`: when the certificate has fewer than 30 days left (`min_days_remaining = 30`), the apply renews it and writes new secret versions. Running tasks keep the certificate they started with, so roll them afterwards:

```bash
aws ecs update-service --cluster "$(terraform output -raw ecs_cluster_name)" \
  --service "$(terraform output -raw ecs_service_name)" --force-new-deployment
```

Let's Encrypt certificates last 90 days, so schedule an apply (CI or a cron job) at least monthly.

To bring your own certificate, set `certificate_pem` (full chain) and `private_key_pem`; ACME is skipped and the module stores them in the same two secrets.

## Creating the first API key

The tasks run with ECS Exec enabled. The `first_key_command` output runs `nazr keys create` in the first running task:

```bash
eval "$(terraform output -raw first_key_command)"
```

which expands to:

```bash
aws ecs execute-command --region <region> --cluster <cluster> \
  --task $(aws ecs list-tasks --region <region> --cluster <cluster> --service-name <service> \
           --desired-status RUNNING --query 'taskArns[0]' --output text) \
  --container nazr --interactive --command "/nazr keys create --label first"
```

The image is distroless and has no shell, but ECS Exec runs the given command directly, which works for the static `/nazr` binary; `--interactive` is required by the CLI even for a single command. The command inherits the task's environment (including `NAZR_DATABASE_URL`). To pick a specific task, list them with `aws ecs list-tasks --cluster <cluster> --service-name <service>`. Further keys can be managed through `/admin/keys` with the admin token:

```bash
aws secretsmanager get-secret-value --secret-id "$(terraform output -raw admin_token_secret_arn)" \
  --query SecretString --output text
```

## Security groups and client IPs

Because the NLB preserves client IPs, packets arrive at the task from the client's internet address, so a VPC-CIDR rule on the task group would block real clients. NLB security groups are evaluated at the NLB's network interfaces, though, so targets can admit traffic by referencing the NLB's security group regardless of client IP preservation ([NLB security groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html)). The task group therefore allows 8443 and 8080 only from the NLB group (traffic and health checks). If that misbehaves in your account or region, the first apply shows it: `wait_for_steady_state` fails because the targets never turn healthy. The fallback is `task_ingress_cidrs = ["0.0.0.0/0", "::/0"]`, which replaces the reference with CIDR rules; that is still safe because the tasks are in private subnets with no public IP, so the only way in is through the NLB. The NLB group allows 443/80 from anywhere and forwards only 8443/8080 to the task group; the database, Redis and EFS groups accept connections only from the task group.

## Data persistence and the MaxMind limit

The data directory holds the downloaded MaxMind databases and IP lists. The image runs as uid/gid 65532, and the module does not depend on how Fargate initialises the image's `VOLUME /data`: if it ended up as a root-owned mount, the nonroot process could not write it and every download would fail. So:

- **Default (`enable_efs_data = false`)**: nothing is mounted and `NAZR_DATA_DIR=/tmp/nazr`. Distroless `/tmp` is mode 1777 in the container's writable layer, so nazr creates the directory itself regardless of volume semantics. It sits on the task's 21 GiB ephemeral storage, ready to use and free, but is **per task and lost when the task stops**. Every new task (deploys, scaling, replacements) downloads everything again. MaxMind allows a limited number of GeoLite2 downloads per account per day (30 at the time of writing), and each task downloads two editions on start, so frequent deploys with several tasks can exhaust it. When the limit is hit, GeoLite2 enrichment is missing on those tasks until the next refresh.
- **`enable_efs_data = true`**: an encrypted EFS file system with an access point that forces uid/gid 65532 and creates its root directory as 65532:65532 `0755`, mounted at `/data` with TLS and IAM authorization; `NAZR_DATA_DIR` becomes `/data`. Downloads persist across restarts and are shared by all tasks, which keeps MaxMind usage low. It costs a little (EFS storage is a few hundred MB) and adds NFS latency to reads of the databases at load time.

`data_dir` overrides the directory in either mode.

Use EFS when you deploy often or run many tasks; the default is fine for a small, stable deployment.

## Metrics and logs

Logs go to CloudWatch Logs `/ecs/<name>` (JSON). Metrics listen on `127.0.0.1:9090` inside the task and are not exposed; set `extra_env = { NAZR_METRICS_ADDR = ":9090" }` and add your own security group rule if you scrape them from the VPC.

## Cost notes

Approximate us-east-1 on-demand prices with the defaults (check the AWS pricing pages; data transfer and request charges are extra):

| Item | Approx. per month |
| --- | --- |
| 2 Fargate tasks, ARM64, 0.5 vCPU / 1 GiB (+1 GiB ephemeral above the free 20) | ~$29 |
| NLB (hourly; LCUs extra) | ~$16 |
| NAT gateway (hourly; $0.045/GB processed extra) | ~$33 |
| 4 interface endpoints × 2 AZs | ~$58 |
| Public IPv4 addresses (NAT + NLB) | ~$11 |
| RDS `db.t4g.micro` + 20 GiB gp3 | ~$14 |
| Secrets Manager (5–6 secrets) | ~$2.5 |
| ElastiCache `cache.t4g.micro` (only with `enable_redis`) | ~$12 |
| EFS (only with `enable_efs_data`, < 1 GiB) | < $1 |

That is roughly $165 per month without Redis. The VPC endpoints and the NAT gateway are about half of it; deploying into an existing VPC that already has a NAT gateway (`examples/existing-vpc`) avoids both. `cpu_architecture = "X86_64"` costs about 25% more for the tasks.

## Teardown

```bash
terraform destroy
```

RDS writes a final snapshot (`<name>-final`); delete it when no longer needed. Secrets go through Secrets Manager's default 30-day recovery window; the module uses name prefixes, so a re-created stack does not collide with them. The ECR repository (when created) must be empty before it can be destroyed.
