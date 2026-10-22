data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  # Short, deterministic and unique per domain, so two deployments can share
  # an account. Fits the 32-character NLB and target group name limits.
  name = "nazr-${substr(sha1(var.domain), 0, 6)}"
  tags = merge(var.tags, { app = "nazr" })

  create_network     = var.vpc_id == null
  vpc_id             = local.create_network ? module.network[0].vpc_id : var.vpc_id
  public_subnet_ids  = local.create_network ? module.network[0].public_subnet_ids : var.public_subnet_ids
  private_subnet_ids = local.create_network ? module.network[0].private_subnet_ids : var.private_subnet_ids

  # Secret ARNs are read from the *_version resources (their secret_id is the
  # secret ARN) so the service waits until each secret has a value.
  use_acme       = var.certificate_pem == ""
  cert_secret_id = local.use_acme ? module.cert[0].cert_secret_arn : aws_secretsmanager_secret_version.tls_cert[0].secret_id
  key_secret_id  = local.use_acme ? module.cert[0].key_secret_arn : aws_secretsmanager_secret_version.tls_key[0].secret_id

  image = var.image == "" ? "ghcr.io/${var.image_owner}/nazr:latest" : var.image
}

module "network" {
  source = "./modules/network"
  count  = local.create_network ? 1 : 0

  name   = local.name
  region = var.region
  tags   = local.tags
}

module "cert" {
  source = "./modules/cert"
  count  = local.use_acme ? 1 : 0

  name            = local.name
  domain          = var.domain
  route53_zone_id = var.route53_zone_id
  region          = var.region
  acme_email      = var.acme_email
  tags            = local.tags
}

# Caller-supplied certificate: stored the same way the cert module stores the
# ACME one, so the service only ever sees two secret ARNs.
resource "aws_secretsmanager_secret" "tls_cert" {
  count = local.use_acme ? 0 : 1

  name_prefix = "${local.name}/tls-cert-"
  description = "nazr TLS certificate chain (PEM) for ${var.domain}"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "tls_cert" {
  count = local.use_acme ? 0 : 1

  secret_id     = aws_secretsmanager_secret.tls_cert[0].id
  secret_string = var.certificate_pem
}

resource "aws_secretsmanager_secret" "tls_key" {
  count = local.use_acme ? 0 : 1

  name_prefix = "${local.name}/tls-key-"
  description = "nazr TLS private key (PEM) for ${var.domain}"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "tls_key" {
  count = local.use_acme ? 0 : 1

  secret_id     = aws_secretsmanager_secret.tls_key[0].id
  secret_string = var.private_key_pem
}

resource "random_password" "admin_token" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "admin_token" {
  name_prefix = "${local.name}/admin-token-"
  description = "nazr NAZR_ADMIN_TOKEN for ${var.domain}"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "admin_token" {
  secret_id     = aws_secretsmanager_secret.admin_token.id
  secret_string = var.admin_token != "" ? var.admin_token : random_password.admin_token.result
}

# One JSON secret; the task definition picks each key with the
# <arn>:<json-key>:: valueFrom syntax. Created only when MaxMind is configured
# (Secrets Manager rejects empty secret strings).
resource "aws_secretsmanager_secret" "maxmind" {
  count = var.maxmind_account_id != "" ? 1 : 0

  name_prefix = "${local.name}/maxmind-"
  description = "nazr MaxMind GeoLite2 credentials"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "maxmind" {
  count = var.maxmind_account_id != "" ? 1 : 0

  secret_id = aws_secretsmanager_secret.maxmind[0].id
  secret_string = jsonencode({
    account_id  = var.maxmind_account_id
    license_key = var.maxmind_license_key
  })
}

module "database" {
  source = "./modules/database"

  name                  = local.name
  vpc_id                = local.vpc_id
  subnet_ids            = local.private_subnet_ids
  client_security_group = module.service.task_security_group_id
  instance_class        = var.db_instance_class
  allocated_storage     = var.db_allocated_storage
  enable_redis          = var.enable_redis
  redis_node_type       = var.redis_node_type
  tags                  = local.tags
}

module "service" {
  source = "./modules/service"

  name               = local.name
  region             = var.region
  account_id         = data.aws_caller_identity.current.account_id
  partition          = data.aws_partition.current.partition
  domain             = var.domain
  route53_zone_id    = var.route53_zone_id
  vpc_id             = local.vpc_id
  public_subnet_ids  = local.public_subnet_ids
  private_subnet_ids = local.private_subnet_ids

  image            = local.image
  cpu_architecture = var.cpu_architecture
  desired_count    = var.desired_count
  cpu              = var.cpu
  memory           = var.memory

  database_url_secret_arn = module.database.database_url_secret_arn
  tls_cert_secret_arn     = local.cert_secret_id
  tls_key_secret_arn      = local.key_secret_id
  admin_token_secret_arn  = aws_secretsmanager_secret_version.admin_token.secret_id
  maxmind_secret_arn      = var.maxmind_account_id != "" ? aws_secretsmanager_secret_version.maxmind[0].secret_id : ""
  redis_url               = module.database.redis_url

  event_retention       = var.event_retention
  cors_origins          = var.cors_origins
  extra_env             = var.extra_env
  enable_efs_data       = var.enable_efs_data
  data_dir              = var.data_dir
  health_check_protocol = var.health_check_protocol
  tags                  = local.tags
}
