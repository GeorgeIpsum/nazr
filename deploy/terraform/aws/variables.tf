variable "domain" {
  description = "Hostname the API is served on (e.g. nazr.example.com). Must live in var.route53_zone_id."
  type        = string
}

variable "route53_zone_id" {
  description = "ID of the Route53 hosted zone for var.domain. Used for the A alias and the ACME DNS-01 challenge."
  type        = string
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "image_owner" {
  description = "GHCR owner used to compose the default image (ghcr.io/<owner>/nazr:latest) when var.image is empty. Forks change only this."
  type        = string
  default     = "GeorgeIpsum"
}

variable "image" {
  description = "Container image. A full reference (containing '/') is used verbatim; a bare tag (e.g. \"v1.0.0\") creates an ECR repository named nazr and uses <account>.dkr.ecr.<region>.amazonaws.com/nazr:<tag>. Empty means ghcr.io/<image_owner>/nazr:latest."
  type        = string
  default     = ""
}

variable "cpu_architecture" {
  description = "Fargate CPU architecture: ARM64 (Graviton, about 20% cheaper) or X86_64. The image must be published for it."
  type        = string
  default     = "ARM64"

  validation {
    condition     = contains(["ARM64", "X86_64"], var.cpu_architecture)
    error_message = "cpu_architecture must be ARM64 or X86_64."
  }
}

variable "desired_count" {
  description = "Number of ECS tasks."
  type        = number
  default     = 2
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory (MiB)."
  type        = number
  default     = 1024
}

variable "db_instance_class" {
  description = "RDS instance class for PostgreSQL 17."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage (GiB)."
  type        = number
  default     = 20
}

variable "enable_redis" {
  description = "Create a single-node ElastiCache Redis and set NAZR_REDIS_URL (shared rate limiter and key cache across tasks)."
  type        = bool
  default     = false
}

variable "redis_node_type" {
  description = "ElastiCache node type when enable_redis is true."
  type        = string
  default     = "cache.t4g.micro"
}

variable "maxmind_account_id" {
  description = "MaxMind account ID for GeoLite2 downloads. Empty disables GeoLite2."
  type        = string
  default     = ""
}

variable "maxmind_license_key" {
  description = "MaxMind license key. Required when maxmind_account_id is set."
  type        = string
  default     = ""
  sensitive   = true

  validation {
    condition     = (var.maxmind_account_id == "") == (var.maxmind_license_key == "")
    error_message = "Set both maxmind_account_id and maxmind_license_key, or neither."
  }
}

variable "admin_token" {
  description = "Bearer token for /admin/keys. Empty generates a random 48-character token (read it from the admin_token_secret_arn secret)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "certificate_pem" {
  description = "Optional PEM certificate (full chain). When set, ACME is skipped and this certificate is stored in Secrets Manager instead."
  type        = string
  default     = ""
  sensitive   = true
}

variable "private_key_pem" {
  description = "PEM private key for certificate_pem."
  type        = string
  default     = ""
  sensitive   = true

  validation {
    condition     = (var.certificate_pem == "") == (var.private_key_pem == "")
    error_message = "Set both certificate_pem and private_key_pem, or neither."
  }
}

variable "acme_email" {
  description = "Contact email for the ACME account. Required unless certificate_pem is set."
  type        = string
  default     = ""

  validation {
    condition     = var.acme_email != "" || var.certificate_pem != ""
    error_message = "acme_email is required when certificate_pem is not provided."
  }
}

variable "acme_server_url" {
  description = "ACME directory URL. Use https://acme-staging-v02.api.letsencrypt.org/directory for testing."
  type        = string
  default     = "https://acme-v02.api.letsencrypt.org/directory"
}

variable "vpc_id" {
  description = "Existing VPC ID. When null, the network module creates a VPC (10.0.0.0/16, two AZs, one NAT gateway)."
  type        = string
  default     = null
}

variable "private_subnet_ids" {
  description = "Private subnets (outbound internet via NAT) for tasks, RDS and Redis, in at least two AZs. Required with vpc_id."
  type        = list(string)
  default     = []

  validation {
    condition     = var.vpc_id == null || length(var.private_subnet_ids) >= 2
    error_message = "private_subnet_ids needs at least two subnets (two AZs) when vpc_id is set."
  }
}

variable "public_subnet_ids" {
  description = "Public subnets for the internet-facing NLB. Required with vpc_id."
  type        = list(string)
  default     = []

  validation {
    condition     = var.vpc_id == null || length(var.public_subnet_ids) >= 1
    error_message = "public_subnet_ids needs at least one subnet when vpc_id is set."
  }
}

variable "enable_efs_data" {
  description = "Mount an EFS access point (uid/gid 65532) at /data so MaxMind and IP-list downloads survive task restarts. Default keeps /data on the task's ephemeral storage."
  type        = bool
  default     = false
}

variable "health_check_protocol" {
  description = "NLB target health check: HTTPS (GET /healthz on 443, expects 200) or TCP (connect to 443)."
  type        = string
  default     = "HTTPS"

  validation {
    condition     = contains(["HTTPS", "TCP"], var.health_check_protocol)
    error_message = "health_check_protocol must be HTTPS or TCP."
  }
}

variable "event_retention" {
  description = "NAZR_EVENT_RETENTION: events older than this are pruned (Go duration, 0 keeps forever)."
  type        = string
  default     = "2160h"
}

variable "cors_origins" {
  description = "NAZR_CORS_ORIGINS: comma-separated global CORS origins."
  type        = string
  default     = "*"
}

variable "extra_env" {
  description = "Extra plain environment variables for the container (e.g. { NAZR_LOG_LEVEL = \"debug\" }). Overrides the module's own values on conflict. Do not put secrets here."
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Tags added to every resource (app = \"nazr\" is always added)."
  type        = map(string)
  default     = {}
}
