variable "name" {
  description = "Name prefix for resources (also the ECS cluster and service name)."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "account_id" {
  description = "AWS account ID (for the ECR image URI)."
  type        = string
}

variable "partition" {
  description = "AWS partition (aws, aws-cn, aws-us-gov)."
  type        = string
  default     = "aws"
}

variable "domain" {
  description = "Hostname for the Route53 alias."
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 zone for the alias record."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "public_subnet_ids" {
  description = "Subnets for the internet-facing NLB."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Subnets for the tasks (and EFS mount targets)."
  type        = list(string)
}

variable "image" {
  description = "Full image reference, or a bare tag to use with a module-created ECR repository named nazr."
  type        = string
}

variable "cpu_architecture" {
  description = "Fargate CPU architecture (ARM64 or X86_64)."
  type        = string
  default     = "ARM64"
}

variable "desired_count" {
  description = "Number of tasks."
  type        = number
  default     = 2
}

variable "cpu" {
  description = "Task CPU units."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Task memory (MiB)."
  type        = number
  default     = 1024
}

variable "database_url_secret_arn" {
  description = "Secret ARN for NAZR_DATABASE_URL."
  type        = string
}

variable "tls_cert_secret_arn" {
  description = "Secret ARN for NAZR_TLS_CERT_PEM."
  type        = string
}

variable "tls_key_secret_arn" {
  description = "Secret ARN for NAZR_TLS_KEY_PEM."
  type        = string
}

variable "admin_token_secret_arn" {
  description = "Secret ARN for NAZR_ADMIN_TOKEN."
  type        = string
}

variable "maxmind_secret_arn" {
  description = "JSON secret ARN with account_id and license_key keys; empty disables MaxMind."
  type        = string
  default     = ""
}

variable "redis_url" {
  description = "NAZR_REDIS_URL; empty disables Redis. Carries no credential, so it is plain environment."
  type        = string
  default     = ""
}

variable "event_retention" {
  description = "NAZR_EVENT_RETENTION."
  type        = string
  default     = "2160h"
}

variable "cors_origins" {
  description = "NAZR_CORS_ORIGINS."
  type        = string
  default     = "*"
}

variable "extra_env" {
  description = "Extra plain environment variables (override module values)."
  type        = map(string)
  default     = {}
}

variable "enable_efs_data" {
  description = "Mount an EFS access point at /data."
  type        = bool
  default     = false
}

variable "data_dir" {
  description = "NAZR_DATA_DIR. Empty means /data when enable_efs_data is true (EFS access point owned by 65532), otherwise /tmp/nazr on the task's ephemeral storage."
  type        = string
  default     = ""
}

variable "health_check_protocol" {
  description = "Target group health check protocol: HTTPS or TCP."
  type        = string
  default     = "HTTPS"
}

variable "wait_for_steady_state" {
  description = "Make terraform apply wait (up to 20 minutes) for the service to reach a steady state, failing on a broken deployment."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
