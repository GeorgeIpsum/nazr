variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "domain" {
  description = "Hostname the API is served on, e.g. nazr.example.com."
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 hosted zone that contains var.domain."
  type        = string
}

variable "acme_email" {
  description = "Contact email for the Let's Encrypt account."
  type        = string
}

variable "maxmind_account_id" {
  description = "MaxMind account ID for GeoLite2 downloads (empty disables them)."
  type        = string
  default     = ""
}

variable "maxmind_license_key" {
  description = "MaxMind license key."
  type        = string
  default     = ""
  sensitive   = true
}

variable "vpc_id" {
  description = "Existing VPC to deploy into."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets (with a NAT route) for ECS tasks, RDS and Redis; at least two AZs."
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnets for the internet-facing NLB; at least two AZs."
  type        = list(string)
}
