variable "name" {
  description = "Name prefix for the secrets."
  type        = string
}

variable "domain" {
  description = "Certificate common name."
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 zone used for the DNS-01 challenge."
  type        = string
}

variable "region" {
  description = "AWS region passed to the lego Route53 DNS provider."
  type        = string
}

variable "acme_email" {
  description = "ACME account contact email."
  type        = string
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
