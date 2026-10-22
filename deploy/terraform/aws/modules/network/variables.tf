variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "region" {
  description = "AWS region (used for VPC endpoint service names)."
  type        = string
}

variable "cidr_block" {
  description = "VPC CIDR. Subnets are /20 slices of it."
  type        = string
  default     = "10.0.0.0/16"
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
