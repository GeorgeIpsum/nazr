variable "name" {
  description = "Name prefix for resources."
  type        = string
}

variable "vpc_id" {
  description = "VPC for the database security group."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets (two or more AZs) for RDS and ElastiCache."
  type        = list(string)
}

variable "client_security_group" {
  description = "Security group of the ECS tasks; the only allowed source for 5432 and 6379."
  type        = string
}

variable "instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage" {
  description = "RDS allocated storage (GiB)."
  type        = number
  default     = 20
}

variable "enable_redis" {
  description = "Create a single-node ElastiCache Redis cluster."
  type        = bool
  default     = false
}

variable "redis_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.micro"
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}
