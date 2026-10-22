output "database_url_secret_arn" {
  description = "Secrets Manager ARN holding NAZR_DATABASE_URL."
  value       = aws_secretsmanager_secret_version.database_url.secret_id
}

output "redis_url" {
  description = "NAZR_REDIS_URL (redis://host:6379), or empty when Redis is disabled."
  value       = var.enable_redis ? "redis://${aws_elasticache_cluster.this[0].cache_nodes[0].address}:${aws_elasticache_cluster.this[0].port}" : ""
}

output "security_group_id" {
  description = "Security group shared by RDS and ElastiCache."
  value       = aws_security_group.this.id
}
