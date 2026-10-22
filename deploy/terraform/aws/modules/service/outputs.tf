output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.this.name
}

output "nlb_dns_name" {
  description = "NLB DNS name."
  value       = aws_lb.this.dns_name
}

output "ecr_repository_url" {
  description = "ECR repository URL, or empty when var.image is a full reference."
  value       = local.create_ecr ? aws_ecr_repository.this[0].repository_url : ""
}

output "task_security_group_id" {
  description = "Security group of the tasks (allowed into RDS/Redis/EFS)."
  value       = aws_security_group.task.id
}
