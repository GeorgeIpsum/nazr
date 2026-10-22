output "api_url" {
  description = "Public URL of the API."
  value       = "https://${var.domain}"
}

output "nlb_dns_name" {
  description = "DNS name of the Network Load Balancer (var.domain is an alias to it)."
  value       = module.service.nlb_dns_name
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = module.service.cluster_name
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = module.service.service_name
}

output "ecr_repository_url" {
  description = "ECR repository URL when var.image is a bare tag, otherwise empty."
  value       = module.service.ecr_repository_url
}

output "admin_token_secret_arn" {
  description = "Secrets Manager ARN holding NAZR_ADMIN_TOKEN (the value itself is never output)."
  value       = aws_secretsmanager_secret.admin_token.arn
}

output "first_key_command" {
  description = "Creates the first API key through ECS Exec (needs the AWS CLI Session Manager plugin)."
  value = join(" ", [
    "aws ecs execute-command --region ${var.region}",
    "--cluster ${module.service.cluster_name}",
    "--task $(aws ecs list-tasks --region ${var.region} --cluster ${module.service.cluster_name} --service-name ${module.service.service_name} --desired-status RUNNING --query 'taskArns[0]' --output text)",
    "--container nazr --interactive",
    "--command \"/nazr keys create --label first\"",
  ])
}
