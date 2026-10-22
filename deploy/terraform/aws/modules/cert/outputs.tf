output "cert_secret_arn" {
  description = "Secrets Manager ARN of the PEM certificate chain (NAZR_TLS_CERT_PEM)."
  value       = aws_secretsmanager_secret_version.cert.secret_id
}

output "key_secret_arn" {
  description = "Secrets Manager ARN of the PEM private key (NAZR_TLS_KEY_PEM)."
  value       = aws_secretsmanager_secret_version.key.secret_id
}
