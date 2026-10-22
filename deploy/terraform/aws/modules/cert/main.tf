terraform {
  required_version = ">= 1.9"

  required_providers {
    acme = {
      source  = "vancluever/acme"
      version = "~> 2.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

resource "tls_private_key" "account" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "acme_registration" "this" {
  account_key_pem = tls_private_key.account.private_key_pem
  email_address   = var.acme_email
}

# Issued with a Route53 DNS-01 challenge, so neither port 80 nor 443 has to
# be reachable during issuance. The lego Route53 provider uses the standard
# AWS credential chain of the machine running Terraform (not the aws provider
# configuration). Renewal happens on any `terraform apply` within
# min_days_remaining of expiry; the new secret version is picked up by tasks
# started after that (force a new deployment to roll them).
resource "acme_certificate" "this" {
  account_key_pem    = acme_registration.this.account_key_pem
  common_name        = var.domain
  min_days_remaining = 30

  dns_challenge {
    provider = "route53"

    config = {
      AWS_HOSTED_ZONE_ID = var.route53_zone_id
      AWS_REGION         = var.region
    }
  }
}

resource "aws_secretsmanager_secret" "cert" {
  name_prefix = "${var.name}/tls-cert-"
  description = "nazr TLS certificate chain (PEM) for ${var.domain}, issued by ACME"
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "cert" {
  secret_id     = aws_secretsmanager_secret.cert.id
  secret_string = "${acme_certificate.this.certificate_pem}${acme_certificate.this.issuer_pem}"
}

resource "aws_secretsmanager_secret" "key" {
  name_prefix = "${var.name}/tls-key-"
  description = "nazr TLS private key (PEM) for ${var.domain}, issued by ACME"
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "key" {
  secret_id     = aws_secretsmanager_secret.key.id
  secret_string = acme_certificate.this.private_key_pem
}
