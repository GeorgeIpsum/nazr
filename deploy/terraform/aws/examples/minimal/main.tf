# Minimal deployment: the module creates its own VPC, RDS instance, ACME
# certificate and ECS service. Only the hostname, zone and contact email are
# required.
module "nazr" {
  source = "../.."

  region          = var.region
  domain          = var.domain
  route53_zone_id = var.route53_zone_id
  acme_email      = var.acme_email

  maxmind_account_id  = var.maxmind_account_id
  maxmind_license_key = var.maxmind_license_key

  tags = {
    environment = "example"
  }
}

output "api_url" {
  value = module.nazr.api_url
}

output "first_key_command" {
  value = module.nazr.first_key_command
}
