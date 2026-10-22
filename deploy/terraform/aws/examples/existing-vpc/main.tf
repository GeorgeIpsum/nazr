# Deploy into an existing VPC: the network module is skipped and the given
# subnets are used. Private subnets need outbound internet (NAT) for image
# pulls, MaxMind and IP-list downloads.
module "nazr" {
  source = "../.."

  region          = var.region
  domain          = var.domain
  route53_zone_id = var.route53_zone_id
  acme_email      = var.acme_email

  maxmind_account_id  = var.maxmind_account_id
  maxmind_license_key = var.maxmind_license_key

  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids
  public_subnet_ids  = var.public_subnet_ids

  enable_redis  = true
  desired_count = 2

  tags = {
    environment = "example"
  }
}

output "api_url" {
  value = module.nazr.api_url
}

output "nlb_dns_name" {
  value = module.nazr.nlb_dns_name
}

output "first_key_command" {
  value = module.nazr.first_key_command
}
