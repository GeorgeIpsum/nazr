terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

locals {
  # A bare tag (no '/') means "push to the ECR repository this module creates".
  create_ecr = !strcontains(var.image, "/")
  image      = local.create_ecr ? "${aws_ecr_repository.this[0].repository_url}:${var.image}" : var.image

  secret_arns = compact([
    var.database_url_secret_arn,
    var.tls_cert_secret_arn,
    var.tls_key_secret_arn,
    var.admin_token_secret_arn,
    var.maxmind_secret_arn,
  ])
}

resource "aws_ecs_cluster" "this" {
  name = var.name
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_ecr_repository" "this" {
  count = local.create_ecr ? 1 : 0

  name                 = "nazr"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

# --- Security groups --------------------------------------------------------
#
# The NLB is a TCP passthrough with client IP preservation: packets reach the
# task with the real client's source address, not the NLB's. NLB security
# groups are evaluated at the NLB's ENIs, so a target group can still admit
# traffic by referencing the NLB security group regardless of client IP
# preservation: the task group admits 8443/8080 (the container ports) from the
# NLB group only. var.task_ingress_cidrs replaces that with CIDR rules (escape
# hatch, e.g. 0.0.0.0/0 and ::/0; tasks sit in private subnets without public
# IPs either way). wait_for_steady_state fails the first apply if health
# checks cannot reach the tasks.

resource "aws_security_group" "nlb" {
  name_prefix = "${var.name}-nlb-"
  description = "nazr NLB: 443 and 80 from the internet"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-nlb" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "task" {
  name_prefix = "${var.name}-task-"
  description = "nazr tasks: 8443 and 8080 via the NLB"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-task" })

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  # Clients connect to the NLB on 443/80; the NLB forwards to unprivileged
  # container ports because the image runs as uid 65532 and Fargate does not
  # guarantee that non-root processes may bind ports below 1024.
  ports = {
    https = { listener = 443, container = 8443 }
    http  = { listener = 80, container = 8080 }
  }
  cidrs = {
    ipv4 = { cidr_ipv4 = "0.0.0.0/0", cidr_ipv6 = null }
    ipv6 = { cidr_ipv4 = null, cidr_ipv6 = "::/0" }
  }
  nlb_ingress = merge([
    for pn, p in local.ports : {
      for cn, c in local.cidrs : "${pn}-${cn}" => merge(c, { name = pn, port = p.listener })
    }
  ]...)
  # Default: task ingress from the NLB security group. With task_ingress_cidrs
  # set, CIDR rules replace it.
  task_ingress_from_nlb = length(var.task_ingress_cidrs) == 0 ? local.ports : {}
  task_ingress_cidr = merge([
    for pn, p in local.ports : {
      for c in var.task_ingress_cidrs : "${pn}-${c}" => {
        name      = pn
        port      = p.container
        cidr_ipv4 = strcontains(c, ":") ? null : c
        cidr_ipv6 = strcontains(c, ":") ? c : null
      }
    }
  ]...)
}

resource "aws_vpc_security_group_ingress_rule" "nlb" {
  for_each = local.nlb_ingress

  security_group_id = aws_security_group.nlb.id
  description       = "${upper(each.value.name)} from the internet"
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr_ipv4
  cidr_ipv6         = each.value.cidr_ipv6
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_task" {
  for_each = local.ports

  security_group_id            = aws_security_group.nlb.id
  description                  = "Forward ${upper(each.key)} and health checks to the tasks"
  ip_protocol                  = "tcp"
  from_port                    = each.value.container
  to_port                      = each.value.container
  referenced_security_group_id = aws_security_group.task.id
  tags                         = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "task_from_nlb" {
  for_each = local.task_ingress_from_nlb

  security_group_id            = aws_security_group.task.id
  description                  = "${upper(each.key)} and health checks from the NLB"
  ip_protocol                  = "tcp"
  from_port                    = each.value.container
  to_port                      = each.value.container
  referenced_security_group_id = aws_security_group.nlb.id
  tags                         = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "task" {
  for_each = local.task_ingress_cidr

  security_group_id = aws_security_group.task.id
  description       = "${upper(each.value.name)} via the NLB (task_ingress_cidrs)"
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  cidr_ipv4         = each.value.cidr_ipv4
  cidr_ipv6         = each.value.cidr_ipv6
  tags              = var.tags
}

# Outbound: RDS, Redis, EFS, VPC endpoints, and the internet via NAT for
# image pulls, MaxMind and IP-list downloads.
resource "aws_vpc_security_group_egress_rule" "task_all" {
  security_group_id = aws_security_group.task.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  tags              = var.tags
}

# --- Optional persistent /data on EFS ---------------------------------------

resource "aws_efs_file_system" "data" {
  count = var.enable_efs_data ? 1 : 0

  encrypted = true
  tags      = merge(var.tags, { Name = "${var.name}-data" })
}

# The image runs as uid/gid 65532 (distroless nonroot). The access point forces
# that identity and creates its root directory owned by it, so the API can
# write /data (an empty volume owned by root would make downloads fail).
resource "aws_efs_access_point" "data" {
  count = var.enable_efs_data ? 1 : 0

  file_system_id = aws_efs_file_system.data[0].id

  posix_user {
    uid = 65532
    gid = 65532
  }

  root_directory {
    path = "/nazr-data"

    creation_info {
      owner_uid   = 65532
      owner_gid   = 65532
      permissions = "0755"
    }
  }

  tags = var.tags
}

resource "aws_security_group" "efs" {
  count = var.enable_efs_data ? 1 : 0

  name_prefix = "${var.name}-efs-"
  description = "nazr EFS: NFS from the tasks"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-efs" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "efs" {
  count = var.enable_efs_data ? 1 : 0

  security_group_id            = aws_security_group.efs[0].id
  description                  = "NFS from the nazr tasks"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.task.id
  tags                         = var.tags
}

resource "aws_efs_mount_target" "data" {
  count = var.enable_efs_data ? length(var.private_subnet_ids) : 0

  file_system_id  = aws_efs_file_system.data[0].id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs[0].id]
}

# --- Service ----------------------------------------------------------------

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 60
  enable_execute_command             = true
  propagate_tags                     = "SERVICE"

  # Fail the apply when tasks never become healthy (bad image, crash loop)
  # instead of reporting success. Waits up to the provider's 20-minute default.
  wait_for_steady_state = var.wait_for_steady_state

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = local.ports

    content {
      target_group_arn = aws_lb_target_group.this[load_balancer.key].arn
      container_name   = "nazr"
      container_port   = load_balancer.value.container
    }
  }

  tags = var.tags

  depends_on = [aws_lb_listener.this, aws_efs_mount_target.data]
}

resource "aws_route53_record" "this" {
  zone_id = var.route53_zone_id
  name    = var.domain
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}
