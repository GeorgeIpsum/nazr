# TCP passthrough: nazr terminates TLS itself, which is what lets it read the
# raw ClientHello (JA4) and HTTP/2 frames. An ALB or CloudFront in front would
# terminate TLS and destroy those fingerprints.
resource "aws_lb" "this" {
  name               = var.name
  load_balancer_type = "network"
  internal           = false
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.nlb.id]

  enable_cross_zone_load_balancing = true

  tags = var.tags
}

resource "aws_lb_target_group" "this" {
  for_each = local.ports

  name        = "${var.name}-${each.key}"
  port        = each.value.container
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  # Required for fingerprinting: the task sees the client's real address.
  preserve_client_ip   = true
  deregistration_delay = 30

  # Both target groups probe the TLS port (8443): the HTTP port only redirects.
  health_check {
    protocol            = var.health_check_protocol
    port                = tostring(local.ports.https.container)
    path                = var.health_check_protocol == "HTTPS" ? "/healthz" : null
    matcher             = var.health_check_protocol == "HTTPS" ? "200" : null
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = var.tags
}

resource "aws_lb_listener" "this" {
  for_each = local.ports

  load_balancer_arn = aws_lb.this.arn
  port              = each.value.listener
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[each.key].arn
  }

  tags = var.tags
}
