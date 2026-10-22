terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

resource "aws_security_group" "this" {
  name_prefix = "${var.name}-db-"
  description = "PostgreSQL and Redis, reachable only from the nazr tasks"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-db" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "postgres" {
  security_group_id            = aws_security_group.this.id
  description                  = "PostgreSQL from the nazr tasks"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = var.client_security_group
  tags                         = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "redis" {
  count = var.enable_redis ? 1 : 0

  security_group_id            = aws_security_group.this.id
  description                  = "Redis from the nazr tasks"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = var.client_security_group
  tags                         = var.tags
}

# No egress rules: RDS and ElastiCache only answer connections.

# --- PostgreSQL -------------------------------------------------------------

# Alphanumeric only, so the password can go into a URL without escaping.
resource "random_password" "master" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "this" {
  name_prefix = "${var.name}-"
  description = "nazr database subnets"
  subnet_ids  = var.subnet_ids
  tags        = var.tags
}

resource "aws_db_instance" "this" {
  identifier_prefix = "${var.name}-"

  engine         = "postgres"
  engine_version = "17"
  instance_class = var.instance_class

  allocated_storage = var.allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = "nazr"
  username = "nazr"
  password = random_password.master.result
  port     = 5432

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  publicly_accessible    = false
  multi_az               = false

  backup_retention_period    = 7
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true

  # Deliberately off so `terraform destroy` works for evaluation stacks.
  # Turn it on (and keep the final snapshot) for anything holding real data.
  deletion_protection       = false
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"

  tags = var.tags
}

resource "aws_secretsmanager_secret" "database_url" {
  name_prefix = "${var.name}/database-url-"
  description = "nazr NAZR_DATABASE_URL (contains the RDS master password)"
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = "postgres://${aws_db_instance.this.username}:${random_password.master.result}@${aws_db_instance.this.address}:${aws_db_instance.this.port}/${aws_db_instance.this.db_name}?sslmode=require"
}

# --- Redis (optional) -------------------------------------------------------

resource "aws_elasticache_subnet_group" "this" {
  count = var.enable_redis ? 1 : 0

  name        = "${var.name}-redis"
  description = "nazr Redis subnets"
  subnet_ids  = var.subnet_ids
  tags        = var.tags
}

# Single node, no replica: Redis only holds the shared rate limiter and key
# cache, which nazr rebuilds on its own (and fails open) if the node is lost.
resource "aws_elasticache_cluster" "this" {
  count = var.enable_redis ? 1 : 0

  cluster_id           = "${var.name}-redis"
  engine               = "redis"
  engine_version       = "7.1"
  parameter_group_name = "default.redis7"
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.this[0].name
  security_group_ids = [aws_security_group.this.id]

  tags = var.tags
}
