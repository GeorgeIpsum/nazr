locals {
  environment = merge(
    {
      NAZR_TLS_MODE        = "terminate"
      NAZR_DATA_DIR        = "/data"
      NAZR_EVENT_RETENTION = var.event_retention
      NAZR_CORS_ORIGINS    = var.cors_origins
      NAZR_METRICS_ADDR    = "127.0.0.1:9090"
    },
    var.redis_url != "" ? { NAZR_REDIS_URL = var.redis_url } : {},
    var.extra_env,
  )

  secrets = concat(
    [
      { name = "NAZR_DATABASE_URL", valueFrom = var.database_url_secret_arn },
      { name = "NAZR_TLS_CERT_PEM", valueFrom = var.tls_cert_secret_arn },
      { name = "NAZR_TLS_KEY_PEM", valueFrom = var.tls_key_secret_arn },
      { name = "NAZR_ADMIN_TOKEN", valueFrom = var.admin_token_secret_arn },
    ],
    var.maxmind_secret_arn == "" ? [] : [
      { name = "NAZR_MAXMIND_ACCOUNT_ID", valueFrom = "${var.maxmind_secret_arn}:account_id::" },
      { name = "NAZR_MAXMIND_LICENSE_KEY", valueFrom = "${var.maxmind_secret_arn}:license_key::" },
    ],
  )

  container = {
    name      = "nazr"
    image     = local.image
    essential = true
    command   = ["serve"]

    portMappings = [
      for port in values(local.public_ports) : { containerPort = port, protocol = "tcp" }
    ]

    environment = [for k in sort(keys(local.environment)) : { name = k, value = local.environment[k] }]
    secrets     = local.secrets

    # Without EFS, /data is the container's writable layer (the image's
    # VOLUME /data, already owned by 65532) on the task's ephemeral storage.
    mountPoints = var.enable_efs_data ? [{ sourceVolume = "data", containerPath = "/data", readOnly = false }] : []

    # Lets ECS Exec run commands in a distroless image (no shell, no init).
    linuxParameters = { initProcessEnabled = true }

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "nazr"
      }
    }
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([local.container])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # Room for the writable layer that holds /data (MaxMind and IP lists).
  ephemeral_storage {
    size_in_gib = 21
  }

  dynamic "volume" {
    for_each = var.enable_efs_data ? [1] : []

    content {
      name = "data"

      efs_volume_configuration {
        file_system_id     = aws_efs_file_system.data[0].id
        transit_encryption = "ENABLED"

        authorization_config {
          access_point_id = aws_efs_access_point.data[0].id
          iam             = "ENABLED"
        }
      }
    }
  }

  tags = var.tags
}
