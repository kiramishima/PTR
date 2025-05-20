## main.tf
provider "aws" {
  region = var.aws_region
}

# Configuración de variables
variable "aws_region" {
  description = "Región de AWS"
  default     = "us-east-1"
}

variable "environment" {
  description = "Entorno de despliegue"
  default     = "production"
}

variable "project_name" {
  description = "Nombre del proyecto"
  default     = "secure-application"
}

variable "vpc_cidr" {
  description = "CIDR del VPC"
  default     = "10.0.0.0/16"
}

# VPC y configuración de red segura
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
  }
}

# Subredes públicas y privadas en múltiples zonas de disponibilidad
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "${var.project_name}-private-subnet-${count.index + 1}"
    Environment = var.environment
  }
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 3)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project_name}-public-subnet-${count.index + 1}"
    Environment = var.environment
  }
}

data "aws_availability_zones" "available" {}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.project_name}-igw"
    Environment = var.environment
  }
}

# NAT Gateway con IP elástica
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name        = "${var.project_name}-eip"
    Environment = var.environment
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name        = "${var.project_name}-nat"
    Environment = var.environment
  }
}

# Tablas de enrutamiento para subredes públicas y privadas
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name        = "${var.project_name}-public-route-table"
    Environment = var.environment
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name        = "${var.project_name}-private-route-table"
    Environment = var.environment
  }
}

# Asociaciones de tabla de rutas
resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Grupo de seguridad por defecto
resource "aws_security_group" "default" {
  name        = "${var.project_name}-default-sg"
  description = "Default security group to allow inbound/outbound from the VPC"
  vpc_id      = aws_vpc.main.id

  # No permitir tráfico entrante por defecto
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Allow internal traffic only"
  }

  # Permitir todo el tráfico saliente
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "${var.project_name}-default-sg"
    Environment = var.environment
  }
}

# KMS para encriptación
resource "aws_kms_key" "main" {
  description             = "KMS key for encrypting resources"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-kms"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.project_name}-key"
  target_key_id = aws_kms_key.main.key_id
}

# S3 con configuración segura
resource "aws_s3_bucket" "main" {
  bucket = "${var.project_name}-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "${var.project_name}-bucket"
    Environment = var.environment
  }
}

# Generar sufijo aleatorio para nombre único del bucket
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Bloquear acceso público al bucket S3
resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encriptar bucket S3 con KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Forzar HTTPS en el bucket
resource "aws_s3_bucket_policy" "main" {
  bucket = aws_s3_bucket.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ForceSSLOnlyAccess"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.main.arn,
          "${aws_s3_bucket.main.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# Versioning del bucket S3
resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ECR Repository con escaneo de imágenes
resource "aws_ecr_repository" "main" {
  name                 = "${var.project_name}-repository"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.main.arn
  }

  tags = {
    Name        = "${var.project_name}-ecr"
    Environment = var.environment
  }
}

# Política de ciclo de vida para el repositorio ECR
resource "aws_ecr_lifecycle_policy" "main" {
  repository = aws_ecr_repository.main.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire images older than 90 days"
        selection = {
          tagStatus   = "any"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 90
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# Configuración de ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "${var.project_name}-ecs"
    Environment = var.environment
  }
}

# Activar protección de datos para el cluster
resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

# Grupo de seguridad para ECS Tasks
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.project_name}-ecs-tasks-sg"
  description = "Allow inbound access to ECS tasks from ALB only"
  vpc_id      = aws_vpc.main.id

  ingress {
    protocol        = "tcp"
    from_port       = 80
    to_port         = 80
    security_groups = [aws_security_group.alb.id]
    description     = "Allow HTTP traffic from ALB"
  }

  ingress {
    protocol        = "tcp"
    from_port       = 443
    to_port         = 443
    security_groups = [aws_security_group.alb.id]
    description     = "Allow HTTPS traffic from ALB"
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "${var.project_name}-ecs-tasks-sg"
    Environment = var.environment
  }
}

# Rol de ejecución de tareas ECS
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.project_name}-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-ecs-task-execution-role"
    Environment = var.environment
  }
}

# Adjuntar políticas al rol de ejecución de tareas ECS
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Security Group para ALB
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP traffic"
  }

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS traffic"
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "${var.project_name}-alb-sg"
    Environment = var.environment
  }
}

# Redshift con configuración segura
resource "aws_redshift_subnet_group" "main" {
  name       = "${var.project_name}-redshift-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name        = "${var.project_name}-redshift-subnet-group"
    Environment = var.environment
  }
}

resource "aws_security_group" "redshift" {
  name        = "${var.project_name}-redshift-sg"
  description = "Security group for Redshift cluster"
  vpc_id      = aws_vpc.main.id

  # Solo permitir conexiones desde ECS o subredes específicas
  ingress {
    protocol        = "tcp"
    from_port       = 5439
    to_port         = 5439
    security_groups = [aws_security_group.ecs_tasks.id]
    description     = "Allow Redshift traffic from ECS tasks"
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "${var.project_name}-redshift-sg"
    Environment = var.environment
  }
}

resource "aws_redshift_cluster" "main" {
  cluster_identifier        = "${var.project_name}-redshift"
  database_name             = "app_data"
  master_username           = "admin"
  # En producción, usa aws_secretsmanager_secret para almacenar contraseñas
  master_password           = "Y0ur-S3cur3-P@ssw0rd" # Cambiar por una generada dinámicamente
  node_type                 = "dc2.large"
  cluster_type              = "single-node"
  automated_snapshot_retention_period = 7
  encrypted                 = true
  kms_key_id                = aws_kms_key.main.arn
  enhanced_vpc_routing      = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.project_name}-final-snapshot"
  vpc_security_group_ids    = [aws_security_group.redshift.id]
  cluster_subnet_group_name = aws_redshift_subnet_group.main.name
  publicly_accessible       = false

  logging {
    enable = true
  }

  tags = {
    Name        = "${var.project_name}-redshift"
    Environment = var.environment
  }
}

# Aurora Serverless
resource "aws_rds_cluster_parameter_group" "main" {
  name        = "${var.project_name}-aurora-pg"
  family      = "aurora-postgresql13"
  description = "Aurora PostgreSQL parameter group"

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  tags = {
    Name        = "${var.project_name}-aurora-pg"
    Environment = var.environment
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-aurora-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name        = "${var.project_name}-aurora-subnet-group"
    Environment = var.environment
  }
}

resource "aws_security_group" "aurora" {
  name        = "${var.project_name}-aurora-sg"
  description = "Security group for Aurora Serverless"
  vpc_id      = aws_vpc.main.id

  # Solo permitir conexiones desde ECS
  ingress {
    protocol        = "tcp"
    from_port       = 5432
    to_port         = 5432
    security_groups = [aws_security_group.ecs_tasks.id]
    description     = "Allow PostgreSQL traffic from ECS tasks"
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "${var.project_name}-aurora-sg"
    Environment = var.environment
  }
}

resource "aws_rds_cluster" "aurora" {
  cluster_identifier        = "${var.project_name}-aurora"
  engine                    = "aurora-postgresql"
  engine_mode               = "serverless"
  database_name             = "app_database"
  master_username           = "admin"
  # En producción, usa aws_secretsmanager_secret para almacenar contraseñas
  master_password           = aws_secretsmanager_secret.database_master_password # Cambiar por una generada dinámicamente
  backup_retention_period   = 7
  preferred_backup_window   = "03:00-04:00"
  preferred_maintenance_window = "sun:04:30-sun:05:30"
  db_subnet_group_name      = aws_db_subnet_group.main.name
  vpc_security_group_ids    = [aws_security_group.aurora.id]
  storage_encrypted         = true
  kms_key_id                = aws_kms_key.main.arn
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.project_name}-aurora-final-snapshot"
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.main.name
  deletion_protection       = true
  
  scaling_configuration {
    auto_pause               = true
    max_capacity             = 32
    min_capacity             = 2
    seconds_until_auto_pause = 300
  }

  tags = {
    Name        = "${var.project_name}-aurora"
    Environment = var.environment
  }
}

# CloudWatch logs para almacenar logs de forma centralizada
resource "aws_cloudwatch_log_group" "main" {
  name              = "/aws/${var.project_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.main.arn

  tags = {
    Name        = "${var.project_name}-logs"
    Environment = var.environment
  }
}

# WAF para proteger APIs y aplicaciones web
resource "aws_wafv2_web_acl" "main" {
  name        = "${var.project_name}-waf"
  description = "WAF for protecting web applications"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Regla contra SQL injection
  rule {
    name     = "SQL-Injection-Prevention"
    priority = 1

    action {
      block {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLInjection"
      sampled_requests_enabled   = true
    }
  }

  # Regla contra XSS
  rule {
    name     = "XSS-Prevention"
    priority = 2

    action {
      block {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        excluded_rule {
          name = "SizeRestrictions_BODY"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "XSSPrevention"
      sampled_requests_enabled   = true
    }
  }

  # Regla de limitación de tasa para prevenir DDoS
  rule {
    name     = "RateLimiting"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimiting"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name        = "${var.project_name}-waf"
    Environment = var.environment
  }
}

# Outputs para información importante
output "vpc_id" {
  description = "ID del VPC"
  value       = aws_vpc.main.id
}

output "s3_bucket_name" {
  description = "Nombre del bucket S3"
  value       = aws_s3_bucket.main.id
}

output "ecr_repository_url" {
  description = "URL del repositorio ECR"
  value       = aws_ecr_repository.main.repository_url
}

output "ecs_cluster_name" {
  description = "Nombre del cluster ECS"
  value       = aws_ecs_cluster.main.name
}

output "redshift_endpoint" {
  description = "Endpoint de Redshift"
  value       = aws_redshift_cluster.main.endpoint
}

output "aurora_endpoint" {
  description = "Endpoint de Aurora"
  value       = aws_rds_cluster.aurora.endpoint
}

output "kms_key_id" {
  description = "ID de la clave KMS"
  value       = aws_kms_key.main.id
}

## variables.tf
variable "aws_region" {
  description = "Región de AWS para desplegar recursos"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Entorno de despliegue (dev, staging, prod)"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Nombre del proyecto"
  type        = string
  default     = "secure-application"
}

variable "vpc_cidr" {
  description = "CIDR del VPC"
  type        = string
  default     = "10.0.0.0/16"
}

## secrets.tf - Para gestión de secretos
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "${var.project_name}/${var.environment}/database"
  description             = "Credenciales para bases de datos"
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.main.arn

  tags = {
    Name        = "${var.project_name}-db-secrets"
    Environment = var.environment
  }
}

# En un entorno real, deberías usar variables o un proceso separado para crear los valores secretos
resource "aws_secretsmanager_secret_version" "database_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
  secret_string = jsonencode({
    username           = "admin"
    password           = "Y0ur-S3cur3-P@ssw0rd"
    aurora_endpoint    = aws_rds_cluster.aurora.endpoint
    redshift_endpoint  = aws_redshift_cluster.main.endpoint
  })
}

## waf.tf - Configuración adicional de WAF
resource "aws_wafv2_ip_set" "allowed_ips" {
  name               = "${var.project_name}-allowed-ips"
  description        = "IP addresses that are allowed to access the application"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["192.0.2.0/24", "198.51.100.0/24"] # Reemplazar con tus IPs permitidas

  tags = {
    Name        = "${var.project_name}-allowed-ips"
    Environment = var.environment
  }
}

## cloudwatch.tf - Alertas y monitoreo adicional
resource "aws_cloudwatch_metric_alarm" "s3_bucket_size" {
  alarm_name          = "${var.project_name}-s3-bucket-size"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = 86400
  statistic           = "Maximum"
  threshold           = 5000000000 # 5 GB
  alarm_description   = "Este alarma se activa cuando el tamaño del bucket S3 supera los 5 GB"
  
  dimensions = {
    BucketName = aws_s3_bucket.main.id
    StorageType = "StandardStorage"
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
  kms_master_key_id = aws_kms_key.main.id
  
  tags = {
    Name        = "${var.project_name}-alerts"
    Environment = var.environment
  }
}

## compliance.tf - Políticas para cumplimiento y seguridad
resource "aws_config_config_rule" "encrypted_volumes" {
  name = "${var.project_name}-encrypted-volumes"
  
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  
  tags = {
    Name        = "${var.project_name}-encrypted-volumes-rule"
    Environment = var.environment
  }
}

resource "aws_config_config_rule" "s3_bucket_ssl" {
  name = "${var.project_name}-s3-bucket-ssl"
  
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }
  
  tags = {
    Name        = "${var.project_name}-s3-ssl-rule"
    Environment = var.environment
  }
}

## logging.tf - Configuración centralizada de logs
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.main.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  enable_log_file_validation    = true
  is_multi_region_trail         = true
  kms_key_id                    = aws_kms_key.main.arn
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
  
  tags = {
    Name        = "${var.project_name}-cloudtrail"
    Environment = var.environment
  }
}