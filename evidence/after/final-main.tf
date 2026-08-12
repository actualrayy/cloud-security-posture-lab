terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  required_version = ">= 1.5.0"
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

resource "aws_vpc" "lab" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "cloud-security-posture-lab"
    Project     = "Cloud Security Posture Lab"
    Environment = "SecurityLab"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.10.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "cspm-lab-public"
  }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "cspm-lab-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = {
    Name = "cspm-lab-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "baseline" {
  name        = "cspm-lab-baseline"
  description = "Baseline security group for CSPM lab"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cspm-lab-baseline-sg"
  }
}

resource "aws_s3_bucket" "secure_baseline" {
  bucket = "cspm-lab-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "cspm-lab-secure-baseline"
    Purpose = "CSPM testing"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_baseline" {
  bucket = aws_s3_bucket.secure_baseline.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_baseline" {
  bucket = aws_s3_bucket.secure_baseline.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_iam_policy" "intentional_overprivileged" {
  name        = "cspm-lab-intentional-overprivileged"
  description = "Least-privilege policy after CSPM remediation"

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ]

        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "cspm-lab-remediated-policy"
    Purpose     = "CSPM remediation testing"
    Intentional = "false"
  }
}
resource "aws_iam_role" "cspm_ec2_role" {
  name = "cspm-lab-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "ec2.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "cspm-lab-ec2-role"
    Purpose = "CSPM attack-path testing"
  }
}

resource "aws_iam_role_policy_attachment" "cspm_ec2_overprivileged" {
  role       = aws_iam_role.cspm_ec2_role.name
  policy_arn = aws_iam_policy.intentional_overprivileged.arn
}

resource "aws_iam_instance_profile" "cspm_ec2_profile" {
  name = "cspm-lab-ec2-profile"
  role = aws_iam_role.cspm_ec2_role.name

  tags = {
    Name    = "cspm-lab-ec2-profile"
    Purpose = "CSPM attack-path testing"
  }
}

resource "aws_instance" "cspm_target" {
  ami                         = "ami-0c02fb55956c7d316"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.baseline.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.cspm_ec2_profile.name

  tags = {
    Name        = "cspm-lab-attack-path-target"
    Purpose     = "CSPM attack-path testing"
    Intentional = "true"
  }
}
resource "aws_cloudtrail" "cspm_lab" {
  name                          = "cspm-lab-trail"
  s3_bucket_name                = aws_s3_bucket.secure_baseline.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  tags = {
    Name    = "cspm-lab-cloudtrail"
    Purpose = "CSPM security monitoring"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.secure_baseline.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.secure_baseline.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = "s3:PutObject"

        Resource = "${aws_s3_bucket.secure_baseline.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

