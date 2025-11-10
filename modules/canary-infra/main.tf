resource "aws_vpc_endpoint" "s3_gateway_endpoint" {   //This is the endpoint gateway in our vpc to allow it 
  vpc_id       = var.vpc_id               
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"

  
  route_table_ids = [var.route_table_id]

  tags = {
    Name = "s3-gateway-endpoint"
  }
}

data "aws_iam_policy_document" "canary-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      identifiers =  ["lambda.amazonaws.com", "synthetics.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_iam_role" "canary-role" {
  name               = "canary-role"
  assume_role_policy = data.aws_iam_policy_document.canary-assume-role-policy.json
  description        = "IAM role for AWS Synthetic Monitoring Canaries"

  tags = {
    Name = "canary"
  }
}


resource "aws_kms_key" "canaries_reports_bucket_encryption_key" {
  enable_key_rotation = true

  //setting the kms key policies
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowAccountAdministrators"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "kms:*"
        Resource = "*"
      },
      {
        Sid = "AllowCanaryRoleUsage"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.canary-role.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid = "AllowSyntheticsServiceUseOfKey"
        Effect = "Allow"
        Principal = {
          Service = "synthetics.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket" "canaries_reports_bucket" {
  bucket = "canaries-reports-bucket-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  #checkov:skip=CKV_AWS_18:The bucket does not require access logging
  #checkov:skip=CKV_AWS_144:The bucket does not require cross-region replication
  tags = {
    Name = "canary"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "canaries_reports_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.canaries_reports_bucket.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.canaries_reports_bucket_encryption_key.arn
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "canaries_reports_bucket_versioning" {
  bucket = aws_s3_bucket.canaries_reports_bucket.bucket
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "canaries_reports_bucket_lifecycle_configuration" {
  bucket = aws_s3_bucket.canaries_reports_bucket.bucket
  rule {
    id = "config"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "canaries_reports_bucket_ownership" {
  bucket = aws_s3_bucket.canaries_reports_bucket.bucket
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "canaries_reports_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.canaries_reports_bucket_ownership]
  bucket = aws_s3_bucket.canaries_reports_bucket.bucket
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "canaries_reports_bucket_block_public_access" {
  bucket                  = aws_s3_bucket.canaries_reports_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "canaries_reports_bucket-policy" {
  bucket = aws_s3_bucket.canaries_reports_bucket.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Id        = "CanariesReportsBucketPolicy"
    Statement = [
      {
        Sid       = "Permissions"  //allows the root user to access the s3 bucket
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = ["s3:*"]
        Resource = [aws_s3_bucket.canaries_reports_bucket.arn, 
        "${aws_s3_bucket.canaries_reports_bucket.arn}/*"]
      },
      {
        "Sid": "AllowSSLRequestsOnly",  //allows only https requests
        "Action": "s3:*",
        "Effect": "Deny",
        "Resource": [
          aws_s3_bucket.canaries_reports_bucket.arn,
          "${aws_s3_bucket.canaries_reports_bucket.arn}/*"
        ],
        "Condition": {
          "Bool": {
            "aws:SecureTransport": "false"
          }
        },
        "Principal": "*"
      }
      /*
      {
        Sid    = "AllowCanaryAccess",   //allows the canary to access the s3 bucket so it can store logs in it
        Effect = "Allow",
        Principal = { AWS = aws_iam_role.canary-role.arn },
        Action = "s3:*",
        Resource = [
          aws_s3_bucket.canaries_reports_bucket.arn,
          "${aws_s3_bucket.canaries_reports_bucket.arn}/*"
        ],
        Condition = {
          StringEquals = {
            "aws:SourceVpce" = "${aws_vpc_endpoint.s3_gateway_endpoint.id}"
          }
        }
      }
      
      {
        "Sid": "AllowAccessFromVPCEndpoint",    //allows the private s3 bucket to be accessed by the specified vpc. We have created a endpoint gateway in the vpc.
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          aws_s3_bucket.canaries_reports_bucket.arn,
          "${aws_s3_bucket.canaries_reports_bucket.arn}/*"
        ],
        "Condition": {
          "StringEquals": {
            "aws:SourceVpce": "vpc-0a9f079ba4d91671c"
          }
        }
      }
      */
    ]
  })
}



resource "aws_iam_role_policy_attachment" "AWSLambdaVPCAccessExecutionRole" {
  role       = aws_iam_role.canary-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "aws_iam_policy_document" "canary-policy" {
  statement {
    sid     = "CanaryS3Permission1"
    effect  = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetBucketLocation",
      "s3:ListAllMyBuckets",
      "s3:ListBucket",
      "s3:GetObject"
    ]
    resources = [
      aws_s3_bucket.canaries_reports_bucket.arn,
      "${aws_s3_bucket.canaries_reports_bucket.arn}/*"
    ]
  }

  statement {
    sid     = "CanaryS3Permission2"
    effect  = "Allow"
    actions = [
      "s3:ListAllMyBuckets"
    ]
    resources = [
      "arn:aws:s3:::*"
    ]
  }

  statement {
    sid     = "CanaryCloudWatchLogsCreateLogGroup"
    effect  = "Allow"
    actions = [
      "logs:CreateLogGroup"
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/synthetics/*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }

  statement {
    sid     = "CanaryCloudWatchLogs"
    effect  = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = [
      # For Synthetics Canary log groups
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/synthetics/*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/synthetics/*:log-stream:*",
      # For Lambda (used internally by canary runtimes)
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*:log-stream:*"
    ]
  }

  statement {
    sid     = "CanaryCloudWatchAlarm"
    effect  = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = [
      "*"
    ]
    condition {
      test     = "StringEquals"
      values   = ["CloudWatchSynthetics"]
      variable = "cloudwatch:namespace"
    }
  }

  statement {
    sid     = "CanaryinVPC"
    effect  = "Allow"
    actions = [
      "ec2:DescribeNetworkInterfaces",
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeInstances",
      "ec2:AttachNetworkInterface"
    ]
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:network-interface/*"
    ]
  }

  statement {
    sid     = "CanaryKMSUse"
    effect  = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.canaries_reports_bucket_encryption_key.arn
    ]
  }

  statement {
    sid     = "CanaryCloudWatchAdditional"
    effect  = "Allow"
    actions = [
      "logs:PutRetentionPolicy",
      "logs:TagResource"
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/synthetics/*",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }

  statement {
    sid     = "CanarySyntheticsDescribe"
    effect  = "Allow"
    actions = [
      "synthetics:DescribeCanaries",
      "synthetics:GetCanaryRuns",
      "synthetics:DescribeCanariesLastRun"
    ]
    resources = ["*"]
  }

  statement {
    sid     = "CanaryKMSList"
    effect  = "Allow"
    actions = [
      "kms:ListAliases",
      "kms:ListKeys"
    ]
    resources = ["*"]
  }
}


resource "aws_iam_policy" "canary-policy" {
  name        = "canary-policy"
  policy      = data.aws_iam_policy_document.canary-policy.json
  description = "IAM role for AWS Synthetic Monitoring Canaries"

  tags = {
    Name = "canary"
  }
}

resource "aws_iam_role_policy_attachment" "canary-policy-attachment" {
  role       = aws_iam_role.canary-role.name
  policy_arn = aws_iam_policy.canary-policy.arn
}

resource "aws_iam_role_policy_attachment" "canary-synthetics-full-access" {
  role       = aws_iam_role.canary-role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchSyntheticsFullAccess"
}

resource "aws_security_group" "canary_sg" {
  name        = "canary_sg"
  description = "Allow canaries to call the services they need to call"
  vpc_id      = var.vpc_id

  #checkov:skip=CKV2_AWS_5:Security group is correctly attached using output variable
  egress = [
    {
      description      = "Allow calls from canary to DNS"
      from_port        = 53
      to_port          = 53
      protocol         = "TCP"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "Allow calls from canary to HTTPS"
      from_port        = 443
      to_port          = 443
      protocol         = "TCP"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "Allow calls from canary to HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "TCP"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "Allow calls from canary to DNS (UDP)"   //DNS primarily uses UDP port 53. By adding this egress for udp, we prevent dns resolution failures
      from_port        = 53
      to_port          = 53
      protocol         = "UDP"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    }
  ]

  tags = {
    Name = "canary"
  }
}

resource "aws_security_group" "canary_endpoints_sg" {
  name        = "canary_endpoints_sg"
  description = "Security group attached to interface endpoints"
  vpc_id      = var.vpc_id

  ingress = [
    {
      description      = "Allow HTTPS from Canary"
      from_port        = 443
      to_port          = 443
      protocol         = "TCP"
      cidr_blocks = []
      ipv6_cidr_blocks = []
      prefix_list_ids = []
      security_groups  = [aws_security_group.canary_sg.id]
      self             = false
    }
  ]


  tags = {
    Name = "canary"
  }
}


resource "aws_vpc_endpoint" "canary_monitoring_endpoint" {
  service_name      = "com.amazonaws.${data.aws_region.current.name}.monitoring"
  vpc_id            = var.vpc_id
  vpc_endpoint_type = "Interface"
  private_dns_enabled = true

  security_group_ids = [aws_security_group.canary_endpoints_sg.id]
  subnet_ids         = var.subnet_ids

  tags = {
    Name = "canary"
  }
}

resource "aws_vpc_endpoint" "canary_synthetics_endpoint" {
  service_name        = "com.amazonaws.${data.aws_region.current.name}.synthetics"
  vpc_id              = var.vpc_id
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  security_group_ids = [aws_security_group.canary_endpoints_sg.id]
  subnet_ids         = var.subnet_ids


  tags = {
    Name = "canary"
  }
}


resource "aws_vpc_endpoint" "canary_logs_endpoint" {
  service_name        = "com.amazonaws.${data.aws_region.current.name}.logs"
  vpc_id              = var.vpc_id
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  security_group_ids = [aws_security_group.canary_endpoints_sg.id]
  subnet_ids         = var.subnet_ids

  tags = {
    Name = "canary"
  }
}


