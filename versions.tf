terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.55.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "= 2.4.2"
    }
  }

  required_version = "~> 1.12.2"

  backend "s3" {
    bucket         = "tf-canary-backend"
    key            = "envs/prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tf-state-locking-canary"
    encrypt        = true
  }
}