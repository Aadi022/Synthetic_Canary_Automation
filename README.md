# Canary-Automation-Infra – Terraform Deployment

This project deploys a private, VPC-integrated CloudWatch Synthetics Canary using Terraform.  
The canary runs inside a private subnet, uses VPC Endpoints, stores artifacts in a KMS-encrypted S3 bucket, and triggers SNS alerts on failures.

---

## Project Overview

- Canary (Lambda-based) runs inside a private VPC subnet  
- Accesses AWS APIs through VPC Endpoints (no internet required)  
- Stores logs and screenshots in KMS-encrypted S3  
- Triggers CloudWatch Alarm and sends SNS notifications  
- Uses remote Terraform backend (S3 + DynamoDB lock table)

---

## Required Inputs

Defined in `terraform.tfvars`:

- `api_hostname`, `api_path`
- `vpc_id`, `subnet_ids`, `route_table_id`
- `frequency` (in minutes)
- `alert_sns_topic`
- `name`, `runtime_version`, `take_screenshot`

---

## Canary Infrastructure (modules/canary-infra)

### KMS
- Creates a key for S3 artifact encryption  
- Accessible by root account, Canary IAM role, and AWS Synthetics service

### S3 Bucket
- Private bucket for canary artifacts  
- Default KMS encryption  
- Versioning enabled  
- Lifecycle rule deletes older versions after 30 days  
- Bucket policy restricts access to HTTPS and the private VPC endpoint

### IAM Role and Policies
Provides permissions for:
- S3 read/write for artifact storage  
- CloudWatch Logs creation and publishing  
- CloudWatch Metrics (PutMetricData)  
- Creating ENIs inside the VPC  
- KMS key usage  
- CloudWatch Synthetics access

### Security Groups
- Canary SG: DNS, HTTP, and HTTPS egress  
- Endpoint SG: HTTPS ingress from the Canary SG

### VPC Endpoints
- CloudWatch Logs  
- CloudWatch Monitoring  
- CloudWatch Synthetics  
- S3 Gateway endpoint

---

## Canary Module (modules/canary)

### Template Script
`canary.js.tpl` is rendered and packaged as a ZIP. It:

- Starts a headless browser  
- Hits the target URL  
- Measures DOM/content load time  
- Stores screenshots and HAR logs  
- Sends logs to CloudWatch Logs

### CloudWatch Alarm
Triggers an SNS notification if:

- `SuccessPercent` drops below 90% within a five-minute evaluation period

---

## Deployment
- terraform init
- terraform plan
- terraform apply

---

## Summary
This Terraform setup delivers a secure and production-ready CloudWatch Synthetics Canary solution, featuring:

- Private VPC execution  
- Strong IAM controls  
- KMS encryption  
- VPC Endpoint integrations  
- Automated monitoring and alerting
