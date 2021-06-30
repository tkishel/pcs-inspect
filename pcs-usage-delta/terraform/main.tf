terraform {
  required_version = ">= 0.13.0"
}

#### REQUIRED VARIABLES/PARAMETERS

# Define in terraform.tfvars.

variable "aws_region" {
  type = string
}

variable "prisma_api_endpoint" {
  type        = string
  description = "(Required) Prisma Cloud API URL (for example: https://api.prismacloud.io)"
}

variable "prisma_access_key" {
  type        = string
  description = "(Required) API Access Key"
}

variable "prisma_secret_key" {
  type        = string
  description = "(Required) API Secret Key"
}

#### OPTIONAL VARIABLES/PARAMETERS

# Define in terraform.tfvars.
# See also configure_defaults in pcs-usage-delta.py for defaults.

variable "debug_mode" {
  default     = "false"
  type        = string
  description = "(Optional) Enable debugging (choices: 'true, 'false')"
}

variable "cloud_account_id" {
  default     = ""
  type        = string
  description = "(Optional) Cloud Account ID to limit the usage query"
}

variable "historical_data_to_retain" {
  default     = 30
  type        = number
  description = "(Optional) Number of samples to retain)"
}

variable "lambda_s3_bucket" {
  default     = "pcs-usage-delta"
  type        = string
  description = "(Optional) Bucket to save samples"
}

variable "lambda_s3_object" {
  default     = "pcs-usage-history.csv"
  type        = string
  description = "(Optional) Bucket object to save samples"
}

variable "percent_change_trigger" {
  default     = 10
  type        = number
  description = "(Optional) Percentage to trigger a notification (choices: 1 ... 99)"
}

variable "time_range_amount" {
  default     = 1
  type        = number
  description = "(Optional) Time Range Amount to limit the usage query (choices: 1, 2, 3)"
}

variable "time_range_unit" {
  default     = "month"
  type        = string
  description = "(Optional) Time Range Unit to limit the usage query (choices: 'day', 'week', 'month', 'year')"
}

#### REGION

provider "aws" {
  region = var.aws_region
}

#### LAMBDA

data "archive_file" "pcs_usage_delta_zip" {
  output_path = "/tmp/pcs_usage_delta_lambda.zip"
  type        = "zip"
  source {
    content  = "${path.module}/lambda_function.py"
    filename = "lambda_function.py"
  }
  source {
    content  = "${path.module}/requirements.txt"
    filename = "requirements.txt"
  }
}

data "aws_kms_ciphertext" "pcs_usage_delta_prisma_api_key" {
  key_id    = aws_kms_key.pcs_usage_delta_kms_key.key_id
  plaintext = <<EOF
{
  "PRISMA_ACCESS_KEY": "${var.prisma_access_key}",
  "PRISMA_SECRET_KEY": "${var.prisma_secret_key}"
}
EOF
}

resource "aws_lambda_function" "pcs_usage_delta" {
  description                    = "This function samples (licensable) resource (and workload) counts."
  environment {
    variables = {
      PRISMA_API_ENDPOINT       = var.prisma_api_endpoint,
      PRISMA_API_KEY            = data.aws_kms_ciphertext.pcs_usage_delta_prisma_api_key.ciphertext_blob,
      DEBUG_MODE                = var.debug_mode,
      CLOUD_ACCOUNT_ID          = var.cloud_account_id,
      HISTORICAL_DATA_TO_RETAIN = var.historical_data_to_retain,
      LAMBDA_S3_BUCKET          = var.lambda_s3_bucket,
      LAMBDA_S3_OBJECT          = var.lambda_s3_object,
      PERCENT_CHANGE_TRIGGER    = var.percent_change_trigger,
      TIME_RANGE_AMOUNT         = var.time_range_amount,
      TIME_RANGE_UNIT           = var.time_range_unit
    }
  }
  filename                       = "/tmp/pcs_usage_delta_lambda.zip"
  function_name                  = "pcs_usage_delta"
  handler                        = "lambda_function.lambda_handler"
  kms_key_arn                    = aws_kms_key.pcs_usage_delta_kms_key.arn
  memory_size                    = 128
  package_type                   = "Zip"
  reserved_concurrent_executions = 1
  role                           = aws_iam_role.pcs_usage_delta_role.arn
  runtime                        = "python3.8"
  source_code_hash               = data.archive_file.pcs_usage_delta_zip.output_base64sha256
  tags                           = { storestatus = "dnd" }
  timeout = 59
}

resource "aws_lambda_permission" "cloudwatch_call_pcs_usage_delta" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pcs_usage_delta.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.pcs_usage_delta.arn
  statement_id  = "AllowExecutionFromCloudWatch"
}

#### S3

resource "aws_s3_bucket" "pcs-usage-delta" {
  bucket = "pcs-usage-delta"
  acl    = "private"
  tags   = { storestatus = "dnd" }
}

resource "aws_s3_bucket_public_access_block" "pcs_usage_delta" {
  bucket                  = aws_s3_bucket.pcs-usage-delta.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#### KMS

resource "aws_kms_key" "pcs_usage_delta_kms_key" {
  description         = "KMS Key for encryption and decryption of environment variables."
  enable_key_rotation = true
  tags                = { storestatus = "dnd" }
}

resource "aws_kms_alias" "pcs_usage_delta_kms_key_alias" {
  name          = "alias/pcs_usage_delta_kms_key"
  target_key_id = aws_kms_key.pcs_usage_delta_kms_key.key_id
}

resource "aws_kms_grant" "pcs_usage_delta" {
  name              = "pcs_usage_delta"
  key_id            = aws_kms_key.pcs_usage_delta_kms_key.key_id
  grantee_principal = aws_iam_role.pcs_usage_delta_role.arn
  operations        = ["Decrypt", "DescribeKey"]
}

#### IAM

data "aws_iam_policy_document" "pcs_usage_delta_cloudwatch" {
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_policy" "pcs_usage_delta_cloudwatch_policy" {
  name        = "pcs_usage_delta_cloudwatch_policy"
  description = "Allow writing to CloudWatch"
  path        = "/"
  policy      = data.aws_iam_policy_document.pcs_usage_delta_cloudwatch.json
}

resource "aws_iam_role_policy_attachment" "pcs_usage_delta_cloudwatch" {
  policy_arn = aws_iam_policy.pcs_usage_delta_cloudwatch_policy.arn
  role       = aws_iam_role.pcs_usage_delta_role.name
}

data "aws_iam_policy_document" "pcs_usage_delta_s3" {
  statement {
    actions   = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
    effect    = "Allow"
    resources = ["arn:aws:s3:::pcs-usage-delta", "arn:aws:s3:::pcs-usage-delta/*"]
  }
}

resource "aws_iam_policy" "pcs_usage_delta_s3_policy" {
  name        = "pcs_usage_delta_s3_policy"
  description = "Allow reading and writing to S3"
  policy      = data.aws_iam_policy_document.pcs_usage_delta_s3.json
}

resource "aws_iam_role_policy_attachment" "pcs_usage_delta_s3" {
  policy_arn = aws_iam_policy.pcs_usage_delta_s3_policy.arn
  role       = aws_iam_role.pcs_usage_delta_role.name
}

data "aws_iam_policy_document" "pcs_usage_delta_assume_role" {
  statement {
    actions       = ["sts:AssumeRole"]
    effect        = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pcs_usage_delta_role" {
  name               = "pcs_usage_delta_role"
  assume_role_policy = data.aws_iam_policy_document.pcs_usage_delta_assume_role.json
  tags               = { storestatus = "dnd" }
}

#### CLOUDWATCH

resource "aws_cloudwatch_event_rule" "pcs_usage_delta" {
  name                = "pcs_usage_delta"
  description         = "Trigger sampling of Prisma Cloud license usage"
  schedule_expression = "rate(1 day)"
  tags                = { storestatus = "dnd" }
}

resource "aws_cloudwatch_event_target" "pcs_usage_delta" {
  arn       = aws_lambda_function.pcs_usage_delta.arn
  rule      = aws_cloudwatch_event_rule.pcs_usage_delta.name
  target_id = "pcs_usage_delta"
}

resource "aws_cloudwatch_log_group" "pcs_usage_delta_cloudwatch" {
  name              = "/aws/lambda/${aws_lambda_function.pcs_usage_delta.function_name}"
  retention_in_days = 14
  tags              = { storestatus = "dnd" }
}