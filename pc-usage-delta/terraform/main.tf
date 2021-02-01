terraform {
  required_version = ">= 0.13.0"
}

#### REQUIRED VARIABLES/PARAMETERS

variable "aws_region" {
  type = string
}

variable "prisma_api_endpoint" {
  type        = string
  description = "Prisma Cloud API URL (for example: https://api.prismacloud.io)"
}

variable "prisma_access_key" {
  type        = string
  description = "API Access Key"
}

variable "prisma_secret_key" {
  type        = string
  description = "API Secret Key"
}

#### OPTIONAL VARIABLES/PARAMETERS

# See also ../pc-usage-delta.py for defaults.

variable "debug_mode" {
  default     = "false"
  type        = string
  description = "Enable debugging (choices: 'true, 'false')"
}

variable "cloud_account_id" {
  default     = ""
  type        = string
  description = "Cloud Account ID to limit the usage query"
}

variable "historical_data_to_retain" {
  default     = 30
  type        = number
  description = "Number of samples to retain)"
}

variable "lambda_s3_bucket" {
  default     = "pc-usage-delta"
  type        = string
  description = "Bucket to save samples"
}

variable "lambda_s3_object" {
  default     = "pc-usage-history.csv"
  type        = string
  description = "Bucket object to save samples"
}

variable "percent_change_trigger" {
  default     = 10
  type        = number
  description = "Percentage to trigger a notification (choices: 1 ... 99)"
}

variable "time_range_amount" {
  default     = 1
  type        = number
  description = "Time Range Amount to limit the usage query (choices: 1, 2, 3)"
}

variable "time_range_unit" {
  default     = "month"
  type        = string
  description = "Time Range Unit to limit the usage query (choices: 'day', 'week', 'month', 'year')"
}

#### REGION

provider "aws" {
  region = var.aws_region
}

#### LAMBDA FUNCTION

data "archive_file" "pc_usage_delta" {
  source_file = "${path.module}/lambda_function.py"
  output_path = "/tmp/pc_usage_delta_lambda.zip"
  type        = "zip"
}

resource "aws_lambda_function" "pc_usage_delta" {
  description                    = "Sample Prisma Cloud license usage"
  environment {
    variables = {
      PRISMA_API_ENDPOINT       = var.prisma_api_endpoint,
      PRISMA_ACCESS_KEY         = var.prisma_access_key,
      PRISMA_SECRET_KEY         = var.prisma_secret_key,
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
  filename                       = "/tmp/pc_usage_delta_lambda.zip"
  function_name                  = "pc_usage_delta"
  handler                        = "lambda_function.lambda_handler"
  memory_size                    = 128
  package_type                   = "Zip"
  reserved_concurrent_executions = 1
  role                           = aws_iam_role.pc_usage_delta.arn
  runtime                        = "python3.8"
  source_code_hash               = data.archive_file.pc_usage_delta.output_base64sha256
  tags = {
    storestatus = "dnd"
  }
  timeout = 59
}

#### S3 BUCKET

resource "aws_s3_bucket" "pc-usage-delta" {
  bucket = "pc-usage-delta"
  acl    = "private"
  tags = {
    storestatus = "dnd"
  }
}

resource "aws_s3_bucket_public_access_block" "pc_usage_delta" {
  bucket                  = aws_s3_bucket.pc-usage-delta.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#### LAMBDA / S3 POLICY

resource "aws_iam_policy" "pc_usage_delta" {
  name        = "pc_usage_delta"
  description = "Allow reading and writing of usage data to S3"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Action": [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket"
    ],
    "Effect": "Allow",
    "Resource": [
      "arn:aws:s3:::pc-usage-delta",
      "arn:aws:s3:::pc-usage-delta/*"
    ]
  }]
}
EOF
}

resource "aws_iam_role_policy_attachment" "pc_usage_delta" {
  policy_arn = aws_iam_policy.pc_usage_delta.arn
  role     = aws_iam_role.pc_usage_delta.name
}

#### LAMBDA / CLOUDWATCH POLICY

resource "aws_iam_policy" "pc_usage_delta_logging" {
  name        = "pc_usage_delta_logging"
  description = "Allow writing of log data to CloudWatch"
  path        = "/"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "pc_usage_delta_logging" {
  policy_arn = aws_iam_policy.pc_usage_delta_logging.arn
  role       = aws_iam_role.pc_usage_delta.name
}

resource "aws_cloudwatch_log_group" "pc_usage_delta" {
  name              = "/aws/lambda/${aws_lambda_function.pc_usage_delta.function_name}"
  retention_in_days = 14
  tags = {
    storestatus = "dnd"
  }
}

#### LAMBDA ROLE WITH POLICY

resource "aws_iam_role" "pc_usage_delta" {
  name = "pc_usage_delta"
  assume_role_policy = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Action": "sts:AssumeRole",
     "Principal": {
       "Service": "lambda.amazonaws.com"
     },
     "Effect": "Allow"
   }
 ]
}
EOF
  tags = {
    storestatus = "dnd"
  }
}

#### CLOUDWATCH

resource "aws_cloudwatch_event_rule" "pc_usage_delta" {
  name                = "pc_usage_delta"
  description         = "Trigger sampling of Prisma Cloud license usage"
  schedule_expression = "rate(1 day)"
  tags = {
    storestatus = "dnd"
  }
}

####

resource "aws_cloudwatch_event_target" "pc_usage_delta" {
  arn       = aws_lambda_function.pc_usage_delta.arn
  rule      = aws_cloudwatch_event_rule.pc_usage_delta.name
  target_id = "lambda"
}

####

resource "aws_lambda_permission" "cloudwatch_call_pc_usage_delta_lambda" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pc_usage_delta.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.pc_usage_delta.arn
  statement_id  = "AllowExecutionFromCloudWatch"
}