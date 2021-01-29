terraform {
  required_version = ">= 0.13.0"
}

provider "aws" {
  region = "us-east-1"
}

####

data "archive_file" "pc_usage_delta" {
  source_file = "/Users/tkishel/Code/pcs-inspect/pc-usage-delta.py"
  output_path = "/tmp/lambda.zip"
  type        = "zip"
}

resource "aws_lambda_function" "pc_usage_delta" {
  description                    = "Sample Prisma Cloud license usage"
  environment {
    variables = {
      PRISMA_API_ENDPOINT = "",
      PRISMA_ACCESS_KEY   = "",
      PRISMA_SECRET_KEY   = "",
      CLOUD_ACCOUNT_ID    = ""
    }
  }
  filename                       = "/tmp/lambda.zip"
  function_name                  = "pc_usage_delta"
  handler                        = "lambda_function.lambda_handler"
  memory_size                    = 128
  package_type                   = "Zip"
  reserved_concurrent_executions = 1
  # role                         = "${aws_iam_role.pc_usage_delta.arn}"
  runtime                        = "python3.8"
  source_code_hash               = data.archive_file.pc_usage_delta.output_base64sha256
  tags = {
    storestatus = "dnd"
  }
  timeout = 59
}

####

resource "aws_s3_bucket" "pc_usage_delta" {
  bucket = "pc_usage_delta"
  tags = {
    storestatus = "dnd"
  }
}

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
			"arn:aws:s3:::pc_usage_delta",
			"arn:aws:s3:::pc_usage_delta/*"
		]
	}]
}
EOF
}

####

# ?: Allow Terraform to create the role for the lamdba, and attach the policy to that role.

# resource "aws_iam_role" "pc_usage_delta" {
#   name = "pc_usage_delta"
# }

resource "aws_iam_role_policy_attachment" "pc_usage_delta" {
  # role     = "${aws_iam_role.pc_usage_delta.id}"
  role       = "${aws_lambda_function.pc_usage_delta.role.arn}"
  policy_arn = "${aws_iam_policy.pc_usage_delta.arn}"
}

####

resource "aws_cloudwatch_event_rule" "pc_usage_delta" {
  name                = "pc_usage_delta"
  description         = "Trigger sampling of Prisma Cloud license usage"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "pc_usage_delta" {
  arn       = "${aws_lambda_function.pc_usage_delta.arn}"
  rule      = "${aws_cloudwatch_event_rule.pc_usage_delta.name}"
  target_id = "lambda"
}

resource "aws_cloudwatch_log_group" "pc_usage_delta" {
    name              = "/aws/lambda/${aws_lambda_function.pc_usage_delta.function_name}"
    retention_in_days = 14
}

resource "aws_lambda_permission" "cloudwatch_call_pc_usage_delta_lambda" {
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.pc_usage_delta.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.pc_usage_delta.arn}"
  statement_id  = "AllowExecutionFromCloudWatch"
}