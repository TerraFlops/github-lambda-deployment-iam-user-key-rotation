locals {
  github_repository = replace(var.github_repository, "_", "-")
  github_repository_snake = join("", [ for element in split("-", local.github_repository): title(lower(element)) ])
  iam_username = "GithubDeployment${local.github_repository_snake}"
}

# Grab the current account ID and region
data "aws_caller_identity" "default" {}
data "aws_region" "default" {}

module "github_iam_user_rotate" {
  source = "git::https://github.com/TerraFlops/aws-lambda-python.git?ref=v2.10"
  lambda_name = "github-iam-user-key-rotate-${local.github_repository}"
  lambda_description = "Lambda function to rotate GitHub IAM user access key/secret"
  lambda_path = "${path.module}/src"
  lambda_handler = "handler.handler"
  lambda_python_version = "3.8"
  lambda_iam_role_arn = aws_iam_role.github_iam_user_rotate.arn
  lambda_memory = 128
  lambda_timeout = 300
  lambda_cloudwatch_encryption_enabled = true
  lambda_subnet_ids = null
  lambda_security_group_ids = null
  ignore_changes = true
  lambda_environment_variables = {
    iam_username = aws_iam_user.github_deployment.name
    github_organization = var.github_organization
    github_repository = var.github_repository
    github_token_ssm_parameter_name = var.github_token_ssm_parameter_name
    github_environment = var.github_environment
  }
}

resource "aws_iam_user" "github_deployment" {
  name = local.iam_username
}

resource "aws_iam_group" "github_deployment" {
  name = local.iam_username
}

resource "aws_iam_policy" "github_deployment" {
  name = local.iam_username
  description = "GitHub Actions deployment policy"
  policy = data.aws_iam_policy_document.github_deployment.json
}

resource "aws_iam_group_policy" "github_deployment" {
  name = local.iam_username
  group = aws_iam_group.github_deployment.name
  policy = data.aws_iam_policy_document.github_deployment.json
}

resource "aws_iam_group_membership" "github_deployment" {
  group = aws_iam_group.github_deployment.name
  name = local.iam_username
  users = [
    aws_iam_user.github_deployment.name
  ]
}

# Grant the user full control over the ECR repositories for the backend in this account
data "aws_iam_policy_document" "github_deployment" {
  version = "2012-10-17"
  statement {
    effect = "Allow"
    actions = ["lambda:*"]
    resources = var.lambda_function_arns
  }
  statement {
    effect = "Allow"
    actions = [
      "logs:GetLogEvents",
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "lambda:*"
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParametersByPath",
      "ssm:PutParameter"
    ]
    resources = ["*"]
  }
  statement {
    effect = "Allow"
    actions = [
      "iam:PassRole"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "github_iam_user_rotate" {
  name = local.iam_username
  assume_role_policy = data.aws_iam_policy_document.github_iam_user_rotate_assume_role.json
}

data "aws_iam_policy_document" "github_iam_user_rotate_assume_role" {
  version = "2012-10-17"
  statement {
    actions = ["sts:AssumeRole"]
    effect = "Allow"
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type = "Service"
    }
  }
}

resource "aws_iam_role_policy" "github_iam_user_rotate" {
  name = local.iam_username
  role = aws_iam_role.github_iam_user_rotate.name
  policy = data.aws_iam_policy_document.github_iam_user_rotate.json
}

data "aws_iam_policy_document" "github_iam_user_rotate" {
  version = "2012-10-17"
  statement {
    sid = "SsmParameterAccess"
    actions = [
      "ssm:GetParameters",
      "ssm:GetParameter",
      "ssm:GetParametersByPath"
    ]
    effect = "Allow"
    resources = [
      "arn:aws:ssm:${data.aws_region.default.name}:${data.aws_caller_identity.default.account_id}:parameter/${trim(var.github_token_ssm_parameter_name, "/")}" ]
  }
  statement {
    sid = "AccessKeyAccess"
    actions = [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:ListAccessKeys"
    ]
    effect = "Allow"
    resources = [
      aws_iam_user.github_deployment.arn
    ]
  }
}

# Schedule Lambda execution every 6 hours
resource "aws_cloudwatch_event_rule" "github_iam_user_rotate" {
  name = local.iam_username
  description = "Schedule for GitHub IAM key/secret rotation"
  schedule_expression = "rate(24 hours)"
}

resource "aws_cloudwatch_event_target" "github_iam_user_rotate" {
  arn = module.github_iam_user_rotate.lambda_function_arn
  rule = aws_cloudwatch_event_rule.github_iam_user_rotate.name
  target_id = local.iam_username
}

resource "aws_lambda_permission" "github_iam_user_rotate" {
  action = "lambda:InvokeFunction"
  function_name = module.github_iam_user_rotate.lambda_function_arn
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.github_iam_user_rotate.arn
}
