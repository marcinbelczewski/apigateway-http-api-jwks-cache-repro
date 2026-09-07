terraform {
  required_version = ">= 1.7, < 2.0"
  required_providers {
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "region" {
  description = "AWS Region for both the API and issuer."
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Resource prefix; use a unique name for parallel deployments."
  type        = string
  default     = "http-api-jwks-repro"
}

provider "aws" {
  region = var.region
}

locals {
  functions = toset(["backend", "issuer"])
  jwks      = file("${path.module}/../.local/jwks.json")
  issuer    = trimsuffix(aws_lambda_function_url.issuer.function_url, "/")
  audience  = "jwks-cache-repro"
}

# Two tiny, dependency-free Lambdas, each allowed to write only its own logs.
data "archive_file" "function" {
  for_each = local.functions

  type        = "zip"
  source_file = "${path.module}/../lambdas/${each.key}.py"
  output_path = "${path.module}/../.local/${each.key}.zip"
}

resource "aws_cloudwatch_log_group" "function" {
  for_each = local.functions

  name              = "/aws/lambda/${var.name}-${each.key}"
  retention_in_days = 14
}

resource "aws_iam_role" "function" {
  for_each = local.functions

  name_prefix = "${var.name}-${each.key}-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "logs" {
  for_each = local.functions

  role = aws_iam_role.function[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.function[each.key].arn}:*"
    }]
  })
}

resource "aws_lambda_function" "function" {
  for_each = local.functions

  function_name    = "${var.name}-${each.key}"
  role             = aws_iam_role.function[each.key].arn
  runtime          = "python3.12"
  handler          = "${each.key}.handler"
  architectures    = ["arm64"]
  timeout          = 10
  filename         = data.archive_file.function[each.key].output_path
  source_code_hash = data.archive_file.function[each.key].output_base64sha256

  environment {
    variables = each.key == "issuer" ? { JWKS_JSON = local.jwks } : {}
  }
  depends_on = [aws_iam_role_policy.logs]
}

# Public discovery/JWKS only. Both permissions are required by Function URLs.
resource "aws_lambda_function_url" "issuer" {
  function_name      = aws_lambda_function.function["issuer"].function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "issuer_url" {
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.function["issuer"].function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "issuer_invoke" {
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.function["issuer"].function_name
  principal                = "*"
  invoked_via_function_url = true
}

resource "aws_apigatewayv2_api" "repro" {
  name          = var.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.repro.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "instrumented-issuer"
  jwt_configuration {
    issuer   = local.issuer
    audience = [local.audience]
  }
  depends_on = [aws_lambda_permission.issuer_url, aws_lambda_permission.issuer_invoke]
}

resource "aws_apigatewayv2_integration" "backend" {
  api_id                 = aws_apigatewayv2_api.repro.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.function["backend"].arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "probe" {
  api_id             = aws_apigatewayv2_api.repro.id
  route_key          = "GET /probe"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
  target             = "integrations/${aws_apigatewayv2_integration.backend.id}"
}

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${var.name}"
  retention_in_days = 14
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.repro.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 10
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn
    format = jsonencode({
      requestId          = "$context.requestId"
      requestTimeEpoch   = "$context.requestTimeEpoch"
      status             = "$context.status"
      responseLatency    = "$context.responseLatency"
      integrationLatency = "$context.integrationLatency"
      authorizerError    = "$context.authorizer.error"
    })
  }
}

resource "aws_lambda_permission" "backend" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.function["backend"].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.repro.execution_arn}/*/GET/probe"
}

output "repro" {
  description = "Public deployment details used by the local runner."
  value = {
    region           = var.region
    api_id           = aws_apigatewayv2_api.repro.id
    authorizer_id    = aws_apigatewayv2_authorizer.jwt.id
    issuer           = local.issuer
    audience         = local.audience
    jwks_sha256      = sha256(local.jwks)
    probe_url        = "${aws_apigatewayv2_api.repro.api_endpoint}/probe"
    access_log_group = aws_cloudwatch_log_group.access.name
    issuer_log_group = aws_cloudwatch_log_group.function["issuer"].name
  }
}
