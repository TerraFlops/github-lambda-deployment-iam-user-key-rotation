output "lambda_function_arn" {
  value = module.github_iam_user_rotate.lambda_function_arn
}
output "lambda_function_name" {
  value = module.github_iam_user_rotate.lambda_function_name
}
output "lambda_function_version" {
  value = module.github_iam_user_rotate.lambda_function_version
}
output "iam_user_arn" {
  value = aws_iam_user.github_deployment.arn
}
output "iam_user_name" {
  value = aws_iam_user.github_deployment.name
}
output "iam_role_arn" {
  value = aws_iam_role.github_iam_user_rotate.arn
}
output "iam_role_name" {
  value = aws_iam_role.github_iam_user_rotate.name
}