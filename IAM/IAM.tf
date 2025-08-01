terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  required_version = ">= 1.3.0"
}

provider "aws" {
  region = "ap-northeast-2"
}

# ---------------------
# 1. CloudTrail (관리형 트레일)
# ---------------------
resource "aws_cloudtrail" "default" {
  depends_on = [
    aws_cloudwatch_log_group.iam_logs,
    aws_iam_role.cloudtrail_cw_role,
    aws_iam_role_policy.cloudtrail_cw_policy
  ]

  name                          = "default"
  s3_bucket_name                = "iam-monitoriing-whs-0724-449"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.iam_logs.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw_role.arn
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::iam-monitoriing-whs-0724-449/"]
    }
  }
}

resource "aws_cloudwatch_log_group" "iam_logs" {
  name              = "/aws/cloudtrail/iam-activity"
  retention_in_days = 30
}

resource "aws_iam_role" "cloudtrail_cw_role" {
  name = "cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cw_policy" {
  name = "cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cw_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = [
        "logs:PutLogEvents",
        "logs:CreateLogStream"
      ],
      Resource = "${aws_cloudwatch_log_group.iam_logs.arn}:*"
    }]
  })
}

# ---------------------
# 2. Metric Filters (3가지 시나리오)
# ---------------------

# 2-1. 크리덴셜 스터핑 
resource "aws_cloudwatch_log_metric_filter" "credential_stuffing_filter" {
  name           = "CredentialStuffingFilter"
  log_group_name = aws_cloudwatch_log_group.iam_logs.name

  pattern = <<PATTERN
{ ($.eventSource = "signin.amazonaws.com") && 
  ( $.awsRegion != "ap-northeast-2" || 
    (
      $.sourceIPAddress != "211.*" &&
      $.sourceIPAddress != "121.128.*" &&
      $.sourceIPAddress != "218.145.*" &&
      $.sourceIPAddress != "59.*" &&
      $.sourceIPAddress != "223.130.*"
    )
  )
}
PATTERN


  metric_transformation {
    name      = "CredentialStuffingMetric"
    namespace = "IAMSecurityMonitoring"
    value     = "1"
  }
}

# 2-2. 제3자 (FederatedUser) 권한 상승
resource "aws_cloudwatch_log_metric_filter" "federated_user_privilege_escalation_filter" {
  name           = "FederatedUserPrivilegeEscalationFilter"
  log_group_name = aws_cloudwatch_log_group.iam_logs.name

  pattern = <<PATTERN
{ 
  ($.userIdentity.type = "FederatedUser") && 
  (
    $.eventName = "AttachUserPolicy" || 
    $.eventName = "AttachRolePolicy" || 
    $.eventName = "PutUserPolicy" || 
    $.eventName = "PutRolePolicy" || 
    $.eventName = "CreatePolicy" || 
    $.eventName = "AssumeRole"
  )
}
PATTERN

  metric_transformation {
    name      = "FederatedUserPrivilegeEscalationMetric"
    namespace = "IAMSecurityMonitoring"
    value     = "1"
  }
}

# 2-3. PassRole 남용 탐지
resource "aws_cloudwatch_log_metric_filter" "passrole_abuse_filter" {
  name           = "PassRoleAbuseFilter"
  log_group_name = aws_cloudwatch_log_group.iam_logs.name

  pattern = <<PATTERN
{ $.eventName = "PassRole" && $.errorCode != "AccessDenied" }
PATTERN

  metric_transformation {
    name      = "PassRoleAbuseMetric"
    namespace = "IAMSecurityMonitoring"
    value     = "1"
  }
}

# 2-4. AssumeRole 권한 상승 이상 탐지
resource "aws_cloudwatch_log_metric_filter" "assumerole_anomaly_filter" {
  name           = "AssumeRoleAnomalyFilter"
  log_group_name = aws_cloudwatch_log_group.iam_logs.name

  pattern = <<PATTERN
{ 
  $.eventName = "AssumeRole" && 
  (
    $.requestParameters.roleArn = "*Admin*" || 
    $.requestParameters.roleArn = "*PowerUser*"
  ) && 
  $.sourceIPAddress != "203.0.113.*" 
}
PATTERN


  metric_transformation {
    name      = "AssumeRoleAnomalyMetric"
    namespace = "IAMSecurityMonitoring"
    value     = "1"
  }
}


# ---------------------
# 3. Metric Alarms
# ---------------------

resource "aws_cloudwatch_metric_alarm" "credential_stuffing_alarm" {
  alarm_name          = "Alarm_CredentialStuffing"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.credential_stuffing_filter.metric_transformation[0].name
  namespace           = "IAMSecurityMonitoring"
  period              = 300
  statistic           = "Sum"
  threshold           = 1

  alarm_description  = "Detects login attempts from non-designated regions or IPs (credential stuffing)"
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "federated_user_privilege_escalation_alarm" {
  alarm_name          = "Alarm_FederatedUserPrivilegeEscalation"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.federated_user_privilege_escalation_filter.metric_transformation[0].name
  namespace           = "IAMSecurityMonitoring"
  period              = 300
  statistic           = "Sum"
  threshold           = 1

  alarm_description  = "Detects suspicious privilege escalation by federated users"
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "passrole_abuse_alarm" {
  alarm_name          = "Alarm_PassRoleAbuse"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.passrole_abuse_filter.metric_transformation[0].name
  namespace           = "IAMSecurityMonitoring"
  period              = 300
  statistic           = "Sum"
  threshold           = 1

  alarm_description  = "Detects PassRole API calls without AccessDenied errors (potential abuse)"
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "assumerole_anomaly_alarm" {
  alarm_name          = "Alarm_AssumeRoleAnomaly"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.assumerole_anomaly_filter.metric_transformation[0].name
  namespace           = "IAMSecurityMonitoring"
  period              = 300
  statistic           = "Sum"
  threshold           = 1

  alarm_description  = "Detects AssumeRole calls for Admin/PowerUser roles from unusual IPs"
  treat_missing_data = "notBreaching"
}

# 합쳐진 PassRole 및 AssumeRole 이상 탐지 복합 알람
resource "aws_cloudwatch_composite_alarm" "passrole_assumerole_combined_alarm" {
  alarm_name = "Alarm_PassRoleAndAssumeRoleAnomaly"
  alarm_rule = "ALARM(${aws_cloudwatch_metric_alarm.passrole_abuse_alarm.alarm_name}) OR ALARM(${aws_cloudwatch_metric_alarm.assumerole_anomaly_alarm.alarm_name})"
}

# ---------------------
# 4. Lambda (Discord 알림)
# ---------------------
resource "aws_lambda_function" "discord_alert" {
  filename         = "./lambda/lambda.zip"
  function_name    = "SendDiscordAlert"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = filebase64sha256("lambda/lambda.zip")
  runtime          = "python3.12"
  timeout          = 10

}

resource "aws_iam_role" "lambda_exec" {
  name = "lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------------------
# 5. EventBridge Rule → Lambda 연결
# ---------------------
resource "aws_cloudwatch_event_rule" "alarm_triggered" {
  name = "AlarmStateChangeRule"

  event_pattern = jsonencode({
    "source": ["aws.cloudwatch"],
    "detail-type": ["CloudWatch Alarm State Change","CloudWatch Composite Alarm State Change"],
    "detail": {
      "state": {
        "value": ["ALARM"]
      },
      "alarmName": [
        "Alarm_CredentialStuffing",
        "Alarm_FederatedUserPrivilegeEscalation",
        "Alarm_AssumeRoleAnomaly",
        "Alarm_PassRoleAbuse",
        "Alarm_PassRoleAndAssumeRoleAnomaly"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "send_to_lambda" {
  rule      = aws_cloudwatch_event_rule.alarm_triggered.name
  target_id = "SendDiscordLambda"
  arn       = aws_lambda_function.discord_alert.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.discord_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alarm_triggered.arn
}

# ---------------------
# CloudTrail용 S3 버킷 정책 추가
# ---------------------
data "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "iam-monitoriing-whs-0724-449"
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = data.aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AWSCloudTrailAclCheck",
        Effect   = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = "arn:aws:s3:::iam-monitoriing-whs-0724-449"
      },
      {
        Sid      = "AWSCloudTrailWrite",
        Effect   = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "arn:aws:s3:::iam-monitoriing-whs-0724-449/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

