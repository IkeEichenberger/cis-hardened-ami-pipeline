provider "aws" {
  profile = var.profile
  region  = var.region
  version = ">= 2.23.0"
}

data "aws_caller_identity" "current" {}

# role that CodeBuild will execute Packer container under
resource "aws_iam_role" "codebuild_hardened_ami" {
  name = "hardened-ami-codebuild-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# policy for CodeBuild Packer container
# see https://www.packer.io/docs/builders/amazon.html#using-an-iam-instance-profile
resource "aws_iam_role_policy" "codebuild_hardened_ami" {
  role = "${aws_iam_role.codebuild_hardened_ami.name}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": [
        "*"
      ],
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
POLICY
}

# CodeBuild project to automate hardened AMI creation
resource "aws_codebuild_project" "codebuild_hardened_ami" {
  name          = "Hardened-AMI"
  description   = "Automated build process for CIS hardened Amazon Linux 2 AMI"
  build_timeout = "20"
  service_role  = "${aws_iam_role.codebuild_hardened_ami.arn}"

  # this assumes source is in preexisting CodeCommit repo but could easily come from various others
  # see https://www.terraform.io/docs/providers/aws/r/codebuild_project.html#source
  source {
    type      = "CODECOMMIT"
    location  = "https://git-codecommit.${var.region}.amazonaws.com/v1/repos/${var.repo}"
    buildspec = "buildspec.yml"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:1.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "hardened-ami"
      stream_name = "build"
    }
  }
}
