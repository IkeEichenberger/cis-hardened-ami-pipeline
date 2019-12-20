# All configuration variables are defined with default values where appropriate.
# These variables can then be set locally in your terraform.tfvars.

variable "profile" {
  description = "Name of profile running Terraform"
  default     = "default"
}

variable "region" {
  description = "Target region"
  type        = "string"
  default     = "us-east-1"
}

variable "repo" {
  description = "Name of CodeCommit repo these configs are stored in"
  type        = "string"
}
