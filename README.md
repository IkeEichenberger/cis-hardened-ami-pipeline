# Hardened AMI Pipeline based on CIS Benchmarks

There are three pieces to the Hardened AMI process. The first is the Terraform config in codebuild.tf. This creates a CodeBuild project associated with a CodeCommit repo along with an IAM role that the CodeBuild container will run under. Second is the buildspec.yml. These are the build instructions that the CodeBuild project will execute whenever a build is started. This runs within a Docker container and in this case installs Packer and then runs Packer. The Packer run is the final piece. It is setup with packer.json and it launches an EC2 instance, runs some partitioning and hardening scripts, and then creates a new AMI from that instance.

This blog post describes the high level process without Terraform or the hardening scripts.
https://aws.amazon.com/blogs/devops/how-to-create-an-ami-builder-with-aws-codebuild-and-hashicorp-packer/

## CIS Benchmark Notes

As of this writing the hardening script addresses over 95% of the CIS Benchmark findings that were present in the underlying Amazon Linux 2 image. While this is much better starting point for securing your EC2 instances it is not necessarily complete. The recommendations could change over time and there may be changes that should be implemented that are not included here. See the TODO lines in scripts/harden.sh for known limitations. The CIS Benchmark that these scripts are based off of can be found under the docs folder.

## Additional Work

This should just be used as the starting point for an automated AMI pipeline. Here are some additional features that should be added if used in a long term production setting:

* Trigger the CodeBuild project based off a commit to the repository, a change to the source AMI and/or on a scheduled basis to ensure it gets the latest patches, etc.
* Automatically delete old AMIs and their snapshots when they are superceded by a new version.
* Test the EC2 instance hardening and fail the creation if it doesn't meet a desired threshold.
* Audit your environment to ensure all EC2 instances are using the correct AMI.
* Add ability to copy the AMI to multiple regions and/or accounts.
