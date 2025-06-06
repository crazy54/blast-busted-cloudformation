# CloudFormation Stack Deleter (cfn-stack-deleter)

## Overview/Description

The CloudFormation Stack Deleter is a Python script designed to assist in the deletion of AWS CloudFormation stacks, particularly those that encounter issues due to lingering resources that CloudFormation itself cannot or will not delete. This tool attempts to pre-emptively identify and remove/clean up these problematic resources before initiating the standard CloudFormation stack deletion process.

Key capabilities include:
*   Handling non-empty S3 buckets.
*   Clearing images from ECR repositories.
*   Terminating associated EC2 instances (including disabling termination protection).
*   Detaching and deleting associated EBS volumes.
*   Cleaning up IAM roles by detaching policies and removing them from instance profiles.
*   Detaching IAM policies from stack-specific roles to aid in their removal.
*   Persistent state saving and loading, allowing resumption of operations.
*   A `--dry-run` mode to preview actions without making changes.
*   Detailed logging to both console and a file.

## !! WARNING: DESTRUCTIVE OPERATIONS !!

**This tool performs DESTRUCTIVE operations on your AWS resources, including deleting S3 objects, ECR images, EC2 instances, EBS volumes, IAM roles, and IAM policies. It is designed to forcefully remove resources to facilitate CloudFormation stack deletion.**

*   **USE WITH EXTREME CAUTION.**
*   **ALWAYS test with the `--dry-run` flag first in any new environment or with any new stack.**
*   **It is highly recommended to test this script on non-production environments until you are thoroughly familiar with its behavior and impact.**
*   **You are solely responsible for any actions taken by this script and any resulting data loss or resource deletion.**
*   **Backup any critical data or resources before using this tool.**
*   **Review the resources and proposed actions carefully during the confirmation prompt.**

## Prerequisites

*   **Python**: Python 3.7 or higher.
*   **AWS Account**: An AWS account with permissions to manage CloudFormation and the resources within the stacks you intend to delete (S3, ECR, EC2, IAM, STS).
*   **AWS CLI (Recommended)**: Configured AWS CLI, especially if you plan to use named profiles or require SSO login capabilities that Boto3 can leverage.
*   **Boto3**: The AWS SDK for Python. This is the primary dependency.

## Installation

1.  **Clone the Repository**:
    ```bash
    git clone <repository_url>  # Replace <repository_url> with the actual URL
    cd cfn-stack-deleter
    ```

2.  **Create a Python virtual environment (recommended)**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

### AWS Authentication

The script uses the standard Boto3 credential resolution chain. You can configure credentials via:

1.  **AWS CLI Named Profiles**:
    Use the `--profile <your-profile-name>` argument. Ensure the profile is configured in your `~/.aws/config` or `~/.aws/credentials` files.
    ```bash
    python cfn_stack_deleter.py --stack-name my-stack --region us-east-1 --profile my-dev-profile
    ```

2.  **IAM Role Assumption**:
    Use the `--role-arn <role-arn-to-assume>` argument. The credentials used to run the script (from default chain or a specified `--profile`) must have `sts:AssumeRole` permission for the target role.
    ```bash
    python cfn_stack_deleter.py --stack-name my-stack --region us-east-1 --role-arn arn:aws:iam::123456789012:role/MyDeletionRole
    ```
    You can also specify `--role-session-name <session-name>` (defaults to "CfnStackDeleterSession").

3.  **Environment Variables**:
    Set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`.

4.  **EC2 Instance Profile**:
    If running on an EC2 instance, the script will automatically use the instance's IAM role if no other credentials are provided.

### IAM Permissions

The IAM user or role executing this script requires extensive permissions to describe and delete various resources across multiple services. Minimally, it would need permissions like:

*   `cloudformation:DescribeStacks`, `cloudformation:ListStackResources`, `cloudformation:DeleteStack`
*   `s3:ListBucketVersions`, `s3:DeleteObject`, `s3:DeleteObjectVersion` (for all objects in target buckets)
*   `ecr:ListImages`, `ecr:BatchDeleteImage`
*   `ec2:DescribeInstances`, `ec2:ModifyInstanceAttribute` (for termination protection), `ec2:TerminateInstances`
*   `ec2:DescribeVolumes`, `ec2:DetachVolume`, `ec2:DeleteVolume`
*   `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:DetachRolePolicy`, `iam:ListRolePolicies`, `iam:DeleteRolePolicy`, `iam:ListInstanceProfilesForRole`, `iam:RemoveRoleFromInstanceProfile`, `iam:DeleteRole`
*   `iam:GetPolicy`, `iam:ListEntitiesForPolicy`, `iam:DetachRolePolicy` (for customer-managed policies)
*   `sts:GetCallerIdentity` (used by the script to display current identity)
*   `sts:AssumeRole` (if using the `--role-arn` feature)

**It is strongly recommended to grant these permissions based on the principle of least privilege and only to trusted entities.** Consider creating a specific IAM role for running this script with only the necessary permissions for the cleanup tasks.

## Usage

```
python cfn_stack_deleter.py --help
```

Below is a representation of the help output:

```
usage: cfn_stack_deleter.py [-h] --stack-name STACK_NAME --region REGION [--dry-run] [--profile PROFILE] [--role-arn ROLE_ARN] [--role-session-name ROLE_SESSION_NAME]

Deletes an AWS CloudFormation stack and attempts to pre-delete associated resources
that might cause deletion failures (e.g., non-empty S3 buckets, ECR repositories with images,
EC2 instances, EBS volumes, and IAM roles/policies by detaching them from stack resources).

options:
  -h, --help            show this help message and exit
  --stack-name STACK_NAME
                        The name or ARN of the CloudFormation stack to delete.
  --region REGION       The AWS region where the stack exists (e.g., 'us-east-1').
  --dry-run             Perform a dry run: show what would be done without making any changes. State files might still be saved if a scan is performed.

authentication options:
  --profile PROFILE     The AWS CLI profile to use for authentication. If not specified, default SDK credential chain is used.
  --role-arn ROLE_ARN   The ARN of the IAM role to assume for AWS operations (e.g., 'arn:aws:iam::123456789012:role/MyRole'). If provided, the script will attempt to assume this role.
  --role-session-name ROLE_SESSION_NAME
                        An identifier for the assumed role session. Default: 'CfnStackDeleterSession'.

Examples:
  python cfn_stack_deleter.py --stack-name my-test-stack --region us-east-1
  python cfn_stack_deleter.py --stack-name my-app-stack --region eu-west-1 --profile my-aws-profile --dry-run
  python cfn_stack_deleter.py --stack-name shared-service --region us-west-2 --role-arn arn:aws:iam::123456789012:role/MyCrossAccountRole

Logs are stored in files named like 'cfn_deleter_<stack_name>_<timestamp>.log' in the current directory.
```

### Common Examples:

1.  **Perform a dry run on a stack:**
    ```bash
    python cfn_stack_deleter.py --stack-name my-problem-stack --region us-east-1 --dry-run
    ```

2.  **Delete a stack using default credentials:**
    ```bash
    python cfn_stack_deleter.py --stack-name my-problem-stack --region us-east-1
    ```
    (After reviewing the dry run and confirming the actions!)

3.  **Delete a stack using a specific AWS profile:**
    ```bash
    python cfn_stack_deleter.py --stack-name my-problem-stack --region us-west-2 --profile my-admin-profile
    ```

4.  **Delete a stack by assuming an IAM role:**
    ```bash
    python cfn_stack_deleter.py --stack-name my-problem-stack --region eu-central-1 --role-arn arn:aws:iam::098765432109:role/StackDeletionRole
    ```

## Features

*   **Handles Problematic Resources**:
    *   `AWS::S3::Bucket`: Empties buckets (all versions and delete markers).
    *   `AWS::ECR::Repository`: Deletes all images.
    *   `AWS::EC2::Instance`: Disables termination protection and terminates instances.
    *   `AWS::EC2::Volume`: Detaches and deletes EBS volumes.
    *   `AWS::IAM::Role`: Detaches managed policies, deletes inline policies, and removes from instance profiles before deleting the role.
    *   `AWS::IAM::Policy`: Detaches customer-managed policies from roles within the same stack to facilitate role deletion. (Does not delete the policy itself.)
*   **State Persistence**: Saves the scanned resource state to a local JSON file (`cfn_deleter_state_<stack_name>.json`). On re-runs, it can load this state and ask the user to resume or re-scan, potentially saving time on large stacks.
*   **Dry Run Mode (`--dry-run`)**: Allows users to see what actions the script *would* take without making any actual changes to AWS resources.
*   **Comprehensive Logging**:
    *   Console output for INFO level messages (and above).
    *   Detailed DEBUG level logging to a file (`cfn_deleter_<stack_name>_<timestamp>.log`).
    *   Log messages clearly indicate when in dry run mode.
*   **User Confirmation**: Displays a summary of resources and planned actions, then requires explicit user confirmation ("yes") before proceeding with any destructive operations.
*   **Flexible Authentication**: Supports AWS named profiles and IAM role assumption.

## How it Works (Simplified)

1.  **Initialization**: Sets up logging and parses command-line arguments. Establishes an AWS session using specified credentials/region.
2.  **State Handling**: Checks for an existing state file (`cfn_deleter_state_<stack_name>.json`). If found, prompts the user to resume or re-scan.
3.  **Resource Discovery**: If not resuming or no state file, it calls `DescribeStacks` (to get Stack ID and verify existence) and `ListStackResources` to get a list of all resources in the stack. This list is then saved to the state file (unless in dry run for the save itself).
4.  **Pre-Deletion Summary & Confirmation**: Displays all discovered resources and highlights those that will be targeted by specific pre-processing handlers. Prompts the user for explicit confirmation before proceeding.
5.  **Resource Pre-Processing**: Iterates through the list of stack resources. If a resource matches a known problematic type (S3, ECR, EC2, IAM), it calls a dedicated handler function for that resource type. These handlers attempt to clean up the resource (e.g., empty a bucket, delete images, terminate an instance). This step respects the `--dry-run` flag.
6.  **CloudFormation Stack Deletion**: After attempting to clean up individual resources, the script calls the standard Boto3 `delete_stack` API for the CloudFormation stack. This step is skipped if in `--dry-run` mode.
7.  **Wait for Completion**: The script waits for the stack deletion to complete using a Boto3 waiter.

## Testing

Unit tests are provided in the `tests/` directory and can be run using:

```bash
python -m unittest discover -s tests
```
The tests use `unittest.mock` to simulate AWS API calls and verify the script's logic without interacting with actual AWS resources.

## Contributing

Contributions are welcome! Please feel free to fork the repository, make your changes, and submit a pull request. For major changes, please open an issue first to discuss.

## License

This project is licensed under the MIT License. (Assuming MIT, if a `LICENSE` file exists with different content, this should be updated).
