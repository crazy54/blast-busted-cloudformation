# This script will be used to delete AWS CloudFormation stacks.
# It will include logic for AWS authentication, resource fetching, and deletion.

import boto3
import botocore # For ClientError
import argparse
import json
import os
import shutil
from datetime import datetime
import time
import logging # Import logging module

# Global logger instance
logger = logging.getLogger("CfnStackDeleter") # Keep this global for the script's own logging

# Argument parsing function for testability
def parse_arguments(argv):
    parser = argparse.ArgumentParser(
        description="""Deletes an AWS CloudFormation stack and attempts to pre-delete associated resources
that might cause deletion failures (e.g., non-empty S3 buckets, ECR repositories with images,
EC2 instances, EBS volumes, and IAM roles/policies by detaching them from stack resources).""",
        epilog="""Examples:
  python cfn_stack_deleter.py --stack-name my-test-stack --region us-east-1
  python cfn_stack_deleter.py --stack-name my-app-stack --region eu-west-1 --profile my-aws-profile --dry-run
  python cfn_stack_deleter.py --stack-name shared-service --region us-west-2 --role-arn arn:aws:iam::123456789012:role/MyCrossAccountRole

Logs are stored in files named like 'cfn_deleter_<stack_name>_<timestamp>.log' in the current directory.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter # Allows for better formatting of epilog
    )
    parser.add_argument("--stack-name", required=True,
                        help="The name or ARN of the CloudFormation stack to delete.")
    parser.add_argument("--region", required=True,
                        help="The AWS region where the stack exists (e.g., 'us-east-1').")
    parser.add_argument("--dry-run", action="store_true",
                        help="Perform a dry run: show what would be done without making any changes. "
                             "State files might still be saved if a scan is performed.")

    auth_group = parser.add_argument_group('authentication options')
    auth_group.add_argument("--profile",
                            help="The AWS CLI profile to use for authentication. "
                                 "If not specified, default SDK credential chain is used.")
    auth_group.add_argument("--role-arn",
                            help="The ARN of the IAM role to assume for AWS operations (e.g., 'arn:aws:iam::123456789012:role/MyRole'). "
                                 "If provided, the script will attempt to assume this role.")
    auth_group.add_argument("--role-session-name", default="CfnStackDeleterSession",
                            help="An identifier for the assumed role session. Default: '%(default)s'.")

    return parser.parse_args(argv)


def setup_logging(stack_name_for_log, is_dry_run=False): # Added is_dry_run
    """Configures logging for console and file."""
    # Use the global logger instance
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers (if any, e.g., during re-runs in a session)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    # Console Handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter_str = '%(asctime)s - %(levelname)s - %(message)s'
    if is_dry_run: # Prepend [DRY RUN] to console messages if dry_run is true
        formatter_str = '[DRY RUN] ' + formatter_str
    formatter = logging.Formatter(formatter_str)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    dry_run_suffix = "_DRYRUN" if is_dry_run else ""
    log_file_name = f"cfn_deleter_{stack_name_for_log}_{timestamp}{dry_run_suffix}.log"
    try:
        fh = logging.FileHandler(log_file_name)
        fh.setLevel(logging.DEBUG)
        file_formatter_str = '%(asctime)s - %(levelname)s - [%(module)s.%(funcName)s:%(lineno)d] - %(message)s'
        if is_dry_run: # Prepend [DRY RUN] to file messages if dry_run is true
             file_formatter_str = '[DRY RUN] ' + file_formatter_str
        file_formatter = logging.Formatter(file_formatter_str)
        fh.setFormatter(file_formatter)
        logger.addHandler(fh)
        logger.info(f"Detailed logging to file: {log_file_name}") # This will also be prepended in dry run
    except Exception as e:
        logger.error(f"Failed to set up file handler for {log_file_name}: {e}")


def main():
    # Import sys for main execution context if not already there
    import sys
    args = parse_arguments(sys.argv[1:])

    # Setup logging early, using stack_name for the log file
    # Logger is already global, setup_logging will use it.
    setup_logging(args.stack_name, args.dry_run)

    logger.info(f"Script starting for CloudFormation stack: '{args.stack_name}' in region '{args.region}'. Dry run: {args.dry_run}")

    if args.profile and args.role_arn:
        logger.debug("Using --profile to source credentials for --role-arn assumption is an advanced flow.")
        pass

    session_params = {"region_name": args.region}
    account_id = None

    try:
        logger.debug(f"Attempting to establish AWS session. Profile: {args.profile}, Role ARN: {args.role_arn}, Region: {args.region}")
        if args.role_arn:
            logger.info(f"Attempting to assume role: {args.role_arn} with session name: {args.role_session_name}")
            sts_client_params = {"region_name": args.region}
            if args.profile:
                 logger.debug(f"Using profile '{args.profile}' to create STS client for assuming role '{args.role_arn}'.")
                 initial_session = boto3.Session(profile_name=args.profile, region_name=args.region)
                 sts_client = initial_session.client('sts')
            else:
                 logger.debug("Using default credential chain for STS client to assume role.")
                 sts_client = boto3.client('sts', region_name=args.region)

            assumed_role_object = sts_client.assume_role(RoleArn=args.role_arn, RoleSessionName=args.role_session_name)
            credentials = assumed_role_object['Credentials']
            session_params.update({
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken'],
            })
            logger.info(f"Successfully assumed role '{args.role_arn}'.")
        elif args.profile:
            session_params["profile_name"] = args.profile
            logger.info(f"Using AWS CLI profile: '{args.profile}' for the session.")
        else:
            logger.info("Using default AWS SDK credential chain for the session.")

        session = boto3.Session(**session_params)

        cfn_client = session.client("cloudformation")
        s3_client = session.client("s3")
        ecr_client = session.client("ecr")
        ec2_client = session.client("ec2")
        iam_client = session.client("iam")

        identity_client = session.client('sts')
        caller_identity = identity_client.get_caller_identity()
        account_id = caller_identity['Account']
        logger.info(f"Running as: {caller_identity['Arn']} in Account: {account_id}")
        logger.debug("Boto3 session and all AWS service clients initialized successfully.")

    except botocore.exceptions.NoCredentialsError:
        logger.error("No AWS credentials found by Boto3. Please configure your credentials (env vars, shared file, SSO, or instance profile).")
        return
    except botocore.exceptions.ProfileNotFound as e:
        profile_name_err = args.profile or "(AWS_PROFILE env var)"
        logger.error(f"Error: AWS profile '{profile_name_err}' not found. Exception: {e}")
        return
    except botocore.exceptions.NoRegionError as e:
        logger.error(f"Boto3 region error: {e}. Configure region via --region, env var (AWS_REGION/AWS_DEFAULT_REGION), or AWS config file.")
        return
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        logger.error(f"AWS API ClientError during session setup or identity check: {error_code} - {error_message}")
        if error_code == "AccessDenied" and args.role_arn: logger.error("Specific check: Access denied for sts:AssumeRole. Ensure base credentials have permission or role trust policy is correct.")
        elif error_code == "ExpiredToken": logger.error("Specific check: AWS security token is expired. Please refresh your credentials.")
        return
    except Exception as e:
        logger.error(f"An unexpected error occurred during AWS session setup: {e}", exc_info=True)
        return

    try:
        delete_stack(cfn_client, s3_client, ecr_client, ec2_client, iam_client,
                     args.stack_name, args.region, account_id, args.dry_run) # Pass dry_run
        logger.info(f"Script execution for stack '{args.stack_name}' completed.")
    except Exception as e:
        logger.error(f"An unhandled exception occurred during delete_stack operation: {e}", exc_info=True)
        logger.info(f"Script execution for stack '{args.stack_name}' failed.")


def get_stack_resources(cfn_client, stack_name):
    logger.info(f"Listing resources and details for stack '{stack_name}'...")
    stack_id = None
    try:
        stack_description_response = cfn_client.describe_stacks(StackName=stack_name)
        if not stack_description_response.get('Stacks'):
            logger.warning(f"Stack '{stack_name}' not found by describe_stacks.")
            return None, None
        stack_info = stack_description_response['Stacks'][0]
        stack_id = stack_info['StackId']
        logger.info(f"Successfully described stack. Stack ID: {stack_id}, Status: {stack_info.get('StackStatus')}")
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if "does not exist" in str(e).lower() or "stacknotfound" in str(e).lower() or error_code == "ValidationError":
            logger.warning(f"Stack '{stack_name}' does not exist or is an invalid name (describe_stacks). Error: {e}")
        elif error_code == "AccessDenied":
            logger.error(f"Access denied for describe_stacks on '{stack_name}'. Error: {e}")
        else:
            logger.error(f"AWS ClientError describing stack '{stack_name}': {e}", exc_info=True)
        return None, None

    detailed_resources = []
    next_token = None
    try:
        logger.debug(f"Listing all resources for stack '{stack_name}' (ID: {stack_id})...")
        while True:
            response = cfn_client.list_stack_resources(StackName=stack_id, NextToken=next_token) if next_token else cfn_client.list_stack_resources(StackName=stack_id)
            for summary in response.get('StackResourceSummaries', []):
                detailed_resources.append({
                    'LogicalResourceId': summary.get('LogicalResourceId'),
                    'PhysicalResourceId': summary.get('PhysicalResourceId'),
                    'ResourceType': summary.get('ResourceType'),
                    'ResourceStatus': summary.get('ResourceStatus'),
                    'DriftInformationSummary': summary.get('DriftInformationSummary', {'StackResourceDriftStatus': 'NOT_CHECKED'})
                })
            next_token = response.get('NextToken')
            if not next_token: break
        logger.info(f"Found {len(detailed_resources)} resources for stack '{stack_name}'.")
        return detailed_resources, stack_id
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "AccessDenied":
            logger.error(f"Access denied listing resources for stack '{stack_name}'. Error: {e}")
        else:
            logger.error(f"AWS ClientError listing resources for stack '{stack_name}': {e}", exc_info=True)
        return None, stack_id
    except Exception as e:
        logger.error(f"Unexpected error listing stack resources for '{stack_name}': {e}", exc_info=True)
        return None, stack_id

STATE_FILE_PREFIX = "cfn_deleter_state_"
def get_state_filename(stack_name): return f"{STATE_FILE_PREFIX}{stack_name}.json"

def save_state(stack_name, stack_id, resources, dry_run=False): # Added dry_run
    if dry_run:
        logger.info(f"[DRY RUN] Would save state for stack '{stack_name}' if not in dry run mode.")
        return
    filename = get_state_filename(stack_name)
    state = { "stack_name": stack_name, "stack_id": stack_id, "last_saved_utc": datetime.utcnow().isoformat(), "resources": resources }
    try:
        with open(filename, 'w') as f: json.dump(state, f, indent=2)
        logger.info(f"State saved for stack '{stack_name}' to {filename}")
    except IOError as e: logger.error(f"Error saving state to {filename}: {e}", exc_info=True)

def load_state(stack_name):
    filename = get_state_filename(stack_name)
    if not os.path.exists(filename):
        logger.debug(f"State file {filename} not found.")
        return None
    try:
        with open(filename, 'r') as f: state = json.load(f)
        logger.info(f"State loaded for stack '{stack_name}' from {filename}")
        return state
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error loading state from {filename}: {e}. It might be corrupted.", exc_info=True)
        return None

def backup_state_file(stack_name, dry_run=False): # Added dry_run
    if dry_run: # No actual file operations in dry run
        logger.info(f"[DRY RUN] Would backup state file for {stack_name} if one exists and not in dry run mode.")
        return
    filename = get_state_filename(stack_name)
    if os.path.exists(filename):
        backup_filename = f"{filename}.{datetime.now().strftime('%Y%m%d%H%M%S')}.bak"
        try:
            shutil.move(filename, backup_filename)
            logger.info(f"Backed up existing state file to {backup_filename}")
        except shutil.Error as e: logger.error(f"Error backing up state file {filename}: {e}", exc_info=True)

def delete_stack(cfn_client, s3_client, ecr_client, ec2_client, iam_client,
                 stack_name, region, account_id, dry_run=False): # Added dry_run
    logger.info(f"Initiating deletion for stack '{stack_name}' in {region} (Account: {account_id}). DRY RUN: {dry_run}")
    stack_resources = None
    stack_id = None
    loaded_state = load_state(stack_name) # load_state doesn't need dry_run, it's read-only
    if loaded_state:
        logger.info(f"Found state for '{loaded_state['stack_name']}' (ID: {loaded_state.get('stack_id', 'N/A')}, {len(loaded_state['resources'])} resources, saved {loaded_state.get('last_saved_utc', 'N/A')}).")
        while True:
            raw_choice = input("Resume with saved state (R), or Re-scan all resources (S)? ")
            choice = raw_choice.strip().upper()
            if choice in ['R', 'S']:
                logger.info(f"User chose: {choice}")
                break
            print("Invalid choice. Please enter 'R' or 'S'.") # Keep print for direct user feedback
        if choice == 'R':
            logger.info("Resuming with loaded state.")
            stack_resources = loaded_state['resources']
            stack_id = loaded_state.get('stack_id')
        else:
            logger.info("Re-scanning. Backing up old state...")
            backup_state_file(stack_name, dry_run) # Pass dry_run

    if stack_resources is None:
        logger.info("-" * 50 + "\nStep 1: Retrieving stack resource details from AWS...")
        fetched_resources, fetched_stack_id = get_stack_resources(cfn_client, stack_name)
        if fetched_resources is None:
            logger.error("Halting: Failed to retrieve resources.")
            return
        stack_resources = fetched_resources
        stack_id = fetched_stack_id
        if stack_id: save_state(stack_name, stack_id, stack_resources, dry_run) # Pass dry_run

    if not stack_resources:
        logger.info(f"No resources found for stack '{stack_name}' (ID: {stack_id or 'N/A'}). Might be empty or already deleted.")
    else:
        logger.info(f"\nDiscovered resources for stack '{stack_name}' (ID: {stack_id or 'N/A'}):")
        # Display resource summary
        print("\n" + "="*20 + " STACK RESOURCE SUMMARY " + "="*20) # Use print for direct visibility
        for res in stack_resources:
            drift_status = res.get('DriftInformationSummary', {}).get('StackResourceDriftStatus', 'N/A')
            print(f"  - LogicalID: {res['LogicalResourceId']}")
            print(f"    PhysicalID: {res.get('PhysicalResourceId', 'N/A')}")
            print(f"    Type: {res['ResourceType']}")
            print(f"    Status: {res['ResourceStatus']}")
            print(f"    Drift: {drift_status}")
            print("    " + "-"*30)
        print("="*62 + "\n")


    logger.info("\nStep 2: Identifying resources for pre-processing...")
    clients = { "s3": s3_client, "ecr": ecr_client, "ec2": ec2_client, "iam": iam_client, "cfn": cfn_client }
    resource_handlers = {
        "AWS::S3::Bucket": handle_s3_bucket, "AWS::ECR::Repository": handle_ecr_repository,
        "AWS::EC2::Instance": handle_ec2_instance, "AWS::EC2::Volume": handle_ec2_volume,
        "AWS::IAM::Role": handle_iam_role, "AWS::IAM::Policy": handle_iam_policy,
    }

    resources_to_preprocess = []
    if stack_resources:
        for resource in stack_resources:
            if resource['ResourceType'] in resource_handlers:
                resources_to_preprocess.append(resource)

    if resources_to_preprocess:
        logger.info("The following resources will be targeted by pre-processing handlers:")
        for res in resources_to_preprocess:
            logger.info(f"  - {res['LogicalResourceId']} (Type: {res['ResourceType']}, PhysicalID: {res.get('PhysicalResourceId', 'N/A')})")
    else:
        logger.info("No resources identified for specific pre-processing handlers.")

    # Confirmation Prompt
    print("\n" + "="*20 + " CONFIRMATION REQUIRED " + "="*20) # Print for visibility
    if dry_run:
        print("This is a DRY RUN. No actual changes will be made to your resources or the stack.")
        prompt_message = "Proceed to show proposed actions? (yes/no): "
    else:
        print("WARNING: The script will attempt to modify/delete the resources listed above and then delete the stack.")
        prompt_message = f"Are you sure you want to proceed with these actions on stack '{stack_name}'? This is irreversible. (yes/no): "

    confirm_input = input(prompt_message).strip().lower()
    logger.info(f"User confirmation input: '{confirm_input}'")
    if confirm_input != "yes":
        logger.info("User did not confirm. Exiting script without performing destructive actions.")
        return

    logger.info("User confirmed. Proceeding with actions.")
    logger.info("\nStep 2a: Executing pre-processing for identified resources...")
    processed_count = 0
    if stack_resources: # Re-check as it might be empty
        for resource in stack_resources: # Iterate all, handlers will pick based on type
            handler = resource_handlers.get(resource['ResourceType'])
            if handler:
                pid = resource.get('PhysicalResourceId')
                lid = resource.get('LogicalResourceId')
                rtype = resource.get('ResourceType')
                logger.debug(f"Calling handler for resource type: {rtype} - {lid}")
                if not pid:
                    logger.warning(f"Skipping {lid} (Type: {rtype}): no PhysicalResourceId.")
                    continue
                logger.info(f"Pre-processing {lid} (Type: {rtype}, ID: {pid})")
                try:
                    handler(clients, resource, stack_resources, stack_name, region, account_id, dry_run) # Pass dry_run
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error pre-processing {pid} (Type: {rtype}): {e}. Continuing...", exc_info=True)
        logger.info(f"Finished pre-processing. {processed_count} resources had specific handlers called.")
    else: logger.info("No resources in stack to pre-process.")


    logger.info(f"\nStep 3: Deleting CloudFormation stack '{stack_name}' (ID: {stack_id or 'N/A'}).")
    if dry_run:
        logger.info(f"[DRY RUN] Would attempt to delete CloudFormation stack '{stack_name}' (ID: {stack_id or 'N/A'}).")
        logger.info("[DRY RUN] Skipping actual stack deletion and waiter.")
        return # End of dry run operations for delete_stack

    try:
        target_id = stack_id if stack_id else stack_name
        try:
            logger.debug(f"Describing stack '{target_id}' before attempting deletion.")
            s_info = cfn_client.describe_stacks(StackName=target_id)['Stacks'][0]
            if s_info['StackStatus'] == 'DELETE_COMPLETE':
                logger.info(f"Stack '{target_id}' already DELETE_COMPLETE.")
                return
            logger.info(f"Stack '{target_id}' status before delete: {s_info['StackStatus']}")
        except botocore.exceptions.ClientError as e:
            if "does not exist" in str(e).lower() or "stacknotfound" in str(e).lower():
                logger.info(f"Stack '{target_id}' already deleted (cannot describe).")
                return
            else: logger.warning(f"Pre-delete describe_stacks failed for '{target_id}': {e}. Proceeding with delete attempt.")

        logger.info(f"Issuing delete_stack command for '{target_id}'.")
        cfn_client.delete_stack(StackName=target_id)
        logger.info(f"Delete request for '{target_id}' submitted. Waiting for completion (up to 1 hour)...")
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(StackName=target_id, WaiterConfig={'Delay': 30, 'MaxAttempts': 120})
        logger.info(f"Stack '{target_id}' deleted successfully.")
    except botocore.exceptions.WaiterError as e:
        logger.error(f"Waiter error for stack '{target_id}' deletion: {e}", exc_info=True)
    except botocore.exceptions.ClientError as e:
        err_code = e.response.get("Error", {}).get("Code")
        if "does not exist" in str(e).lower() or "stacknotfound" in str(e).lower() or ("ValidationError" in err_code and "does not exist" in e.response.get('Error',{}).get('Message','').lower()):
            logger.warning(f"Stack '{stack_name}' (ID: {stack_id or 'N/A'}) not found or already deleted. Error: {e}")
        else: logger.error(f"ClientError deleting stack '{stack_name}' (ID: {stack_id or 'N/A'}): {e}", exc_info=True)
    except Exception as e: logger.error(f"Unexpected error deleting stack '{stack_name}' (ID: {stack_id or 'N/A'}): {e}", exc_info=True)

# --- Resource Handler Signatures Updated to include dry_run ---
def handle_s3_bucket(clients, res_details, stack_res_list, stack_name, region, acc_id, dry_run=False):
    b_name = res_details.get('PhysicalResourceId')
    lid = res_details.get('LogicalResourceId')
    if not b_name: logger.warning(f"S3 Bucket {lid} no PhysicalResourceId. Skip."); return
    logger.debug(f"Calling empty_s3_bucket for {lid} ({b_name}) with dry_run={dry_run}")
    empty_s3_bucket(clients['s3'], b_name, lid, dry_run)

def handle_ecr_repository(clients, res_details, stack_res_list, stack_name, region, acc_id, dry_run=False):
    repo_name = res_details.get('PhysicalResourceId')
    lid = res_details.get('LogicalResourceId')
    if not repo_name: logger.warning(f"ECR Repo {lid} no PhysicalResourceId. Skip."); return
    logger.debug(f"Calling delete_ecr_repository_images for {lid} ({repo_name}) with dry_run={dry_run}")
    delete_ecr_repository_images(clients['ecr'], repo_name, lid, dry_run)

def handle_ec2_instance(clients, res_details, stack_res_list, stack_name, region, acc_id, dry_run=False):
    inst_id = res_details.get('PhysicalResourceId')
    log_id = res_details.get('LogicalResourceId')
    ec2 = clients['ec2']
    if not inst_id: logger.warning(f"EC2 Instance {log_id} no PhysicalResourceId. Skip."); return
    logger.info(f"Handling EC2 Instance: {log_id} (ID: {inst_id})")
    try:
        desc_response = ec2.describe_instances(InstanceIds=[inst_id])
        if not desc_response.get('Reservations'):
             logger.info(f"Instance {inst_id} for {log_id} not found by describe_instances. Likely already terminated.")
             return
        inst_info = desc_response['Reservations'][0]['Instances'][0]

        if inst_info['State']['Name'] in ['terminated', 'shutting-down']:
            logger.info(f"Instance {inst_id} ({log_id}) already {inst_info['State']['Name']}. Skip."); return

        if dry_run:
            logger.info(f"[DRY RUN] Would check and disable termination protection if enabled for {inst_id} ({log_id}).")
            logger.info(f"[DRY RUN] Would terminate instance {inst_id} ({log_id}).")
            return

        term_protection = ec2.describe_instance_attribute(InstanceId=inst_id, Attribute='disableApiTermination')['DisableApiTermination']['Value']
        if term_protection:
            logger.info(f"Disabling termination protection for {inst_id} ({log_id})...")
            ec2.modify_instance_attribute(InstanceId=inst_id, DisableApiTermination={'Value': False})

        logger.info(f"Terminating instance {inst_id} ({log_id})...")
        ec2.terminate_instances(InstanceIds=[inst_id])
        logger.info(f"Termination for {inst_id} ({log_id}) submitted.")
    except botocore.exceptions.ClientError as e:
        if "InvalidInstanceID.NotFound" in str(e): logger.warning(f"EC2 Instance {inst_id} ({log_id}) not found.")
        else: logger.error(f"AWS ClientError EC2 instance {inst_id} ({log_id}): {e}", exc_info=True); raise
    except Exception as e: logger.error(f"Error EC2 instance {inst_id} ({log_id}): {e}", exc_info=True); raise

def handle_ec2_volume(clients, res_details, stack_res_list, stack_name, region, acc_id, dry_run=False):
    vol_id = res_details.get('PhysicalResourceId')
    log_id = res_details.get('LogicalResourceId')
    ec2 = clients['ec2']
    if not vol_id: logger.warning(f"EC2 Volume {log_id} no PhysicalResourceId. Skip."); return
    logger.info(f"Handling EC2 Volume: {log_id} (ID: {vol_id})")
    try:
        vol_desc = ec2.describe_volumes(VolumeIds=[vol_id])
        if not vol_desc.get('Volumes'):
            logger.info(f"Volume {vol_id} ({log_id}) not found. Skipping.")
            return
        vol_info = vol_desc['Volumes'][0]

        if vol_info['State'] in ['deleted', 'deleting']:
            logger.info(f"Volume {vol_id} ({log_id}) already {vol_info['State']}. Skip."); return

        if dry_run:
            if vol_info.get('Attachments'): logger.info(f"[DRY RUN] Would detach volume {vol_id} ({log_id}) from {vol_info['Attachments'][0]['InstanceId']}.")
            logger.info(f"[DRY RUN] Would delete volume {vol_id} ({log_id}).")
            return

        if vol_info.get('Attachments'):
            logger.info(f"Detaching volume {vol_id} ({log_id}) from {vol_info['Attachments'][0]['InstanceId']}...")
            ec2.detach_volume(VolumeId=vol_id)
            waiter = ec2.get_waiter('volume_available')
            logger.info(f"Waiting for volume {vol_id} ({log_id}) to become available...")
            waiter.wait(VolumeIds=[vol_id], WaiterConfig={'Delay': 10, 'MaxAttempts': 30})
            logger.info(f"Volume {vol_id} ({log_id}) is now available.")

        logger.info(f"Deleting volume {vol_id} ({log_id})...")
        ec2.delete_volume(VolumeId=vol_id)
        logger.info(f"Deletion for {vol_id} ({log_id}) submitted.")
    except botocore.exceptions.ClientError as e:
        if "InvalidVolume.NotFound" in str(e): logger.warning(f"EC2 Volume {vol_id} ({log_id}) not found.")
        else: logger.error(f"AWS ClientError EC2 volume {vol_id} ({log_id}): {e}", exc_info=True); raise
    except Exception as e: logger.error(f"Error EC2 volume {vol_id} ({log_id}): {e}", exc_info=True); raise

def handle_iam_role(clients, res_details, stack_res_list, stack_name, region, acc_id, dry_run=False):
    pid = res_details.get('PhysicalResourceId')
    log_id = res_details.get('LogicalResourceId')
    iam = clients['iam']
    if not pid: logger.warning(f"IAM Role {log_id} no PhysicalResourceId. Skip."); return
    r_name = pid if ':' not in pid else pid.split('/')[-1]
    logger.info(f"Handling IAM Role: {log_id} (Name: {r_name})")
    try:
        iam.get_role(RoleName=r_name)

        if dry_run:
            logger.info(f"[DRY RUN] Would list and detach managed policies from {r_name} ({log_id}).")
            logger.info(f"[DRY RUN] Would list and delete inline policies from {r_name} ({log_id}).")
            logger.info(f"[DRY RUN] Would list and remove role {r_name} ({log_id}) from instance profiles.")
            logger.info(f"[DRY RUN] Would delete IAM role {r_name} ({log_id}).")
            return

        for page in iam.get_paginator('list_attached_role_policies').paginate(RoleName=r_name):
            for pol in page.get('AttachedPolicies', []):
                logger.info(f"Detaching managed policy {pol['PolicyArn']} from {r_name} ({log_id})...")
                iam.detach_role_policy(RoleName=r_name, PolicyArn=pol['PolicyArn'])
        for page in iam.get_paginator('list_role_policies').paginate(RoleName=r_name):
            for pol_name in page.get('PolicyNames', []):
                logger.info(f"Deleting inline policy {pol_name} from {r_name} ({log_id})...")
                iam.delete_role_policy(RoleName=r_name, PolicyName=pol_name)
        for page in iam.get_paginator('list_instance_profiles_for_role').paginate(RoleName=r_name):
            for prof in page.get('InstanceProfiles', []):
                prof_name = prof['InstanceProfileName']
                logger.info(f"Removing role {r_name} ({log_id}) from instance profile {prof_name}...")
                iam.remove_role_from_instance_profile(InstanceProfileName=prof_name, RoleName=r_name)

        logger.info(f"Deleting IAM role {r_name} ({log_id})...")
        iam.delete_role(RoleName=r_name)
        logger.info(f"IAM role {r_name} ({log_id}) deleted.")
    except iam.exceptions.NoSuchEntityException: logger.warning(f"IAM Role {r_name} ({log_id}) not found.")
    except iam.exceptions.DeleteConflictException as e: logger.error(f"IAM Role {r_name} ({log_id}) delete conflict: {e}. Might be in use.", exc_info=True); raise
    except Exception as e: logger.error(f"Error IAM role {r_name} ({log_id}): {e}", exc_info=True); raise

def handle_iam_policy(clients, res_details, stack_res_list, stack_name, region, acc_id, dry_run=False):
    pol_arn = res_details.get('PhysicalResourceId')
    log_id = res_details.get('LogicalResourceId')
    iam = clients['iam']
    if not pol_arn: logger.warning(f"IAM Policy {log_id} no PhysicalResourceId. Skip."); return
    logger.info(f"Handling IAM Policy: {log_id} (ARN: {pol_arn})")
    if pol_arn.startswith("arn:aws:iam::aws:policy/"):
        logger.info(f"Policy {pol_arn} ({log_id}) is AWS managed. Skip."); return
    try:
        iam.get_policy(PolicyArn=pol_arn)
        stack_role_names = { (r.get('PhysicalResourceId') if ':' not in r.get('PhysicalResourceId','') else r.get('PhysicalResourceId','').split('/')[-1])
                             for r in stack_res_list if r['ResourceType'] == 'AWS::IAM::Role' and r.get('PhysicalResourceId') }
        logger.debug(f"Policy {pol_arn} ({log_id}). Will detach from stack roles if found: {stack_role_names or 'None in stack'}")

        if dry_run:
            logger.info(f"[DRY RUN] Would list entities for policy {pol_arn} ({log_id}) and detach from stack-specific roles: {stack_role_names or 'None identified'}.")
            logger.info(f"[DRY RUN] Policy {pol_arn} ({log_id}) itself would not be deleted by this script directly.")
            return

        detached_count = 0
        for page in iam.get_paginator('list_entities_for_policy').paginate(PolicyArn=pol_arn):
            for role in page.get('PolicyRoles', []):
                if role['RoleName'] in stack_role_names:
                    logger.info(f"Detaching {pol_arn} ({log_id}) from stack role {role['RoleName']}...")
                    try:
                        iam.detach_role_policy(RoleName=role['RoleName'], PolicyArn=pol_arn)
                        detached_count += 1
                    except Exception as de: logger.error(f"Error detaching {pol_arn} ({log_id}) from {role['RoleName']}: {de}", exc_info=True)
        if detached_count > 0: logger.info(f"Detached {pol_arn} ({log_id}) from {detached_count} stack roles.")
        else: logger.debug(f"Policy {pol_arn} ({log_id}) not found attached to any identified stack roles.")
        logger.info(f"Not deleting policy {pol_arn} ({log_id}) itself. CFN should handle if unattached & stack-specific.")
    except iam.exceptions.NoSuchEntityException: logger.warning(f"IAM Policy {pol_arn} ({log_id}) not found.")
    except Exception as e: logger.error(f"Error IAM policy {pol_arn} ({log_id}): {e}", exc_info=True); raise

def empty_s3_bucket(s3_client, bucket_name, logical_id="N/A", dry_run=False): # Added dry_run
    logger.info(f"Processing S3 bucket: {bucket_name} (Resource: {logical_id})")
    if dry_run:
        logger.info(f"[DRY RUN] Would empty S3 bucket: {bucket_name} (Resource: {logical_id}).")
        return
    try:
        paginator = s3_client.get_paginator('list_object_versions')
        objects_to_delete = {'Objects': []}
        object_count = 0
        logger.debug(f"Listing objects and versions in {bucket_name}...")
        for page in paginator.paginate(Bucket=bucket_name):
            for version_type in ['Versions', 'DeleteMarkers']:
                if version_type in page:
                    for obj in page[version_type]:
                        objects_to_delete['Objects'].append({'Key': obj['Key'], 'VersionId': obj['VersionId']})
                        object_count +=1
            if len(objects_to_delete['Objects']) >= 1000:
                logger.debug(f"Deleting batch of {len(objects_to_delete['Objects'])} objects/versions from {bucket_name}...")
                s3_client.delete_objects(Bucket=bucket_name, Delete=objects_to_delete)
                objects_to_delete = {'Objects': []}
        if len(objects_to_delete['Objects']) > 0:
            logger.debug(f"Deleting final batch of {len(objects_to_delete['Objects'])} objects/versions from {bucket_name}...")
            s3_client.delete_objects(Bucket=bucket_name, Delete=objects_to_delete)
        if object_count > 0: logger.info(f"Successfully emptied S3 bucket: {bucket_name} ({object_count} objects/versions deleted).")
        else: logger.info(f"S3 bucket: {bucket_name} was already empty or had no versions to delete.")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket': logger.warning(f"S3 bucket '{bucket_name}' not found (Resource: {logical_id}).")
        else: logger.error(f"Error emptying S3 bucket '{bucket_name}' (Resource: {logical_id}): {e}", exc_info=True); raise
    except Exception as e: logger.error(f"Error emptying S3 bucket '{bucket_name}' (Resource: {logical_id}): {e}", exc_info=True); raise

def delete_ecr_repository_images(ecr_client, repository_name, logical_id="N/A", dry_run=False): # Added dry_run
    logger.info(f"Processing ECR repository: {repository_name} (Resource: {logical_id})")
    if dry_run:
        logger.info(f"[DRY RUN] Would delete images from ECR repository: {repository_name} (Resource: {logical_id}).")
        return
    try:
        image_ids = []
        paginator = ecr_client.get_paginator('list_images')
        logger.debug(f"Listing images in {repository_name}...")
        for page in paginator.paginate(repositoryName=repository_name):
            if 'imageIds' in page: image_ids.extend(page['imageIds'])
        if not image_ids: logger.info(f"ECR repository '{repository_name}' is already empty (Resource: {logical_id})."); return

        logger.info(f"Found {len(image_ids)} images to delete in {repository_name}.")
        for i in range(0, len(image_ids), 100):
            chunk = image_ids[i:i + 100]
            logger.debug(f"Deleting batch of {len(chunk)} images from '{repository_name}'...")
            ecr_client.batch_delete_image(repositoryName=repository_name, imageIds=chunk)
        logger.info(f"Successfully deleted all images from ECR repository: {repository_name} (Resource: {logical_id}).")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'RepositoryNotFoundException': logger.warning(f"ECR repository '{repository_name}' not found (Resource: {logical_id}).")
        else: logger.error(f"Error deleting images from ECR repository '{repository_name}' (Resource: {logical_id}): {e}", exc_info=True); raise
    except Exception as e: logger.error(f"Error deleting images from ECR repository '{repository_name}' (Resource: {logical_id}): {e}", exc_info=True); raise

if __name__ == "__main__":
    main()
