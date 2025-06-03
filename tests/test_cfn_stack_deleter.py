import unittest
from unittest.mock import patch, mock_open, MagicMock
import argparse
import json
import os # For a few os-related mocks if needed, and for `os.path.exists`
import sys

# Add project root to sys.path to allow importing cfn_stack_deleter
# This assumes the test is run from the project root directory or tests/ directory.
# A more robust solution might involve setting PYTHONPATH or using a proper package structure.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import cfn_stack_deleter # Import the script to be tested

class TestArgParsing(unittest.TestCase):
    def test_required_args(self):
        args = cfn_stack_deleter.parse_arguments(['--stack-name', 'test-stack', '--region', 'us-east-1'])
        self.assertEqual(args.stack_name, 'test-stack')
        self.assertEqual(args.region, 'us-east-1')
        self.assertFalse(args.dry_run) # Default
        self.assertIsNone(args.profile)
        self.assertIsNone(args.role_arn)
        self.assertEqual(args.role_session_name, "CfnStackDeleterSession") # Default

    def test_dry_run(self):
        args = cfn_stack_deleter.parse_arguments(['--stack-name', 's', '--region', 'r', '--dry-run'])
        self.assertTrue(args.dry_run)

    def test_profile(self):
        args = cfn_stack_deleter.parse_arguments(['--stack-name', 's', '--region', 'r', '--profile', 'myprof'])
        self.assertEqual(args.profile, 'myprof')

    def test_role_arn(self):
        args = cfn_stack_deleter.parse_arguments(['--stack-name', 's', '--region', 'r', '--role-arn', 'myarn'])
        self.assertEqual(args.role_arn, 'myarn')

    def test_role_session_name(self):
        args = cfn_stack_deleter.parse_arguments(['--stack-name', 's', '--region', 'r', '--role-session-name', 'customsession'])
        self.assertEqual(args.role_session_name, 'customsession')

    def test_missing_required_args(self):
        # Test that argparse raises SystemExit if required args are missing
        with self.assertRaises(SystemExit):
            cfn_stack_deleter.parse_arguments(['--region', 'us-east-1'])
        with self.assertRaises(SystemExit):
            cfn_stack_deleter.parse_arguments(['--stack-name', 'test-stack'])

class TestStateManagement(unittest.TestCase):
    def setUp(self):
        self.stack_name = "test-stack"
        self.stack_id = "sid-123"
        self.resources = [{"LogicalResourceId": "Res1", "PhysicalResourceId": "Phys1"}]
        self.state_filename = cfn_stack_deleter.get_state_filename(self.stack_name)

    @patch('builtins.open', new_callable=mock_open)
    @patch('cfn_stack_deleter.datetime') # Mock datetime to control timestamp
    def test_save_state_success(self, mock_datetime, mock_file_open):
        mock_datetime.utcnow.return_value.isoformat.return_value = "2023-01-01T12:00:00"
        cfn_stack_deleter.save_state(self.stack_name, self.stack_id, self.resources, dry_run=False)

        mock_file_open.assert_called_once_with(self.state_filename, 'w')
        handle = mock_file_open()

        # Check what was written to the file
        # json.dump(data, handle, indent=2)
        # The first call to write is the data itself, or a part of it.
        # We need to ensure json.dump was called with the correct structure.
        # Since json.dump might write in chunks, we check the call to json.dump itself.

        # For simplicity, let's assume json.dump is called once by mock_open's handle context manager.
        # A more robust way is to patch json.dump directly.

        # Patching json.dump for verification
        with patch('json.dump') as mock_json_dump:
             cfn_stack_deleter.save_state(self.stack_name, self.stack_id, self.resources, dry_run=False)
             expected_state = {
                "stack_name": self.stack_name,
                "stack_id": self.stack_id,
                "last_saved_utc": "2023-01-01T12:00:00",
                "resources": self.resources
            }
             mock_json_dump.assert_called_once_with(expected_state, mock_file_open(), indent=2)


    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='{"stack_name": "test-stack", "resources": []}')
    def test_load_state_success(self, mock_file_open, mock_exists):
        state = cfn_stack_deleter.load_state(self.stack_name)
        mock_exists.assert_called_once_with(self.state_filename)
        mock_file_open.assert_called_once_with(self.state_filename, 'r')
        self.assertEqual(state['stack_name'], 'test-stack')

    @patch('os.path.exists', return_value=False)
    def test_load_state_not_found(self, mock_exists):
        state = cfn_stack_deleter.load_state(self.stack_name)
        mock_exists.assert_called_once_with(self.state_filename)
        self.assertIsNone(state)

    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data='this is not json')
    def test_load_state_corrupted_json(self, mock_file_open, mock_exists):
        state = cfn_stack_deleter.load_state(self.stack_name)
        self.assertIsNone(state) # Should return None on JSONDecodeError

    @patch('os.path.exists', return_value=True)
    @patch('shutil.move') # shutil.move is used in backup_state_file
    @patch('cfn_stack_deleter.datetime')
    def test_backup_state_file(self, mock_datetime_os, mock_shutil_move, mock_os_exists):
        mock_now = MagicMock()
        mock_datetime_os.now.return_value = mock_now
        mock_now.strftime.return_value = "20230101120000"

        cfn_stack_deleter.backup_state_file(self.stack_name, dry_run=False)

        expected_backup_filename = f"{self.state_filename}.20230101120000.bak"
        mock_os_exists.assert_called_once_with(self.state_filename)
        mock_shutil_move.assert_called_once_with(self.state_filename, expected_backup_filename)

    @patch('builtins.open', new_callable=mock_open)
    def test_save_state_dry_run(self, mock_file_open):
        # Test that save_state in dry_run mode does not open/write any file
        cfn_stack_deleter.save_state(self.stack_name, self.stack_id, self.resources, dry_run=True)
        mock_file_open.assert_not_called()

    @patch('shutil.move')
    def test_backup_state_file_dry_run(self, mock_shutil_move):
        # Test that backup_state_file in dry_run mode does not move any file
        cfn_stack_deleter.backup_state_file(self.stack_name, dry_run=True)
        mock_shutil_move.assert_not_called()


class TestLoggingSetup(unittest.TestCase):
    @patch('logging.FileHandler')
    @patch('logging.StreamHandler')
    @patch('logging.getLogger') # Patch getLogger to inspect the one used by the script
    def test_setup_logging_basic(self, mock_getLogger, mock_StreamHandler, mock_FileHandler):
        # Mock the logger instance that will be returned by getLogger
        mock_logger_instance = MagicMock()
        mock_getLogger.return_value = mock_logger_instance

        cfn_stack_deleter.setup_logging("test_stack_log", is_dry_run=False)

        mock_getLogger.assert_called_with("CfnStackDeleter")
        mock_logger_instance.setLevel.assert_called_with(logging.DEBUG)

        self.assertTrue(any(isinstance(call_args[0][0], logging.StreamHandler) for call_args in mock_logger_instance.addHandler.call_args_list))
        self.assertTrue(any(isinstance(call_args[0][0], logging.FileHandler) for call_args in mock_logger_instance.addHandler.call_args_list))

        # Check if FileHandler was called with a path containing the stack name
        mock_FileHandler.assert_called()
        args, kwargs = mock_FileHandler.call_args
        self.assertIn("test_stack_log", args[0])


    @patch('logging.Formatter') # To check formatter string for dry run
    @patch('logging.getLogger')
    def test_setup_logging_dry_run_formatter(self, mock_getLogger, mock_Formatter):
        mock_logger_instance = MagicMock()
        mock_getLogger.return_value = mock_logger_instance

        # Need to capture the handler to check its formatter
        # Mock addHandler to get the handler instance
        mock_stream_handler_instance = MagicMock(spec=logging.StreamHandler)
        mock_file_handler_instance = MagicMock(spec=logging.FileHandler)

        def side_effect_add_handler(handler):
            if isinstance(handler, logging.StreamHandler):
                handler.setFormatter = MagicMock() # Mock setFormatter on the instance
            elif isinstance(handler, logging.FileHandler):
                 handler.setFormatter = MagicMock()

        mock_logger_instance.addHandler = MagicMock(side_effect=side_effect_add_handler)

        with patch('logging.StreamHandler', return_value=mock_stream_handler_instance), \
             patch('logging.FileHandler', return_value=mock_file_handler_instance):
            cfn_stack_deleter.setup_logging("test_stack_log_dry", is_dry_run=True)

        # Check that Formatter was called with a string starting with [DRY RUN] for StreamHandler
        # This is a bit complex due to how formatters are set.
        # A simpler check might be on the formatter string passed to Formatter constructor.

        # mock_Formatter.assert_any_call(unittest.mock.ANY) # Ensure Formatter was called
        # Check if any call to Formatter had a dry run string
        dry_run_formatter_called_for_console = False
        for call in mock_Formatter.call_args_list:
            args, kwargs = call
            if args and args[0].startswith('[DRY RUN] %(asctime)s - %(levelname)s - %(message)s'):
                dry_run_formatter_called_for_console = True
                break
        self.assertTrue(dry_run_formatter_called_for_console, "Dry run formatter for console not found.")


class TestAWSMockingDemonstration(unittest.TestCase): # Renamed for clarity
    @patch('boto3.Session')
    def test_boto3_session_mocking_example(self, MockSession): # Renamed for clarity
        # Configure the mock session and its client
        mock_cfn_client = MagicMock()
        mock_session_instance = MockSession.return_value
        mock_session_instance.client.return_value = mock_cfn_client

        # Example: Mocking describe_stacks
        mock_cfn_client.describe_stacks.return_value = {
            "Stacks": [{"StackName": "test-stack", "StackStatus": "CREATE_COMPLETE", "StackId": "arn:..."}]
        }

        # In a real test, you would call a function from cfn_stack_deleter
        # that uses boto3.Session() and cfn_client.describe_stacks().
        # This test is primarily to show how patching boto3.Session works.

        # Example usage within the test (not calling external code here)
        session_instance = MockSession.return_value # Get the instance of the session
        cfn_mock = MagicMock()
        session_instance.client.return_value = cfn_mock # Make session.client('cloudformation') return our cfn_mock

        cfn_mock.describe_stacks.return_value = {"Stacks": [{"StackId": "id-123"}]}

        # Simulate calling some code that would use this session
        # For instance, if cfn_stack_deleter.some_function_using_session() existed:
        # cfn_stack_deleter.some_function_using_session()

        # Assertions:
        # MockSession.assert_called_once() # If session was expected to be created once
        # session_instance.client.assert_called_with('cloudformation')
        # cfn_mock.describe_stacks.assert_called_with(StackName='some_stack')
        self.assertTrue(True) # Placeholder as this is a demo


class TestResourceHandlers(unittest.TestCase):
    def setUp(self):
        self.mock_clients = {
            's3': MagicMock(),
            'ecr': MagicMock(),
            'ec2': MagicMock(),
            'iam': MagicMock(),
            'cfn': MagicMock()
        }
        self.stack_name = "test-stack"
        self.region = "us-east-1"
        self.account_id = "123456789012"
        self.mock_logger_patch = patch('cfn_stack_deleter.logger') # Patch the logger used by the script
        self.mock_logger = self.mock_logger_patch.start()
        self.addCleanup(self.mock_logger_patch.stop)


    # --- Test handle_s3_bucket (which calls empty_s3_bucket) ---
    def test_handle_s3_bucket_empty(self):
        mock_s3 = self.mock_clients['s3']
        resource_details = {'LogicalResourceId': 'MyBucket', 'PhysicalResourceId': 'bucket-123', 'ResourceType': 'AWS::S3::Bucket'}

        # Paginate returns an iterable, first item is a page, which is a dict
        mock_s3.get_paginator.return_value.paginate.return_value = [{'Versions': [], 'DeleteMarkers': []}]

        cfn_stack_deleter.handle_s3_bucket(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=False)

        mock_s3.get_paginator.assert_called_once_with('list_object_versions')
        mock_s3.get_paginator.return_value.paginate.assert_called_once_with(Bucket='bucket-123')
        mock_s3.delete_objects.assert_not_called() # No objects to delete
        self.mock_logger.info.assert_any_call("Successfully emptied S3 bucket: bucket-123 (0 objects/versions deleted).")


    def test_handle_s3_bucket_with_objects(self):
        mock_s3 = self.mock_clients['s3']
        resource_details = {'LogicalResourceId': 'MyBucket', 'PhysicalResourceId': 'bucket-123', 'ResourceType': 'AWS::S3::Bucket'}

        mock_s3.get_paginator.return_value.paginate.return_value = [
            {'Versions': [{'Key': 'obj1', 'VersionId': 'v1'}]},
            {'DeleteMarkers': [{'Key': 'obj2', 'VersionId': 'v2del'}]}
        ]

        cfn_stack_deleter.handle_s3_bucket(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=False)

        mock_s3.delete_objects.assert_called_once_with(Bucket='bucket-123', Delete={'Objects': [{'Key': 'obj1', 'VersionId': 'v1'}, {'Key': 'obj2', 'VersionId': 'v2del'}]})
        self.mock_logger.info.assert_any_call("Successfully emptied S3 bucket: bucket-123 (2 objects/versions deleted).")

    def test_handle_s3_bucket_no_such_bucket(self):
        mock_s3 = self.mock_clients['s3']
        resource_details = {'LogicalResourceId': 'MyBucket', 'PhysicalResourceId': 'bucket-123', 'ResourceType': 'AWS::S3::Bucket'}

        mock_s3.get_paginator.return_value.paginate.side_effect = botocore.exceptions.ClientError({'Error': {'Code': 'NoSuchBucket', 'Message': 'Not Found'}}, 'ListObjectVersions')

        # empty_s3_bucket should catch this and log, not raise to handler for this specific error
        cfn_stack_deleter.handle_s3_bucket(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.warning.assert_any_call("S3 bucket 'bucket-123' not found (Resource: MyBucket).")

    def test_handle_s3_bucket_dry_run(self):
        mock_s3 = self.mock_clients['s3']
        resource_details = {'LogicalResourceId': 'MyBucket', 'PhysicalResourceId': 'bucket-123', 'ResourceType': 'AWS::S3::Bucket'}

        cfn_stack_deleter.handle_s3_bucket(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=True)

        mock_s3.get_paginator.assert_not_called() # empty_s3_bucket should check dry_run first
        mock_s3.delete_objects.assert_not_called()
        self.mock_logger.info.assert_any_call("[DRY RUN] Would empty S3 bucket: bucket-123 (Resource: MyBucket).")


    # --- Test handle_ecr_repository (which calls delete_ecr_repository_images) ---
    def test_handle_ecr_repo_empty(self):
        mock_ecr = self.mock_clients['ecr']
        resource_details = {'LogicalResourceId': 'MyRepo', 'PhysicalResourceId': 'repo-name', 'ResourceType': 'AWS::ECR::Repository'}
        mock_ecr.get_paginator.return_value.paginate.return_value = [{'imageIds': []}]

        cfn_stack_deleter.handle_ecr_repository(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        mock_ecr.batch_delete_image.assert_not_called()
        self.mock_logger.info.assert_any_call("ECR repository 'repo-name' is already empty (Resource: MyRepo).")

    def test_handle_ecr_repo_with_images(self):
        mock_ecr = self.mock_clients['ecr']
        resource_details = {'LogicalResourceId': 'MyRepo', 'PhysicalResourceId': 'repo-name', 'ResourceType': 'AWS::ECR::Repository'}
        images = [{'imageDigest': 'sha256:123'}, {'imageDigest': 'sha256:456'}]
        mock_ecr.get_paginator.return_value.paginate.return_value = [{'imageIds': images}]

        cfn_stack_deleter.handle_ecr_repository(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        mock_ecr.batch_delete_image.assert_called_once_with(repositoryName='repo-name', imageIds=images)
        self.mock_logger.info.assert_any_call("Successfully deleted all images from ECR repository: repo-name (Resource: MyRepo).")

    def test_handle_ecr_repo_not_found(self):
        mock_ecr = self.mock_clients['ecr']
        resource_details = {'LogicalResourceId': 'MyRepo', 'PhysicalResourceId': 'repo-name', 'ResourceType': 'AWS::ECR::Repository'}
        mock_ecr.get_paginator.return_value.paginate.side_effect = botocore.exceptions.ClientError({'Error': {'Code': 'RepositoryNotFoundException', 'Message': 'Not Found'}}, 'ListImages')

        cfn_stack_deleter.handle_ecr_repository(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.warning.assert_any_call("ECR repository 'repo-name' not found (Resource: MyRepo).")

    def test_handle_ecr_repo_dry_run(self):
        mock_ecr = self.mock_clients['ecr']
        resource_details = {'LogicalResourceId': 'MyRepo', 'PhysicalResourceId': 'repo-name', 'ResourceType': 'AWS::ECR::Repository'}

        cfn_stack_deleter.handle_ecr_repository(self.mock_clients, resource_details, [], self.stack_name, self.region, self.account_id, dry_run=True)
        mock_ecr.get_paginator.assert_not_called()
        mock_ecr.batch_delete_image.assert_not_called()
        self.mock_logger.info.assert_any_call("[DRY RUN] Would delete images from ECR repository: repo-name (Resource: MyRepo).")


    # --- Test handle_ec2_instance ---
    @patch('cfn_stack_deleter.time.sleep', return_value=None) # Mock time.sleep if used by waiters
    def test_handle_ec2_instance_terminates(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyEC2', 'PhysicalResourceId': 'i-123', 'ResourceType': 'AWS::EC2::Instance'}

        mock_ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{'InstanceId': 'i-123', 'State': {'Name': 'running'}}]}]}
        mock_ec2.describe_instance_attribute.return_value = {'DisableApiTermination': {'Value': False}} # Not protected

        cfn_stack_deleter.handle_ec2_instance(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)

        mock_ec2.describe_instances.assert_called_with(InstanceIds=['i-123'])
        mock_ec2.describe_instance_attribute.assert_called_with(InstanceId='i-123', Attribute='disableApiTermination')
        mock_ec2.terminate_instances.assert_called_once_with(InstanceIds=['i-123'])
        self.mock_logger.info.assert_any_call("Termination for i-123 (MyEC2) submitted.")

    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_instance_termination_protected(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyEC2', 'PhysicalResourceId': 'i-123', 'ResourceType': 'AWS::EC2::Instance'}

        mock_ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{'InstanceId': 'i-123', 'State': {'Name': 'running'}}]}]}
        mock_ec2.describe_instance_attribute.return_value = {'DisableApiTermination': {'Value': True}} # IS protected

        cfn_stack_deleter.handle_ec2_instance(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)

        mock_ec2.modify_instance_attribute.assert_called_once_with(InstanceId='i-123', DisableApiTermination={'Value': False})
        mock_ec2.terminate_instances.assert_called_once_with(InstanceIds=['i-123'])
        self.mock_logger.info.assert_any_call("Disabling termination protection for i-123 (MyEC2)...")

    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_instance_already_terminated(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyEC2', 'PhysicalResourceId': 'i-123', 'ResourceType': 'AWS::EC2::Instance'}
        mock_ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{'InstanceId': 'i-123', 'State': {'Name': 'terminated'}}]}]}

        cfn_stack_deleter.handle_ec2_instance(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        mock_ec2.terminate_instances.assert_not_called()
        self.mock_logger.info.assert_any_call("Instance i-123 (MyEC2) already terminated. Skip.")

    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_instance_not_found(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyEC2', 'PhysicalResourceId': 'i-123', 'ResourceType': 'AWS::EC2::Instance'}
        mock_ec2.describe_instances.side_effect = botocore.exceptions.ClientError({'Error': {'Code': 'InvalidInstanceID.NotFound', 'Message': 'Not Found'}}, 'DescribeInstances')

        cfn_stack_deleter.handle_ec2_instance(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.warning.assert_any_call("EC2 Instance i-123 (MyEC2) not found.")
        mock_ec2.terminate_instances.assert_not_called()

    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_instance_dry_run(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyEC2', 'PhysicalResourceId': 'i-123', 'ResourceType': 'AWS::EC2::Instance'}
        mock_ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{'InstanceId': 'i-123', 'State': {'Name': 'running'}}]}]} # Still need to describe for logging

        cfn_stack_deleter.handle_ec2_instance(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=True)
        mock_ec2.modify_instance_attribute.assert_not_called()
        mock_ec2.terminate_instances.assert_not_called()
        self.mock_logger.info.assert_any_call("[DRY RUN] Would check and disable termination protection if enabled for i-123 (MyEC2).")
        self.mock_logger.info.assert_any_call("[DRY RUN] Would terminate instance i-123 (MyEC2).")

    # --- Test handle_ec2_volume ---
    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_volume_deletes_available(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyVol', 'PhysicalResourceId': 'vol-123', 'ResourceType': 'AWS::EC2::Volume'}
        mock_ec2.describe_volumes.return_value = {'Volumes': [{'VolumeId': 'vol-123', 'State': 'available', 'Attachments': []}]}

        cfn_stack_deleter.handle_ec2_volume(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        mock_ec2.detach_volume.assert_not_called()
        mock_ec2.delete_volume.assert_called_once_with(VolumeId='vol-123')
        self.mock_logger.info.assert_any_call("Deletion for vol-123 (MyVol) submitted.")

    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_volume_detaches_then_deletes(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyVol', 'PhysicalResourceId': 'vol-123', 'ResourceType': 'AWS::EC2::Volume'}

        # Initial describe_volumes call
        mock_ec2.describe_volumes.side_effect = [
            {'Volumes': [{'VolumeId': 'vol-123', 'State': 'in-use', 'Attachments': [{'InstanceId': 'i-abc', 'Device': '/dev/sdf'}]}]}, # First call: in-use
            # Subsequent calls for waiter or re-check can be mocked if waiter logic is very specific
            # For this test, assume waiter will eventually see it as 'available'
        ]

        # Mock waiter if used explicitly, or assume detach works and then describe shows available
        mock_waiter = MagicMock()
        mock_ec2.get_waiter.return_value = mock_waiter

        # After detach, volume becomes available
        def describe_volumes_after_detach(*args, **kwargs):
            if kwargs.get('VolumeIds') == ['vol-123']: # Check if it's the describe call we expect
                 return {'Volumes': [{'VolumeId': 'vol-123', 'State': 'available', 'Attachments': []}]}
            return MagicMock() # Default for other calls if any

        # We need to ensure that after detach_volume is called, the next describe_volumes shows 'available'
        # This is tricky with side_effect list if waiter makes multiple calls.
        # Simpler: assume detach works and then we just check delete.
        # The waiter itself calls describe_volumes repeatedly.

        cfn_stack_deleter.handle_ec2_volume(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)

        mock_ec2.detach_volume.assert_called_once_with(VolumeId='vol-123') # Default Force=False is fine
        mock_ec2.get_waiter.assert_called_once_with('volume_available')
        mock_waiter.wait.assert_called_once_with(VolumeIds=['vol-123'], WaiterConfig={'Delay': 10, 'MaxAttempts': 30})
        mock_ec2.delete_volume.assert_called_once_with(VolumeId='vol-123')
        self.mock_logger.info.assert_any_call("Volume vol-123 (MyVol) is now available.")


    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_volume_already_deleted(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyVol', 'PhysicalResourceId': 'vol-123', 'ResourceType': 'AWS::EC2::Volume'}
        mock_ec2.describe_volumes.return_value = {'Volumes': [{'VolumeId': 'vol-123', 'State': 'deleted'}]}

        cfn_stack_deleter.handle_ec2_volume(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        mock_ec2.delete_volume.assert_not_called()
        self.mock_logger.info.assert_any_call("Volume vol-123 (MyVol) already deleted. Skip.")

    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_volume_not_found(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyVol', 'PhysicalResourceId': 'vol-123', 'ResourceType': 'AWS::EC2::Volume'}
        mock_ec2.describe_volumes.side_effect = botocore.exceptions.ClientError({'Error': {'Code': 'InvalidVolume.NotFound', 'Message': 'Not Found'}}, 'DescribeVolumes')

        cfn_stack_deleter.handle_ec2_volume(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.warning.assert_any_call("EC2 Volume vol-123 (MyVol) not found.")
        mock_ec2.delete_volume.assert_not_called()

    @patch('cfn_stack_deleter.time.sleep', return_value=None)
    def test_handle_ec2_volume_dry_run(self, mock_sleep):
        mock_ec2 = self.mock_clients['ec2']
        res_details = {'LogicalResourceId': 'MyVol', 'PhysicalResourceId': 'vol-123', 'ResourceType': 'AWS::EC2::Volume'}
        # Simulate volume is in-use to test both detach and delete dry run logs
        mock_ec2.describe_volumes.return_value = {'Volumes': [{'VolumeId': 'vol-123', 'State': 'in-use', 'Attachments': [{'InstanceId': 'i-abc'}]}]}

        cfn_stack_deleter.handle_ec2_volume(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=True)
        mock_ec2.detach_volume.assert_not_called()
        mock_ec2.delete_volume.assert_not_called()
        self.mock_logger.info.assert_any_call("[DRY RUN] Would detach volume vol-123 (MyVol) from i-abc.")
        self.mock_logger.info.assert_any_call("[DRY RUN] Would delete volume vol-123 (MyVol).")


    # --- Test handle_iam_role ---
    def test_handle_iam_role_simple_delete(self):
        mock_iam = self.mock_clients['iam']
        res_details = {'LogicalResourceId': 'MyRole', 'PhysicalResourceId': 'my-role-name', 'ResourceType': 'AWS::IAM::Role'}

        # Simulate role exists, has no attached/inline policies, no instance profiles
        mock_iam.get_role.return_value = {'Role': {'RoleName': 'my-role-name'}} # Exists
        mock_iam.get_paginator.side_effect = lambda PaginatorName: MagicMock(paginate=MagicMock(return_value=[])) # No items for any paginator

        cfn_stack_deleter.handle_iam_role(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)

        mock_iam.get_role.assert_called_once_with(RoleName='my-role-name')
        mock_iam.delete_role.assert_called_once_with(RoleName='my-role-name')
        self.mock_logger.info.assert_any_call("IAM role my-role-name (MyRole) deleted.")

    def test_handle_iam_role_with_policies_and_profile(self):
        mock_iam = self.mock_clients['iam']
        res_details = {'LogicalResourceId': 'MyRole', 'PhysicalResourceId': 'arn:aws:iam::123:role/complex-role', 'ResourceType': 'AWS::IAM::Role'}

        mock_iam.get_role.return_value = {'Role': {'RoleName': 'complex-role'}}

        # Mock paginators
        mock_list_attached_policies_pager = MagicMock()
        mock_list_attached_policies_pager.paginate.return_value = [{'AttachedPolicies': [{'PolicyArn': 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'}]}]

        mock_list_role_policies_pager = MagicMock()
        mock_list_role_policies_pager.paginate.return_value = [{'PolicyNames': ['my-inline-policy']}]

        mock_list_instance_profiles_pager = MagicMock()
        mock_list_instance_profiles_pager.paginate.return_value = [{'InstanceProfiles': [{'InstanceProfileName': 'my-instance-profile'}]}]

        def paginator_side_effect(PaginatorName):
            if PaginatorName == 'list_attached_role_policies': return mock_list_attached_policies_pager
            if PaginatorName == 'list_role_policies': return mock_list_role_policies_pager
            if PaginatorName == 'list_instance_profiles_for_role': return mock_list_instance_profiles_pager
            return MagicMock(paginate=MagicMock(return_value=[])) # Default for others
        mock_iam.get_paginator.side_effect = paginator_side_effect

        cfn_stack_deleter.handle_iam_role(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)

        mock_iam.detach_role_policy.assert_called_once_with(RoleName='complex-role', PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess')
        mock_iam.delete_role_policy.assert_called_once_with(RoleName='complex-role', PolicyName='my-inline-policy')
        mock_iam.remove_role_from_instance_profile.assert_called_once_with(InstanceProfileName='my-instance-profile', RoleName='complex-role')
        mock_iam.delete_role.assert_called_once_with(RoleName='complex-role')

    def test_handle_iam_role_not_found(self):
        mock_iam = self.mock_clients['iam']
        res_details = {'LogicalResourceId': 'MyRole', 'PhysicalResourceId': 'my-role-name', 'ResourceType': 'AWS::IAM::Role'}
        mock_iam.get_role.side_effect = mock_iam.exceptions.NoSuchEntityException({'Error': {'Code': 'NoSuchEntity', 'Message': 'Not Found'}}, 'GetRole')

        cfn_stack_deleter.handle_iam_role(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.warning.assert_any_call("IAM Role my-role-name (MyRole) not found.")
        mock_iam.delete_role.assert_not_called()

    def test_handle_iam_role_delete_conflict(self):
        mock_iam = self.mock_clients['iam']
        res_details = {'LogicalResourceId': 'MyRole', 'PhysicalResourceId': 'my-role-name', 'ResourceType': 'AWS::IAM::Role'}
        mock_iam.get_role.return_value = {'Role': {'RoleName': 'my-role-name'}}
        mock_iam.get_paginator.side_effect = lambda PaginatorName: MagicMock(paginate=MagicMock(return_value=[]))
        mock_iam.delete_role.side_effect = mock_iam.exceptions.DeleteConflictException({'Error': {'Code': 'DeleteConflict', 'Message': 'Conflict'}}, 'DeleteRole')

        with self.assertRaises(botocore.exceptions.ClientError): # Expecting it to re-raise
             cfn_stack_deleter.handle_iam_role(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.error.assert_any_call("IAM Role my-role-name (MyRole) delete conflict: An error occurred (DeleteConflict) when calling the DeleteRole operation: Conflict. Might be in use.", exc_info=True)


    def test_handle_iam_role_dry_run(self):
        mock_iam = self.mock_clients['iam']
        res_details = {'LogicalResourceId': 'MyRole', 'PhysicalResourceId': 'my-role-name', 'ResourceType': 'AWS::IAM::Role'}
        mock_iam.get_role.return_value = {'Role': {'RoleName': 'my-role-name'}} # Role needs to "exist" for dry run to list things

        cfn_stack_deleter.handle_iam_role(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=True)

        mock_iam.detach_role_policy.assert_not_called()
        mock_iam.delete_role_policy.assert_not_called()
        mock_iam.remove_role_from_instance_profile.assert_not_called()
        mock_iam.delete_role.assert_not_called()
        self.mock_logger.info.assert_any_call("[DRY RUN] Would list and detach managed policies from my-role-name (MyRole).")
        self.mock_logger.info.assert_any_call("[DRY RUN] Would list and delete inline policies from my-role-name (MyRole).")
        self.mock_logger.info.assert_any_call("[DRY RUN] Would list and remove role my-role-name (MyRole) from instance profiles.")
        self.mock_logger.info.assert_any_call("[DRY RUN] Would delete IAM role my-role-name (MyRole).")


    # --- Test handle_iam_policy ---
    def test_handle_iam_policy_aws_managed_skipped(self):
        mock_iam = self.mock_clients['iam']
        res_details = {'LogicalResourceId': 'MyManagedPolicy', 'PhysicalResourceId': 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess', 'ResourceType': 'AWS::IAM::Policy'}

        cfn_stack_deleter.handle_iam_policy(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.info.assert_any_call("Policy arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess (MyManagedPolicy) is AWS managed. Skip.")
        mock_iam.get_policy.assert_not_called() # Should skip before this

    def test_handle_iam_policy_not_found(self):
        mock_iam = self.mock_clients['iam']
        policy_arn = f'arn:aws:iam::{self.account_id}:policy/MyCustomPolicy'
        res_details = {'LogicalResourceId': 'MyCustomPolicy', 'PhysicalResourceId': policy_arn, 'ResourceType': 'AWS::IAM::Policy'}
        mock_iam.get_policy.side_effect = mock_iam.exceptions.NoSuchEntityException({'Error': {'Code': 'NoSuchEntity', 'Message': 'Not Found'}}, 'GetPolicy')

        cfn_stack_deleter.handle_iam_policy(self.mock_clients, res_details, [], self.stack_name, self.region, self.account_id, dry_run=False)
        self.mock_logger.warning.assert_any_call(f"IAM Policy {policy_arn} (MyCustomPolicy) not found.")
        mock_iam.list_entities_for_policy.assert_not_called()

    def test_handle_iam_policy_detach_from_stack_roles(self):
        mock_iam = self.mock_clients['iam']
        policy_arn = f'arn:aws:iam::{self.account_id}:policy/MyCustomPolicy'
        res_details = {'LogicalResourceId': 'MyPol', 'PhysicalResourceId': policy_arn, 'ResourceType': 'AWS::IAM::Policy'}

        # Simulate stack_resources_list containing roles
        stack_resources = [
            {'ResourceType': 'AWS::IAM::Role', 'PhysicalResourceId': 'stack-role-1'},
            {'ResourceType': 'AWS::IAM::Role', 'PhysicalResourceId': 'arn:aws:iam::123:role/stack-role-2'}, # Test ARN parsing for roles too
            {'ResourceType': 'AWS::S3::Bucket', 'PhysicalResourceId': 'some-bucket'} # Other resource
        ]

        mock_iam.get_policy.return_value = {'Policy': {'Arn': policy_arn, 'AttachmentCount': 2}}

        # Simulate policy attached to stack-role-1, stack-role-2 and an external role
        mock_entities_pager = MagicMock()
        mock_entities_pager.paginate.return_value = [{'PolicyRoles': [
            {'RoleName': 'stack-role-1'},
            {'RoleName': 'stack-role-2'},
            {'RoleName': 'external-role'}
        ]}]
        mock_iam.get_paginator.return_value = mock_entities_pager

        cfn_stack_deleter.handle_iam_policy(self.mock_clients, res_details, stack_resources, self.stack_name, self.region, self.account_id, dry_run=False)

        # Assert detach called only for stack roles
        mock_iam.detach_role_policy.assert_any_call(RoleName='stack-role-1', PolicyArn=policy_arn)
        mock_iam.detach_role_policy.assert_any_call(RoleName='stack-role-2', PolicyArn=policy_arn)
        # Assert NOT called for external-role
        calls = mock_iam.detach_role_policy.call_args_list
        self.assertFalse(any(call.kwargs.get('RoleName') == 'external-role' for call in calls))
        self.assertEqual(mock_iam.detach_role_policy.call_count, 2)
        self.mock_logger.info.assert_any_call(f"Detached {policy_arn} (MyPol) from 2 stack roles.")

    def test_handle_iam_policy_no_stack_roles_attached(self):
        mock_iam = self.mock_clients['iam']
        policy_arn = f'arn:aws:iam::{self.account_id}:policy/MyCustomPolicy'
        res_details = {'LogicalResourceId': 'MyPol', 'PhysicalResourceId': policy_arn, 'ResourceType': 'AWS::IAM::Policy'}
        stack_resources = [{'ResourceType': 'AWS::IAM::Role', 'PhysicalResourceId': 'some-other-stack-role'}] # A role not attached

        mock_iam.get_policy.return_value = {'Policy': {'Arn': policy_arn, 'AttachmentCount': 1}}
        mock_entities_pager = MagicMock()
        mock_entities_pager.paginate.return_value = [{'PolicyRoles': [{'RoleName': 'external-role'}]}]
        mock_iam.get_paginator.return_value = mock_entities_pager

        cfn_stack_deleter.handle_iam_policy(self.mock_clients, res_details, stack_resources, self.stack_name, self.region, self.account_id, dry_run=False)
        mock_iam.detach_role_policy.assert_not_called()
        self.mock_logger.debug.assert_any_call(f"Policy {policy_arn} (MyPol) not found attached to any identified stack roles.")


    def test_handle_iam_policy_dry_run(self):
        mock_iam = self.mock_clients['iam']
        policy_arn = f'arn:aws:iam::{self.account_id}:policy/MyCustomPolicy'
        res_details = {'LogicalResourceId': 'MyPol', 'PhysicalResourceId': policy_arn, 'ResourceType': 'AWS::IAM::Policy'}
        stack_resources = [{'ResourceType': 'AWS::IAM::Role', 'PhysicalResourceId': 'stack-role-1'}]

        mock_iam.get_policy.return_value = {'Policy': {'Arn': policy_arn, 'AttachmentCount': 1}} # Policy needs to "exist"

        cfn_stack_deleter.handle_iam_policy(self.mock_clients, res_details, stack_resources, self.stack_name, self.region, self.account_id, dry_run=True)

        mock_iam.list_entities_for_policy.assert_not_called() # Should be skipped in dry_run after initial log
        mock_iam.detach_role_policy.assert_not_called()
        self.mock_logger.info.assert_any_call(f"[DRY RUN] Would list entities for policy {policy_arn} (MyPol) and detach from stack-specific roles: {{'stack-role-1'}}.")


if __name__ == '__main__':
    unittest.main()
