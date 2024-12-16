import argparse
import copy
import os
import re

import boto3

from datetime import datetime

import pybluecat

# Parse script arguments
parser = argparse.ArgumentParser(description='Retrieve IP addresses of EC2 instances and Fargate containers'
                                             ' and sync them to Bluecat Address Manager.',
                                 formatter_class=argparse.RawTextHelpFormatter)
# If 'region' is not specified, use the environment
parser.add_argument('--region', default=os.environ.get('REGION', 'us-west-2'),
                    help='AWS region to use (default: us-west-2)')
parser.add_argument('--environment', help='AWS environment to use (example: production-a)')
parser.add_argument('--no-ec2', action='store_true', help='Skip EC2 instances')
parser.add_argument('--no-fargate', action='store_true', help='Skip Fargate containers')
parser.add_argument('--update-bam', action='store_true', help='Update Bluecat Address Manager')
# Show example commands in the help message
example_commands = """
    ### Environment Variables
    
    Required for Bluecat Address Manager:
    BLUECAT_HOST
    BLUECAT_CFG
    BLUECAT_USER
    BLUECAT_PASS
    
    Required for AWS:
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    or
    AWS_DEFAULT_PROFILE

    ### Example usage

    List AWS Private IPs for us-west-2:
    python3 sync-aws-to-bluecat.py --region us-west-2

    List AWS Private IPs for us-west-2 and update Bluecat records:
    python3 sync-aws-to-bluecat.py --update-bam
    
    List AWS Private IPs for eu-west-2 production-a and update Bluecat records:
    python3 sync-aws-to-bluecat.py --region us-west-2 --environment production-a --update-bam
"""
parser.epilog = example_commands
args = parser.parse_args()

# Create a session using the specified region and environment credentials
session = boto3.Session(region_name=args.region)
# Create EC2, ECS clients
ec2_client = session.client('ec2')
ecs_client = session.client('ecs')
today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# Functions
def bc_check_for_existing(ipv4=''):
    """
    Provide an IPv4 address, and we'll return a boolean.
    True: Exists
    False: Does not exist

    :param ipv4: string
    :return:
    boolean, bam_id if True
    boolean, None if False
    """
    try:
        res = bam.get_ip_address(ip_addr=ipv4)
        this_id = res['id']
        # Returned ID means a record exists
        if this_id:
            return True, this_id
        else:
            #
            return False, None

    except Exception as err:
        print(f'Unable to lookup IP address from BAM: {err}')
        return False, None


def bc_check_for_match(ipv4='', hostname=''):
    """
    This function accepts 2 inputs:
    - ipv4, string containing an IP address
    - hostname, string containing a hostname

    The function looks up the Bluecat IP address and matches its name to a provided hostname.
    A boolean is returned based on whether the hostnames match.
    """
    try:
        res = bam.get_ip_address(ip_addr=ipv4)
        bam_hostname = res['name']
        if hostname == bam_hostname:
            return True
        else:
            return False

    except Exception as err:
        print(f'Unable to lookup IP address from BAM: {err}')
        return False, None


def remove_duplicates(data, index):
    """
    Function that accepts 2 inputs:
    - data, dictionary containing indexes to sort and remove duplicates from
    - index, the index in the dictionary to sort and remove duplicates from

    The returned set is a sorted dictionary with only unique values.
    """
    unique_ips = set()
    result = []
    sorted_data = sorted(data, key=lambda x: x[index])
    for entry in sorted_data:
        entry_ip = entry[index]
        if entry_ip not in unique_ips:
            unique_ips.add(entry_ip)
            result.append(entry)

    return result


def separate_strings(input_string):
    """
    This function takes an input string in the form of <environment>-<variant>-<stack_name> and returns 2
    variables:
    - env_variant, containing <environment>-<variant>
    - stack_name_match, containing <stack_name>
    """
    # Extract environment and variant from input string
    env_variant_match = re.search(r'^(.*?)-(.+?)-', input_string)
    env_variant = env_variant_match.group(1) + '-' + env_variant_match.group(2)

    # Extract stack name from input string
    stack_name_match = re.search(r'-(.+)', input_string[env_variant_match.end(2):]).group(1)

    return env_variant, stack_name_match


def update_bluecat_records(record_dict, delete_existing=False):
    """
    Function that accepts a dictionary of records and updates Bluecat with the provided data.

    :param record_dict:
    :param delete_existing:
    :return: record_count
    """
    record_count = 0
    for bc_object in record_dict:
        # Delete existing records if delete_existing is True
        if delete_existing:
            print(f'Deleting existing records for {bc_object["environment"]} {bc_object["stack_name"]}...')
            filters = {
                'aws_account': bc_object['account_name'],
                'ansible_stack_name': bc_object['stack_name'],
                'ansible_environment': bc_object['environment'],
            }
            search_result = bam.custom_search(obj_type='IP4Address', filters=filters)
            for result in search_result:
                delete_id = result['id']
                print(f'Deleting record ID: {delete_id}')
                bam.delete(delete_id)

            print('')

        # Check for existing Bluecat records
        does_exist, bam_id = bc_check_for_existing(
            ipv4=bc_object['private_ip']
        )
        does_match = bc_check_for_match(
            ipv4=bc_object['private_ip'],
            hostname=bc_object['instance_id']
        )
        if does_exist:
            bc_object['bam_id'] = bam_id

        # Update an existing record with new hostname
        if bam_id and not does_match:
            try:
                entity = bam.get_entity_by_id(bc_object['bam_id'])
                if isinstance(entity['properties'], str):
                    entity = bam.entity_to_json(entity)

                old_properties = entity['properties']
                new_properties = {}
                new_entity = copy.deepcopy(entity)
                # Set new properties
                new_entity['name'] = bc_object['instance_id']
                new_properties['aws_account'] = bc_object['account_name']
                new_properties['aws_last_sync'] = today
                new_properties['ansible_stack_name'] = bc_object['stack_name']
                new_properties['ansible_environment'] = bc_object['environment']
                # Reuse existing properties
                new_properties['state'] = old_properties['state']
                new_properties['address'] = old_properties['address']
                # Convert properties to string
                new_entity['properties'] = bam.prop_d2s(new_properties)
                bam.update(new_entity)
                record_count = record_count + 1
                print(f'Updating {bc_object["private_ip"]}.')
            except Exception as err:
                print(f'Error updating record ID {bc_object["bam_id"]}: {err}')

        # Update an existing record with new properties
        elif bam_id and does_match:
            if bc_object['bam_id']:
                try:
                    entity = bam.get_entity_by_id(bc_object['bam_id'])
                    if isinstance(entity['properties'], str):
                        entity = bam.entity_to_json(entity)

                    old_properties = entity['properties']
                    new_properties = {}
                    new_entity = copy.deepcopy(entity)
                    new_entity['name'] = entity['name']
                    # Update properties
                    new_properties['aws_account'] = bc_object['account_name']
                    new_properties['aws_last_sync'] = today
                    new_properties['ansible_stack_name'] = bc_object['stack_name']
                    new_properties['ansible_environment'] = bc_object['environment']
                    # Reuse existing properties
                    new_properties['state'] = old_properties['state']
                    new_properties['address'] = old_properties['address']
                    # Convert properties to string
                    new_entity['properties'] = bam.prop_d2s(new_properties)
                    bam.update(new_entity)
                    record_count = record_count + 1
                    print(f'Updating: {bc_object["private_ip"]}')
                except Exception as err:
                    print(f'Error updating record ID {bc_object["bam_id"]}: {err}')
        # Create a new record
        else:
            try:
                bam.assign_ip_address(
                    ipv4_address=bc_object['private_ip'],
                    hostname=bc_object['instance_id'],
                    properties={
                        'aws_account': bc_object['account_name'],
                        'aws_last_sync': today,
                        'ansible_stack_name': bc_object['stack_name'],
                        'ansible_environment': bc_object['environment']
                    }
                )
                record_count = record_count + 1
                print(f'Assigning {bc_object["private_ip"]} to {bc_object["instance_id"]}\n')
            except Exception as err:
                print(f'Error assigning IP address {bc_object["private_ip"]}: {err}')

    return record_count


# Login to BAM
bam_host = os.getenv('BLUECAT_HOST')
bam_user = os.getenv('BLUECAT_USER')
bam_pass = os.getenv('BLUECAT_PASS')
bam_cfg = os.getenv('BLUECAT_CFG')
bam = pybluecat.BAM(bam_host, bam_user, bam_pass, bam_cfg)
# Retrieve EC2 instance private IP addresses with tags
ec2_instance_ips = []
if not args.no_ec2:
    print('\nSearching for EC2 hosts...')
    # Retrieve all EC2 instances
    response = ec2_client.describe_instances()
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            # Extract the instance ID, private IP address, and tags
            instance_id = instance['InstanceId']
            private_ip = instance.get('PrivateIpAddress')
            tags = instance.get('Tags', [])
            # Extract tags
            account_name = ''
            env_name = ''
            stack_name = ''
            for tag in tags:
                if tag['Key'] == 'Account Name':
                    account_name = tag['Value'].lower()

                if tag['Key'] == 'Environment':
                    env_name = tag['Value'].lower()

                if tag['Key'] == 'ansible_stack_name':
                    stack_name = tag['Value'].lower()

            # Add instance ID, private IP address, and stack_name to the list
            if instance_id and private_ip:
                if not args.environment or args.environment in env_name:
                    ec2_instance_ips.append({
                        'account_name': account_name,
                        'instance_id': instance_id,
                        'private_ip': private_ip,
                        'environment': env_name,
                        'stack_name': stack_name,
                        'needs_update': False,
                        'bam_id': ''
                    })

    ec2_instance_ips = remove_duplicates(ec2_instance_ips, 'instance_id')
    ec2_instance_ips = remove_duplicates(ec2_instance_ips, 'private_ip')
    print('#### EC2 ####')
    for instance in ec2_instance_ips:
        print(
            f'Instance ID: {instance["instance_id"]}, '
            f'Private IP: {instance["private_ip"]}, '
            f'Environment: {instance["environment"]}, '
            f'Stack Name: {instance["stack_name"]}'
        )

# Retrieve Fargate container private IP addresses with tags
fargate_container_ips = []
if not args.no_fargate:
    print('\nSearching for Fargate containers...')
    # Retrieve all ECS clusters
    response = ecs_client.list_clusters()
    for cluster_arn in response['clusterArns']:
        # Retrieve all tasks in the cluster
        response = ecs_client.list_tasks(cluster=cluster_arn)
        task_arns = response['taskArns']
        # Ensure that task_arns is not empty before calling describe_tasks
        if task_arns:
            # Describe tasks and extract container private IP addresses
            response = ecs_client.describe_tasks(cluster=cluster_arn, tasks=task_arns, include=['TAGS'])
            for task in response['tasks']:
                task_tags = task['tags']
                # Extract tags
                account_name = ''
                env_name = ''
                stack_name = ''
                for tag in task_tags:
                    if tag['key'] == 'Account Name':
                        account_name = tag['value'].lower()

                    if tag['key'] == 'Environment':
                        env_name = tag['value'].lower()

                    if tag['key'] == 'ansible_stack_name':
                        stack_name = tag['value'].lower()

                for container in task['containers']:
                    # If it doesn't have an IP we don't want it
                    try:
                        private_ip = container['networkInterfaces'][0]['privateIpv4Address']
                    except Exception as e:
                        private_ip = None
                        pass

                    container_name = container['name']
                    # Add container name, private IP address, and stack_name to the list
                    if container_name and private_ip:
                        if not args.environment or args.environment in env_name:
                            fargate_container_ips.append({
                                'account_name': account_name,
                                'instance_id': container_name,
                                'private_ip': private_ip,
                                'environment': env_name,
                                'stack_name': stack_name,
                                'needs_update': False,
                                'bam_id': ''
                            })

    # Removed duplicates
    fargate_container_ips = remove_duplicates(fargate_container_ips, 'instance_id')
    fargate_container_ips = remove_duplicates(fargate_container_ips, 'private_ip')
    print('#### Containers ####')
    for container in fargate_container_ips:
        print(f'Container Name: {container["instance_id"]}, '
              f'Private IP: {container["private_ip"]}, '
              f'Environment: {container["environment"]}, '
              f'Stack Name: {container["stack_name"]}'
              )

# Update Bluecat Address Manager with IP reservations
if args.update_bam:
    print('\nUpdating Bluecat records...')
    # Update EC2 records
    if not args.no_ec2:
        ec2_records_updated = update_bluecat_records(ec2_instance_ips)
        print(f'\nUpdated {ec2_records_updated} EC2 record(s).\n')

    # Update Fargate records
    if not args.no_fargate:
        fargate_records_updated = update_bluecat_records(fargate_container_ips, delete_existing=True)
        print(f'\nUpdated {fargate_records_updated} Fargate record(s).\n')
