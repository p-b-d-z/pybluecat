#!/usr/bin/python3
"""
pyBluecat CLI - Interactive shell for Bluecat Address Manager API
"""
import boto3
import botocore.exceptions
import pybluecat
import cmd
import os
import re

from ipaddress import ip_address

import cli.common.logging as bam_log

log = bam_log.Logger()
log.info(f'Module loaded. Log level: {log.log_level.value}')


def get_ssm_parameter(name, profile_name=None, region=None):
    """
    This function takes a parameter name and returns the value from AWS SSM Parameter Store.

    :param name: The name of the parameter to retrieve
    :param profile_name: The AWS profile to use
    :param region: The AWS region to use
    """
    if region is None:
        region = os.getenv('AWS_REGION', 'us-west-2')

    if profile_name is None:
        profile_name = os.getenv('AWS_DEFAULT_PROFILE', 'yam-shared')

    try:
        log.info(f'Connecting to AWS using {profile_name} {region} credentials')
        session = boto3.Session(profile_name=profile_name, region_name=region)
        ssm_client = session.client('ssm')
    except botocore.exceptions.ProfileNotFound as err:
        log.error(err)
        return None

    try:
        log.info(f'Retrieving SSM Path: {name}')
        parameter = ssm_client.get_parameter(Name=name, WithDecryption=True)
    except ssm_client.exceptions.ParameterNotFound as err:
        log.error(f'Parameter was not found in SSM Parameter Store: {name}')
        log.debug(err)
        return None
    except ssm_client.exceptions.ClientError as err:
        log.debug(err)
        return None

    return parameter['Parameter']['Value']


def init_bam():
    """
    Initialize the Bluecat Address Manager API connection
    """
    # Login to BAM using SSM parameters first, then environment variables
    try:
        bam_host = get_ssm_parameter('/all/bluecat/bam_api_host')
        bam_user = get_ssm_parameter('/all/bluecat/bam_api_user')
        bam_pass = get_ssm_parameter('/all/bluecat/bam_api_pass')
        bam_cfg = get_ssm_parameter('/all/bluecat/bam_api_cfg')
    except:
        log.info('SSM parameters not found. Using environment variables.')
        bam_host = os.getenv('BLUECAT_HOST', '')
        bam_user = os.getenv('BLUECAT_USER', '')
        bam_pass = os.getenv('BLUECAT_PASS', '')
        bam_cfg = os.getenv('BLUECAT_CFG', '')

    bam_session = pybluecat.BAM(bam_host, bam_user, bam_pass, bam_cfg)
    log.debug(f'BAM Session: {bam_session}')
    return bam_session


def is_valid_ipaddress(string):
    """
    Function that validates that a string is a valid IP address. Supports IPv4 and IPv6.
    :param string:
    :return: boolean:
    """
    try:
        ip_address(string)
        return True
    except Exception as e:
        print(f'Error: {e}')
        return False


def is_valid_fqdn(fqdn):
    """
    Validate a string to check if it is a valid FQDN.

    Parameters:
    fqdn (str): The string to validate as an FQDN.

    Returns:
    bool: True if the string is a valid FQDN, False otherwise.
    """
    pattern = r"^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:[A-Za-z]{2,}|xn--[A-Za-z0-9]{2,})$"
    return bool(re.match(pattern, fqdn))


def list_to_string(arg, delimiter=' '):
    """Convert a list to a string using space as a delimiter"""
    return delimiter.join(arg)


class BAMShell(cmd.Cmd):
    """
    BAM CLI Shell implementation
    """

    prompt = '(bam)# '
    intro = 'Welcome to pybluecat CLI. Type help or ? to list commands.\n'
    file = None
    # Login to BAM
    bam = init_bam()
    config_cache = {
        'v1_config': bam.config,
        'v2_config': bam.config_v2,
        'dns': {
            'views': bam.get_entities(parent_id=bam.config_id, obj_type='View'),
            'zones': {},
        }
    }
    # Populate zones cache
    for view in config_cache['dns']['views']:
        root_zones = bam.get_entities(parent_id=view['id'], obj_type='Zone')
        config_cache['dns']['zones'][view['id']] = root_zones
        for zone in root_zones:
            sub_zones = bam.get_entities(parent_id=zone['id'], obj_type='Zone')
            config_cache['dns']['zones'][zone['id']] = sub_zones
            for sub_zone in sub_zones:
                sub_zones_2 = bam.get_entities(parent_id=sub_zone['id'], obj_type='Zone')
                config_cache['dns']['zones'][sub_zone['id']] = sub_zones_2

    default_view_id = config_cache['dns']['views'][0]['id']
    log.debug(f'Config:\n{config_cache}\n')

    # Create functions
    def do_create(self, arg):
        """
        Implement the 'create' command.
        """
        args = arg.split()
        if len(args) == 0:
            print('Incomplete command.')
            return

        if args[0] in ['host-record', 'a-record']:
            passthru_args = args[1:]
            if len(passthru_args) > 1:
                host_fqdn = passthru_args[0]
                host_ip = passthru_args[1]
                valid_fqdn = is_valid_fqdn(host_fqdn)
                valid_ip = is_valid_ipaddress(host_ip)
                if valid_fqdn and valid_ip:
                    if len(passthru_args[0].split('.')) > 2:
                        try:
                            record_id = self.bam.add_resource_record(
                                absolute_name=host_fqdn, ip_address=host_ip, ttl=300, view_id=self.default_view_id
                            )
                            print(f'Created record: {record_id}\n')
                        except pybluecat.exceptions.BluecatError as err:
                            log.error(f'Could not complete the request: {err}\n')
                    else:
                        log.error('Invalid FQDN.\n')
                elif not valid_fqdn:
                    log.error('Invalid FQDN.\n')
                elif not valid_ip:
                    log.error('Invalid IP address.\n')

        else:
            log.error(f'Invalid create command: {args}\n')

    # Delete functions
    def do_delete(self, arg):
        """
        Implement the 'delete' command.
        """
        args = arg.split()
        if len(args) == 0:
            log.error('Incomplete command.')
            return

        if args[0] == 'stack':
            command_arg = args[0]
            passthru_args = args[1:]
            if len(args) > 1:
                filters = {'ansible_stack_name': passthru_args[0]}
                search_result = self.bam.custom_search(obj_type='IP4Address', filters=filters)
                log.debug(f'Search result:\n{search_result}\n')
                print(f'Found {len(search_result)} results for {passthru_args[0]}:')
                for result in search_result:
                    delete_id = result['id']
                    print(f'Deleting ID: {delete_id}')
                    self.bam.delete(delete_id)

                print('')
            else:
                log.error(f'Missing arguments for {command_arg}: {passthru_args}\n')

    # Search functions
    def do_search(self, arg):
        """
        Implement the 'search' command.
        """
        args = arg.split()
        if len(args) == 0:
            log.error('Incomplete command.')
            return

        if args[0] in ['address', 'network']:
            command_arg = args[0]
            passthru_args = args[1:]
            if len(args) > 1:
                search_result = self.bam.get_network(passthru_args)
                log.debug(f'Search result:\n{search_result}\n')
                if len(search_result) > 1 and int(search_result['id']) != 0:
                    network_name = search_result['name']
                    properties = self.bam.prop_s2d(search_result['properties'])
                    network_cidr = properties['CIDR']
                    print(f'Network: {network_name}\nCIDR: {network_cidr}\n')
                    self.do_search('block ' + list_to_string(passthru_args))
                else:
                    print('No results found.\n')
            else:
                print(f'Missing arguments for {command_arg}: {passthru_args}\n')
        elif args[0] == 'block':
            command_arg = args[0]
            passthru_args = args[1:]
            if len(args) > 1:
                search_result = self.bam.get_block_by_ip(passthru_args)
                log.debug(f'Search result:\n{search_result}\n')
                if int(search_result['id']) != 0:
                    block_name = search_result['name']
                    properties = self.bam.prop_s2d(search_result['properties'])
                    block_cidr = properties['CIDR']
                    print(f'Block: {block_name}\nCIDR: {block_cidr}\n')
                else:
                    print('No results found.\n')
            else:
                print(f'Missing arguments for {command_arg}: {passthru_args}\n')
        elif args[0] == 'record':
            command_arg = args[0]
            if len(args) > 1:
                passthru_args = args[1]
                search_results = self.bam.get_resource_record_by_hint(passthru_args)
                log.debug(f'Search result:\n{search_results}\n')
                if len(search_results) > 0:
                    for result in search_results:
                        properties = self.bam.prop_s2d(result['properties'])
                        record_ip = properties['addresses']
                        record_fqdn = properties['absoluteName']
                        print(f'Record: {record_fqdn}\nIP: {record_ip}\n')
                else:
                    print('No results found.\n')
            else:
                print(f'Missing argument for {command_arg}\n')
        elif args[0] == 'stack':
            command_arg = args[0]
            passthru_args = args[1:]
            if '--all' in args:
                max_count = 999
            else:
                max_count = 10

            if len(args) > 1:
                filters = {'ansible_stack_name': passthru_args[0]}
                search_result = self.bam.custom_search(obj_type='IP4Address', filters=filters)
                log.debug(f'Search result:\n{search_result}\n')
                print(f'Found {len(search_result)} results for {passthru_args[0]}:')
                count = 0
                for result in search_result:
                    count += 1
                    if count > max_count:
                        print(f'\nDisplay limited to the first {max_count} results.\n')
                        break

                    properties = self.bam.prop_s2d(result['properties'])
                    address_name = result['name']
                    network_address = properties['address']
                    stack_name = properties.get('ansible_stack_name', 'N/A')
                    stack_env = properties.get('ansible_environment', 'N/A')
                    print(f'  - {address_name}: {network_address} | Stack: {stack_name} | Environment: {stack_env}')

                print('')

            else:
                print(f'Missing arguments for {command_arg}: {passthru_args}\n')
        elif args[0] == 'views':
            search_result = self.bam.get_entities(parent_id=self.bam.config_id, obj_type='View')
            log.debug(f'Search result:\n{search_result}\n')
            if len(search_result) > 0:
                for result in search_result:
                    view_name = result['name']
                    view_id = result['id']
                    print(f'View: {view_name} [{view_id}]')

                print('')
            else:
                print('No results found.\n')

        elif args[0] == 'zones':
            search_result = self.bam.get_entities(parent_id=self.default_view_id, obj_type='Zone')
            log.debug(f'Search result:\n{search_result}\n')
            if len(search_result) > 0:
                print('Displaying Zones as [NAME] [ID] [DEPLOYABLE]\n--------------------------------------------')
                for result in search_result:
                    zone_name = result['name']
                    zone_id = result['id']
                    zone_props = self.bam.prop_s2d(result['properties'])
                    is_zone_deployable = bool(zone_props.get('deployable', 'false') == 'true')
                    if is_zone_deployable:
                        print(f'{zone_name} [{zone_id}] [X]')
                    else:
                        print(f'{zone_name} [{zone_id}] [ ]')

                    sub_zones = self.bam.get_entities(parent_id=zone_id, obj_type='Zone')
                    log.debug(f'Search result:\n{sub_zones}\n')
                    for sub_zone in sub_zones:
                        sub_zone_name = sub_zone['name']
                        sub_zone_id = sub_zone['id']
                        sub_zone_props = self.bam.prop_s2d(sub_zone['properties'])
                        is_sub_zone_deployable = bool(sub_zone_props.get('deployable', 'false') == 'true')
                        if is_sub_zone_deployable:
                            print(f'  - {sub_zone_name} [{sub_zone_id}] [X]')
                        else:
                            print(f'  - {sub_zone_name} [{sub_zone_id}] [ ]')

                        sub_zones_2 = self.bam.get_entities(parent_id=sub_zone_id, obj_type='Zone')
                        log.debug(f'Search result:\n{sub_zones_2}\n')
                        for sub_zone_2 in sub_zones_2:
                            sub_zone_name_2 = sub_zone_2['name']
                            sub_zone_id_2 = sub_zone_2['id']
                            sub_zone_props_2 = self.bam.prop_s2d(sub_zone_2['properties'])
                            is_sub_zone_deployable_2 = bool(sub_zone_props_2.get('deployable', 'false') == 'true')
                            if is_sub_zone_deployable_2:
                                print(f'    - {sub_zone_name_2} [{sub_zone_id_2}] [X]')
                            else:
                                print(f'    - {sub_zone_name_2} [{sub_zone_id_2}] [ ]')

                print('')
            else:
                print('No results found.\n')
        else:
            log.error(f'Invalid search command: {args}\n')

    # Tab completion functions
    def complete_create(self, text, line, begidx, endidx):
        """
        Tab completion for the 'create' command.
        """
        options = ['host-record', 'a-record']
        if not text:
            completions = options[:]
        else:
            completions = [o for o in options if o.startswith(text)]

        return completions

    def complete_delete(self, text, line, begidx, endidx):
        """
        Tab completion for the 'delete' command.
        """
        options = ['stack']
        if not text:
            completions = options[:]
        else:
            completions = [o for o in options if o.startswith(text)]

        return completions

    def complete_search(self, text, line, begidx, endidx):
        """
        Tab completion for the 'search' command.
        """
        options = ['address', 'block', 'network', 'record', 'stack', 'views', 'zones']
        if not text:
            completions = options[:]
        else:
            completions = [o for o in options if o.startswith(text)]

        return completions

    def do_exit(self, arg):
        """
        Exit the shell
        """
        self.bam.logout()
        print('Goodbye!')
        return True


def parse(arg):
    """
    Convert a series of zero or more numbers to an argument tuple
    """
    return tuple(map(int, arg.split()))


if __name__ == '__main__':
    BAMShell().cmdloop()
