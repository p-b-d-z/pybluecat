#!/usr/bin/python
"""
Intended to be the one CLI bluecat tool to rule them all
"""
import argparse
import json
import logging
import os
import requests
import re
from ipaddress import ip_address, ip_network
from pybluecat import BAM
from pybluecat import data as bluecat_data
from pybluecat.exceptions import BluecatError
from time import sleep


def get_creds(args):
    """
    Load credentials from file if given
    pull in from environment variables otherwise
    """
    if args.credential_file is not None:
        # Load creds from file
        with open(args.credential_file) as f:
            file_creds = json.load(f)
    else:
        # Load creds from Environment variables
        file_creds = {
            "BLUECAT_HOST": os.getenv('BLUECAT_HOST'),
            "BLUECAT_USER": os.getenv('BLUECAT_USER'),
            "BLUECAT_PASS": os.getenv('BLUECAT_PASS'),
            "BLUECAT_CFG": os.getenv('BLUECAT_CFG'),
        }
    return file_creds


def get_client(loglevel):
    """Instantiate bluecat client"""
    hostname = creds['BLUECAT_HOST']
    username = creds['BLUECAT_USER']
    password = creds['BLUECAT_PASS']
    configname = creds['BLUECAT_CFG']
    bluecat_client = BAM(hostname, username, password, configname, loglevel=loglevel)
    return bluecat_client


def validate_mac_address(mac_address):
    # Regular expression pattern for MAC address validation
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{4}[.]){2}([0-9A-Fa-f]{4})$'
    # Check if the MAC address matches the pattern
    if re.match(pattern, mac_address):
        return True
    else:
        return False


def remove_mac_delimiters(mac):
    """Returns a MAC address sans delimiters"""
    return mac.replace('.', '').replace(':', '').replace('-', '')


def reformat_mac(mac, delimiter='-'):
    """Returns a MAC address with specified delimiter"""
    mac = remove_mac_delimiters(mac)
    formatted_mac = delimiter.join(mac[i:i+2] for i in range(0, len(mac), 2))
    return formatted_mac


def process_dhcp_csv(filepath):
    """Converts a DHCP CSV file into a list of dicts"""
    with open(filepath) as f:
        csv = [line.strip().split(',') for line in f.readlines()]
    if any(field in csv[0] for field in ['hostname', 'mac', 'macaddress', 'network']):
        csv.pop(0)
    if '' in csv[-1]:
        csv.pop(-1)
    device_list = [{
        'name': device[0],
        'mac': device[1],
        'net': device[2].split('/')[0]
    }
        for device in csv
    ]
    return device_list


"""
Search Functions
"""


def find_host_record(hostrecord):
    """
    Searches for DNS HostRecord

    :param hostrecord: string
    :return: List of dictionaries
    """
    record_dict = []
    try:
        search_results = bluecat.search_ip_by_host(keyword=hostrecord)
        """
        Example return data:
        {
            'id': 974535, 
            'name': 'nuc', 
            'type': 'HostRecord',
            'properties': {
                'parentId': '4005', 
                'parentType': 'Zone', 
                'absoluteName': 'nuc.example.com',
                'addresses': '1.1.1.1', 
                'addressIds': '971894', 
                'reverseRecord': 'true'
            }
        }
        """
        for result in search_results:
            record_table = bluecat.entity_to_json(result)
            table_id = record_table['id']
            table_name = record_table['name']
            table_fqdn = record_table['properties']['absoluteName']
            table_ip_address = record_table['properties']['addresses']
            record_dict.append(
                {
                    'bam_id': table_id,
                    'host_name': table_name,
                    'host_fqdn': table_fqdn,
                    'host_ip_address': table_ip_address,
                }
            )
    except Exception as e:
        print('An error occurred:', e)
    return record_dict


def find_mac_in_net(mac):
    """
    Checks for a reservation with the given MAC.

    Returns the object if found, otherwise: None
    """
    mac_dict = []
    try:
        search_results = bluecat.search_ip_by_mac(keyword=mac)
        for result in search_results:
            mac_table = bluecat.entity_to_json(result)
            """
            Example table:
            {
                'id': 258337, 
                'name': None, 
                'type': 'MACAddress',
                'properties': {
                    'address': '54-B2-03-05-39-9C', 
                    'macVendor': 'PEGATRON CORPORATION'
                }
            }
            """
            table_id = mac_table['id']
            table_mac = mac_table['properties']['address']
            table_name = mac_table['name']
            try:
                table_vendor = mac_table['properties']['macVendor']
            except:
                table_vendor = None
            mac_dict.append(
                {
                    'bam_id': table_id,
                    'mac_address': table_mac,
                    'mac_name': table_name,
                    'mac_vendor': table_vendor,
                }
            )
    except Exception as e:
        print('An error occurred:', e)
    return mac_dict


def find_name_in_net(name):
    """
    Checks for a reservation with for the given name in the  given
    network.

    Returns the object if found, otherwise: None
    """
    ip_dict = []
    try:
        search_results = bluecat.search_ip_by_name(name)
        for result in search_results:
            ip_table = bluecat.entity_to_json(result)
            """
            Example table:
            {
                'id': 59958, 
                'name': 'EXAMPLENAME', 
                'type': 'IP4Address',
                'properties': {
                               'macAddress': '34-2E-B7-50-5E-24',
                               'address': '1.1.1.1', 
                               'state': 'DHCP_FREE', 
                              }
            }
            """
            table_id = ip_table['id']
            table_ip_address = ip_table['properties']['address']
            table_name = ip_table['name']
            try:
                table_mac = ip_table['properties']['macAddress']
            except:
                table_mac = ''
            try:
                network = bluecat.get_network_by_ip(table_ip_address)
                network_props = network['properties']
                network_props = bluecat.prop_s2d(network_props)
                """
                Example return data:
                {
                    'VlanId': '1', 
                    'vrf': 'default', 
                    'CIDR': '10.0.0.0/23', 
                    'gateway': '10.0.0.1'
                }
                """
                try:
                    network = network_props['CIDR']
                except:
                    network = None
            except Exception as e:
                network = None
            ip_dict.append(
                {
                    'bam_id': table_id,
                    'ip_name': table_name,
                    'ip_address': table_ip_address,
                    'ip_mac': table_mac,
                    'ip_network': network
                }
            )
    except Exception as e:
        print('An error occurred:', e)
    return ip_dict


def calculate_offset(network):
    if network.prefixlen > 24:
        offset = None
    else:
        offset = str(network.network_address + 31)
    return offset


def create_static(args):
    pass


def delete_static(args):
    pass


def update_static(args):
    pass


def create_static_bulk(device_list):
    pass


def delete_static_bulk(device_list):
    pass


def update_static_bulk(device_list):
    pass


def create_dhcp(args):
    # determine which networks to use
    if args.network:
        networks = [ip_network(unicode(args.network))]
    else:
        networks = lookup_enviornment_or_some_shit(args.environment)
    # loop through networks until reservation is made
    output = {}
    server_set = set()
    for network in networks:
        # Get Network info from Bluecat
        net_obj = bluecat.get_network(str(network.network_address))
        net_obj = bluecat.entity_to_json(net_obj)
        net = ip_network(net_obj['properties']['CIDR'])
        # Check for existing reservations
        reservation = find_mac_in_net(args.mac)
        if reservation is not None:
            output = reservation
            break
        # Set offset for network
        offset = calculate_offset(net)
        # Assign Next Available IP
        mac = remove_mac_delimiters(args.mac)
        response = bluecat.assign_next_ip_address(net_obj['id'], args.hostname, macAddr=mac,
                                                  action='MAKE_DHCP_RESERVED', offset=offset)
        if bluecat.history[-1].status_code == 200:
            server_set = queue_servers(server_set, net_obj['id'])
            output = bluecat.entity_to_json(response)
            dns_response = create_dns_a_record(args.hostname, output['properties']['address'])
            output['dns-status'] = dns_response.json()['permalink']
            break
    deploy_dhcp_and_monitor(server_set)
    return output


def delete_dhcp(args):
    server_set = set()
    mac_entity = bluecat.get_mac_address(args.mac)
    linked_entities = bluecat.get_linked_entities(mac_entity['id'])
    for ip in linked_entities:
        ip = bluecat.entity_to_json(ip)
        net = bluecat.get_network(ip['properties']['address'])
        response = queue_servers(server_set, net['id'])


def update_dhcp(args):
    pass


def handle_dhcp_bulk(args):
    """Single function to dole out bulk dhcp actions"""
    device_list = process_dhcp_csv(args.filepath)
    if args.delete:
        output = delete_dhcp_bulk(device_list)
    elif args.update:
        output = update_dhcp_bulk(device_list)
    else:
        output = create_dhcp_bulk(device_list)
    return output


def create_dhcp_bulk(device_list):
    output = []
    server_set = set()
    for device in device_list:
        # Get Network info from Bluecat
        net_obj = bluecat.get_network(device['net'])
        net_obj = bluecat.entity_to_json(net_obj)
        net = ip_network(net_obj['properties']['CIDR'])
        # Set offset for network
        offset = calculate_offset(net)
        # Check for existing reservations
        reservation = find_mac_in_net(device['mac'], net)
        if reservation is not None:
            output.append(reservation)
            continue
        else:
            mac = remove_mac_delimiters(device['mac'])
            response = bluecat.assign_next_ip_address(net_obj['id'], device['name'], device['mac'],
                                                      action='MAKE_DHCP_RESERVED', offset=offset)
            server_set = queue_servers(server_set, net_obj['id'])
            output.append(bluecat.entity_to_json(response))
            # ip_obj = bluecat.entity_to_json(response)
            dns_response = create_dns_a_record(device['name'], response['properties']['address'])
            output[-1]['dns-status'] = dns_response.json()['permalink']
    deploy_dhcp_and_monitor(server_set)
    return output


def delete_dhcp_bulk(device_list):
    pass


def update_dhcp_bulk(device_list):
    output = []
    server_set = set()
    for device in device_list:
        output_entry = {'deleted': [], 'created': []}
        # Get Network info from Bluecat
        net_obj = bluecat.get_network(device['net'])
        net_obj = bluecat.entity_to_json(net_obj)
        net = ip_network(net_obj['properties']['CIDR'])
        # Find other instances of device of same name
        search_results = bluecat.search_ip_by_name(device['name'])
        for result in search_results:
            # Ensure we only delete exact matches, excluding case
            if result['name'].lower() == device['name'].lower():
                reservation = bluecat.entity_to_json(result)
                # del_addr = ip_address(reservation['properties']['address'])
                del_net = bluecat.get_network(reservation['properties']['address'])
                # delete the reservation from Bluecat
                bluecat.delete(reservation['id'])
                # delete the dns record
                dns_response = delete_dns_a_record(reservation['name'].lower())
                # ensure the changes will get deployed to the correct servers
                server_set = queue_servers(server_set, del_net['id'])
                # log the deletion
                reservation['dns-status'] = dns_response.json()['permalink']
                output_entry['deleted'].append(reservation)
        # Set offset for network
        offset = calculate_offset(net)
        # Check for existing reservations
        reservation = find_mac_in_net(device['mac'], net)
        if reservation is not None:
            output_entry['created'].append(reservation)
            continue
        else:
            mac = remove_mac_delimiters(device['mac'])
            response = bluecat.assign_next_ip_address(net_obj['id'], device['name'], device['mac'],
                                                      action='MAKE_DHCP_RESERVED', offset=offset)
            server_set = queue_servers(server_set, net_obj['id'])
            output_entry['created'].append(bluecat.entity_to_json(response))
            # ip_obj = bluecat.entity_to_json(response)
            dns_response = create_dns_a_record(device['name'], response['properties']['address'])
            output_entry['created'][-1]['dns-status'] = dns_response.json()['permalink']
        output.append(output_entry)
    deploy_dhcp_and_monitor(server_set)
    return output


def queue_servers(server_set, network_id):
    roles = bluecat.get_deployment_roles(network_id)
    server_primary = bluecat.get_server_for_role(roles[0]['id'])
    server_backup_id = bluecat_data.adonis_pairs[server_primary['id']]
    server_set.add(server_primary['id'])
    server_set.add(server_backup_id)
    return server_set


def deploy_dhcp_and_monitor(server_set):
    for server in server_set:
        bluecat.deploy_server_services(server, 'DHCP')
    monitor_server_deployment(server_set)


def monitor_server_deployment(server_set):
    for server in server_set:
        status = bluecat.get_deployment_status(server)
        logger.info(f'{bluecat_data.adonis_id_map[server]} - {bluecat_data.deployment_status[status]}')
    while len(server_set) > 0:
        sleep(2)
        servers = list(server_set)
        for server in servers:
            status = bluecat.get_deployment_status(server)
            if status not in [-1, 0, 1]:
                logger.info(f'{bluecat_data.adonis_id_map[server]} - {bluecat_data.deployment_status[status]}')
                server_set.remove(server)


def create_dns_a_record(name, ip):
    pass


def delete_dns_a_record(name):
    pass


"""
Parser Functions
"""


def add_single_operation_args(parser):
    parser.add_argument('hostname')
    me_group = parser.add_mutually_exclusive_group(required=True)
    me_group.add_argument('-n', '--network', help='network address within desired subnet')
    me_group.add_argument('-e', '--environment', help='environment to assign IP from')
    parser.add_argument('-c', '--creds', help='filepath to read in json credentials')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    parser.add_argument('--nowait', action='store_true', help='do NOT wait for deploy before printing results')


def add_search_operation_args(parser):
    parser.add_argument('--name')
    parser.add_argument('--mac')
    parser.add_argument('--dns')
    parser.add_argument('--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')


def add_dhcp_single_operation_args(parser):
    add_single_operation_args(parser)
    parser.add_argument('mac')


def add_bulk_operation_args(parser):
    parser.add_argument('filepath', help='path to csv file containing record info')
    parser.add_argument('-c', '--creds', help='filepath to read in json credentials')
    me_group = parser.add_mutually_exclusive_group()
    me_group.add_argument('--create', action='store_true', help='create all records in csv, default action')
    me_group.add_argument('--delete', action='store_true', help='delete all records in csv')
    me_group.add_argument('--update', action='store_true', help='update all records in csv')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')


def main():
    # Main Argument Parser "pybluecat"
    parser = argparse.ArgumentParser(prog='Bluecat BAM CLI', formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(title='Subcommands', help='subparsers command help', dest='subparser')

    # "pybluecat" argument: "loglevel"
    parser.add_argument('--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='Enable logging', type=str.upper)

    # "pybluecat" argument: "credential-file"
    parser.add_argument('--credential-file', help='Path to credential file')

    # "pybluecat" sub-parser: "static"
    parser_static = subparsers.add_parser('static', help='Static IP record manipulation')
    sub_static = parser_static.add_subparsers(title='Subcommands', help='Options for static records', dest='subparser')

    # "pybluecat" sub-parser: "dhcp"
    parser_dhcp = subparsers.add_parser('dhcp', help='DHCP IP record manipulation')
    sub_dhcp = parser_dhcp.add_subparsers(title='Subcommands', help='Options for dhcp records', dest='subparser')

    # "pybluecat" sub-parser: "search"
    parser_search = subparsers.add_parser('search', help='Search BAM for Objects')
    # sub_search = parser_search.add_subparsers(title='Subcommands', help='Options for dhcp records', dest='subparser')
    add_search_operation_args(parser_search)

    # # pybluecat static create
    parser_static_create = sub_static.add_parser('create', help='Create a static IP reservation')
    add_single_operation_args(parser_static_create)

    # # pybluecat static delete
    parser_static_delete = sub_static.add_parser('delete', help='Delete a static IP reservation')
    add_single_operation_args(parser_static_delete)

    # # pybluecat static update
    parser_static_update = sub_static.add_parser('update', help='Update a static IP reservation')
    add_single_operation_args(parser_static_update)

    # # pybluecat static bulk
    parser_static_bulk = sub_static.add_parser('bulk', help='Create bulk static records from csv')
    add_bulk_operation_args(parser_static_bulk)

    # # pybluecat dhcp create
    parser_dhcp_create = sub_dhcp.add_parser('create', help='Create a dhcp IP reservation')
    add_dhcp_single_operation_args(parser_dhcp_create)
    parser_dhcp_create.set_defaults(func=create_dhcp)

    # # pybluecat dhcp delete
    parser_dhcp_delete = sub_dhcp.add_parser('delete', help='delete a dhcp IP reservation')
    add_dhcp_single_operation_args(parser_dhcp_delete)

    # # pybluecat dhcp update
    parser_dhcp_update = sub_dhcp.add_parser('update', help='Update a dhcp IP reservation')
    add_dhcp_single_operation_args(parser_dhcp_update)

    # # pybluecat dhcp bulk
    parser_dhcp_bulk = sub_dhcp.add_parser('bulk', help='Create bulk dhcp records from csv')
    add_bulk_operation_args(parser_dhcp_bulk)
    parser_dhcp_bulk.set_defaults(func=handle_dhcp_bulk)

    # Parse the args from any and all parsers
    try:
        args = parser.parse_args()
    except argparse.ArgumentError as e:
        print('Argument error:', e)
    except argparse.ArgumentTypeError as e:
        print('Argument type error:', e)

    # Setup BAM-CLI logger
    global logger
    logger = logging.getLogger('pybluecat-cli')
    loglevel = args.loglevel
    if loglevel in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
        level = getattr(logging, loglevel)
        logger.setLevel(level=level)
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)

    # Get credentials and client
    global creds
    creds = get_creds(args)
    # Load client
    global bluecat
    bluecat = get_client(loglevel=loglevel)

    # Run the relevant function
    logger.debug(args)
    if args.subparser == 'search':
        if args.dns is not None:
            search_results = find_host_record(args.dns)
            print('\n### DNS search results:\nhostname,fqdn,ip address')
            for result in search_results:
                field1 = result['host_name']
                field2 = result['host_fqdn']
                field3 = result['host_ip_address']
                print(f'{field1},{field2},{field3}')
        if args.name is not None:
            search_results = find_name_in_net(args.name)
            print('\n### Name search results:\nhostname,ip address,mac address,network')
            for result in search_results:
                field1 = result['ip_name']
                field2 = result['ip_address']
                field3 = result['ip_mac']
                field4 = result['ip_network']
                print(f'{field1},{field2},{field3},{field4}')
        if args.mac is not None:
            search_mac = reformat_mac(args.mac)
            print('\n### MAC search results:\nmac address,name,vendor')
            if validate_mac_address(search_mac):
                search_results = find_mac_in_net(search_mac)
                for result in search_results:
                    field1 = result['mac_address']
                    field2 = result['mac_name']
                    field3 = result['mac_vendor']
                    print(f'{field1},{field2},{field3}')
        exit(0)
    output = args.func(args)
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
