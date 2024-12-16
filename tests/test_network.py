import os
import time

import pybluecat
from helper_functions import sort_and_filter_list_of_dicts
from pybluecat.data import *
from test_data import *

# Global variables
retries = 3
delay = 5


def test_get_deployment_roles(session, ipv4_address):
    """

    :param session:
    :param ipv4_address:
    :return:
    """
    print(f'Testing get_deployment_roles(ipv4_address={ipv4_address})')
    retry_count = 0
    while retry_count < retries:
        try:
            network_id = session.get_network_by_ip(ipv4_address=ipv4_address)
            network_id = session.entity_to_json(entity=network_id)
            network_entity_id = network_id['id']
            # print(f'Network ID: {network_entity_id}')
            deployment_role = session.get_deployment_roles(entity_id=network_entity_id)
            # print(f'Deployment Role: {deployment_role}')
            return deployment_role
        except Exception as e:
            # print(f'Error: {e}')
            retry_count += 1
            time.sleep(delay)


def test_get_ip_address(session, test_dictionary):
    print('Testing get_ip_address()')
    address_objects = []
    for ipv4 in test_dictionary:
        retry_count = 0
        while retry_count < retries:
            try:
                address_object = session.get_ip_address(ip_addr=ipv4)
                address_object = session.entity_to_json(entity=address_object)
                address_objects.append(address_object)
                print(f'Address Object: {address_object}')
                break
            except Exception as e:
                # print(f'Error: {e}')
                retry_count += 1
                time.sleep(delay)
    return address_objects


def test_get_network_by_ip(session, test_dictionary):
    """
    Example Network Object:
    {
      'id': 48323,
      'name': 'YIT Users',
      'type': 'IP4Network',
      'properties': {
        'VlanId': '800',
        'vrf': 'default',
        'CIDR': '10.8.0.0/23',
        'gateway': '10.8.0.1'
      }
    }

    """
    print('Testing get_network_by_ip()')
    network_objects = []
    for ipv4 in test_dictionary:
        retry_count = 0
        while retry_count < retries:
            try:
                network_object = session.get_network_by_ip(ipv4_address=ipv4)
                network_object = session.entity_to_json(entity=network_object)
                network_objects.append(network_object)
                print(f'Network Object: {network_object}')
                break
            except Exception as e:
                print(f'Error: {e}')
                retry_count += 1
                time.sleep(delay)
    return network_objects


def main():
    test_deploy = False
    bam_host = os.getenv('BLUECAT_HOST')
    bam_user = os.getenv('BLUECAT_USER')
    bam_pass = os.getenv('BLUECAT_PASS')
    bam_cfg = os.getenv('BLUECAT_CFG')
    bam = pybluecat.BAM(bam_host, bam_user, bam_pass, bam_cfg)

    ip_addresses = test_get_ip_address(session=bam, test_dictionary=test_ips)
    print(f'IPs:\n{ip_addresses}\n')
    ip_networks = test_get_network_by_ip(session=bam, test_dictionary=test_ips)
    print(f'Networks:\n{ip_networks}\n')
    roles = []
    for addy in ip_addresses:
        if addy['id'] != 0:
            roles += test_get_deployment_roles(session=bam, ipv4_address=addy['properties']['address'])
    print(f'\nDeployment Roles:')
    master_list = []
    for role in roles:
        if role['type'] == 'MASTER':
            if role['service'] == 'DNS':
                master_list.append(role)
            if role['service'] == 'DHCP':
                master_list.append(role)
        print(f'Role [{role["serverInterfaceId"]}]: {role["type"]} {role["service"]}')

    sorted_master_list = sort_and_filter_list_of_dicts(list_of_dicts=master_list, unique_key='serverInterfaceId')
    print(f'\nMaster:\n{sorted_master_list}')
    if test_deploy:
        print('\nTesting deployment:')
        for svr in sorted_master_list:
            server_id = int(svr['serverInterfaceId']) - 1
            print('Deploying...')
            bam.deploy_server_services(server_id=server_id, services='DNS,DHCP')
            time.sleep(delay)
            print('Checking status...')
            deploy_status = bam.get_deployment_status(server_id=server_id)
            print(f'Status: {deployment_status[deploy_status]}')
            while deploy_status < 2:
                time.sleep(2)
                deploy_status = bam.get_deployment_status(server_id=server_id)
                print(f'Status: {deployment_status[deploy_status]}')


if __name__ == '__main__':
    main()
