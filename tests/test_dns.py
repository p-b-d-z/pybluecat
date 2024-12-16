import os

import pybluecat
from pybluecat.data import helpers
from test_data import *


def test_add_resource_record(session, test_dictionary, view_name='Internal'):
    """
    Add a resource record to the Internal view

    :param session:
    :param test_dictionary:
    :return:
    """
    view_object_results = session.search_by_object_types(keyword='*', obj_type='View', count=20)
    view_id = 0
    for view in view_object_results:
        if view['name'] == view_name:
            view_id = int(view['id'])
            break
    print(f'\nView ID: {view_id}')
    # Validate FQDN
    valid_fqdn = pybluecat.data.helpers.validate_fqdn(fqdn=test_dictionary['absolute_name'])
    print(f'\nValid FQDN: {valid_fqdn}')
    if not valid_fqdn:
        print(f'\nInvalid FQDN: {test_dictionary["absolute_name"]}')
        return None

    valid_ip = pybluecat.data.helpers.validate_ip_address(ip_address=test_dictionary['ip_address'])
    print(f'\nValid IP: {valid_ip}')
    if not valid_ip:
        print(f'\nInvalid IP: {test_dictionary["ip_address"]}')
        return None

    # Due diligence
    record_object_results = session.search_by_object_types(
        keyword=test_dictionary['absolute_name'],
        obj_type='HostRecord',
        count=20
    )
    print(f'\nRecord objects: {record_object_results}')
    ipaddress_object_results = session.search_by_object_types(
        keyword=test_dictionary['ip_address'],
        obj_type='IP4Address',
        count=20
    )
    print(f'\nIP Address objects: {ipaddress_object_results}')
    hint_records = session.get_resource_record_by_hint(hint=test_dictionary['absolute_name'])
    print(f'\nHint record(s): {hint_records}')
    if len(hint_records) > 0:
        print(f'\nRecord exists: {hint_records[0]["id"]}')
        return int(hint_records[0]["id"])
    # Attempt to add the record
    try:
        entity_id = session.add_resource_record(**test_dictionary, view_id=view_id)
        print(f'\nAdded RR: {entity_id}')
        return entity_id
    except Exception as e:
        print(f'Cannot add the record: {e}')
        return None


def main():
    bam_host = os.getenv('BLUECAT_HOST')
    bam_user = os.getenv('BLUECAT_USER')
    bam_pass = os.getenv('BLUECAT_PASS')
    bam_cfg = os.getenv('BLUECAT_CFG')
    bam = pybluecat.BAM(bam_host, bam_user, bam_pass, bam_cfg)

    # Test helpers
    bad_ip = '10.0.0'
    bad_fqdn = 'testing'
    test_bad_ip = pybluecat.data.helpers.validate_ip_address(ip_address=bad_ip)
    test_bad_fqdn = pybluecat.data.helpers.validate_fqdn(fqdn=bad_fqdn)
    print(f'\nBad IP test, valid IP: {test_bad_ip}')
    print(f'\nBad FQDN test, valid FQDN: {test_bad_fqdn}')
    new_record_id = test_add_resource_record(session=bam, test_dictionary=test_dns)
    new_entity = bam.get_entity_by_id(entity_id=new_record_id)
    print(f'\nNew entity: {new_entity}')


if __name__ == '__main__':
    main()
