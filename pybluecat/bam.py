#!/usr/bin/python
import copy
import json
import logging
from functools import wraps
from ipaddress import ip_address, ip_network
from time import sleep

import requests

from pybluecat import data as bluecat_data
from pybluecat.data import *
from pybluecat.exceptions import BluecatError


class BAM:
    """
    About the Bluecat REST API:

    REST APIs have many similarities with the widely used SOAP-based APIs supported by Address
    Manager. However, there are a few differences between REST interface and existing SOAP
    implementation:
    - The names of API methods in REST remain the same as that of SOAP APIs.
    - Signatures of all methods including input and output parameters in REST are the same as in SOAP.
    - In REST API, various primitive request parameters such as int, long and String are expected as URL
    query parameters. Whereas in SOAP, all the request parameters are communicated as part of XML
    body.
    - Complex parameter types such as APIEntity or APIDeploymentOption need to be passed as a part of
    HTTP body of the call in JSON format.
    """

    def __init__(self, hostname=None, username=None, password=None, configname=None, loglevel='CRITICAL'):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.history = []
        self.last_call = None
        self.loglevel = loglevel
        self.logger = self.set_loglevel('pybluecat', loglevel)
        self.py_logger = self.set_loglevel('py.warnings', loglevel)
        self.session = self.init_session()
        self.session_v2 = self.init_session()
        self.base_url = f'https://{hostname}/Services/REST/v1/'
        self.base_url_v2 = f'https://{hostname}/api/v2/'
        if all(param is not None for param in [hostname, username, password]):
            self.login(username, password)
            self.config = self.getConfig(configname)
            # v2 API
            self.login_v2(username, password)
            self.config_v2 = self.get_config_v2(configname)
        else:
            raise Exception('Unable to authenticate, missing credentials.')

        self.config_id = self.config['id']
        self.config_v2_id = self.config_v2['data'][0]['id']
        self.logger.debug(f'Configuration ID | V1: {self.config_id} V2: {self.config_v2_id}')

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.logout()

    def init_session(
            self,
            session_proxies: dict = None,
            session_headers: dict = None,
            session_ssl_verify=None
    ):
        """
        Initialize a requests session object
        :param session_proxies: 
        :param session_headers:
        :param session_ssl_verify: 
        :return: Requests session object: requests.Session()
        """
        # Assign defaults
        if session_ssl_verify is None:
            session_ssl_verify = bluecat_data.ssl_verify

        if session_proxies is None:
            session_proxies = bluecat_data.proxies

        if session_headers is None:
            session_headers = bluecat_data.headers

        session = requests.Session()
        session.proxies.update(session_proxies)
        session.headers.update(session_headers)
        session.verify = session_ssl_verify
        if not ssl_verify:
            logging.captureWarnings(True)

        return session

    def set_loglevel(self, logger_name, loglevel):
        logger = logging.getLogger(logger_name)
        loglevel = loglevel.upper()
        if loglevel in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
            level_attr = getattr(logging, loglevel)
            # logging.basicConfig(level=level)
            logger.setLevel(level=level_attr)

        console_handler = logging.StreamHandler()
        logger.addHandler(console_handler)
        return logger

    ################################################################
    # DECORATORS
    ################################################################

    def rest_call(http_method):
        def rest_call_decorator(func):
            @wraps(func)
            def inner_wrapper(self, *args, **kwargs):
                method, params, data = func(self, *args, **kwargs)
                url = self.base_url + method
                method_map = {
                    'delete': self.session.delete,
                    'get': self.session.get,
                    'post': self.session.post,
                    'put': self.session.put
                }
                response = method_map[http_method](url, params=params, json=data)
                self.logger.debug(f'Request URL: {response.request.url}')
                self.logger.debug(f'Response Code: {response.status_code}')
                self.last_call = response
                self.history.append(response)
                # Handle non-200 responses
                if response.status_code != 200:
                    raise BluecatError(response)

                try:
                    data = response.json()
                    json_body = json.dumps(data, indent=2, sort_keys=True)
                    self.logger.debug(f'Response Body: {json_body}')
                except Exception as e:
                    data = response.content
                    self.logger.error(f'Error parsing response body as JSON: {e}')
                    self.logger.debug(f'Response Body: {data}')

                return data

            return inner_wrapper

        return rest_call_decorator

    def rest_call_v2(http_method):
        def rest_call_decorator(func):
            @wraps(func)
            def inner_wrapper(self, *args, **kwargs):
                method, params, data = func(self, *args, **kwargs)
                if method.startswith('?'):
                    url = self.base_url_v2[:-1] + method
                else:
                    url = self.base_url_v2 + method

                method_map = {
                    'delete': self.session_v2.delete,
                    'get': self.session_v2.get,
                    'patch': self.session.patch,
                    'post': self.session_v2.post,
                    'put': self.session_v2.put
                }
                response = method_map[http_method](url, params=params, json=data)
                self.logger.debug(f'Request URL: {response.request.url}')
                self.logger.debug(f'Response Code: {response.status_code}')
                self.last_call = response
                self.history.append(response)
                # Handle non-200 responses
                if response.status_code != 200:
                    raise BluecatError(response)

                try:
                    data = response.json()
                    json_body = json.dumps(data, indent=2, sort_keys=True)
                    self.logger.debug(f'Response Body: {json_body}')
                except Exception as e:
                    data = response.content
                    self.logger.error(f'Error parsing response body as JSON: {e}')
                    self.logger.debug(f'Response Body: {data}')

                return data

            return inner_wrapper

        return rest_call_decorator

    ################################################################
    # HELPERS
    ################################################################

    def prop_s2d(self, prop_string):
        """
        Convert a property string to a property dictionary
        :param prop_string:
        :return:
        """
        if prop_string is None:
            return None
        else:
            return {p[0]: p[1] for p in [pair.split('=') for pair in prop_string.split('|')[:-1]]}

    def prop_d2s(self, prop_dict):
        """
        Convert a property dictionary to a property string
        :param prop_dict:
        :return:
        """
        if prop_dict is None:
            return None
        else:
            return '|'.join(['='.join(pair) for pair in prop_dict.items()]) + '|'

    def entity_to_json(self, entity):
        """
        Convert an entity to JSON
        :param entity:
        :return:
        """
        entity['properties'] = self.prop_s2d(entity['properties'])
        return entity

    def json_to_entity(self, entity):
        """
        Convert JSON to an entity
        :param entity:
        :return:
        """
        entity['properties'] = self.prop_d2s(entity['properties'])
        return entity

    ################################################################
    # GENERAL STUFF
    ################################################################

    def login(self, username, password):
        method = 'login'
        params = {
            'username': username,
            'password': password
        }
        try:
            response = self.session.get(self.base_url + method, params=params)
            self.logger.info(response.content)
            auth_token = response.text.split('-> ')[1].split(' <-')[0]
            self.session.headers.update({'Authorization': str(auth_token)})
            return response
        except Exception as e:
            self.logger.error(f'Login to v1 API failed: {e}')

        return

    def login_v2(self, username, password):
        method = 'sessions'
        params = {
            'username': username,
            'password': password
        }
        try:
            response = self.session_v2.post(self.base_url_v2 + method, json=params)
            self.logger.info(response.text)
            response_dict = json.loads(response.text)
            auth_token = response_dict.get('basicAuthenticationCredentials', '')
            self.session_v2.headers.update({'Authorization': 'Basic ' + auth_token})
            return response
        except Exception as e:
            self.logger.error(f'Login to v2 API failed: {e}')

        return

    @rest_call('get')
    def logout(self):
        method = 'logout'
        params = None
        data = None
        return method, params, data

    @rest_call('get')
    def get_parent(self, entity_id, include_ha=True):
        method = 'getParent'
        params = {
            'entityId': entity_id,
            'includeHA': include_ha
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_entity_by_name(self, parent_id, name, obj_type):
        method = 'getEntityByName'
        params = {
            'parentId': parent_id,
            'name': name,
            'type': obj_type
        }
        data = None
        return method, params, data

    def getConfig(self, config_name):
        return self.get_entity_by_name(0, config_name, 'Configuration')

    @rest_call_v2('get')
    def get_config_v2(self, config_name):
        method = f'?filter=name:\'{config_name}\''
        params = {}
        data = None
        return method, params, data

    @rest_call('get')
    def get_entities(self, parent_id, obj_type, start=0, count=1000):
        method = 'getEntities'
        params = {
            'parentId': parent_id,
            'type': obj_type,
            'start': start,
            'count': count
        }
        data = None
        return method, params, data

    def get_networks(self, parent_id, start=0, count=1000):
        return self.get_entities(parent_id, 'IP4Network', start, count)

    @rest_call('get')
    def get_entity_by_id(self, entity_id):
        method = 'getEntityById'
        params = {
            'id': entity_id
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_linked_entities(self, entity_id, linked_type='IP4Address', start=0, count=100):
        method = 'getLinkedEntities'
        params = {
            'entityId': entity_id,
            'type': linked_type,
            'start': start,
            'count': count
        }
        data = None
        return method, params, data

    @rest_call('delete')
    def delete(self, entity_id):
        method = 'delete'
        params = {
            'objectId': entity_id
        }
        data = None
        return method, params, data

    @rest_call('put')
    def update(self, entity):
        method = 'update'
        params = None
        data = entity
        return method, params, data

    def update_dhcp_reservation(self, entity, hostname, mac_address):
        if isinstance(entity['properties'], str):
            entity = self.entity_to_json(entity)
        old_properties = entity['properties']
        new_properties = {}
        new_entity = copy.deepcopy(entity)
        # Set new properties
        new_entity['name'] = hostname
        new_properties['macAddress'] = mac_address
        # Reuse existing properties
        new_properties['state'] = old_properties['state']
        new_properties['address'] = old_properties['address']
        # Convert properties to string
        new_entity['properties'] = self.prop_d2s(new_properties)
        self.update(new_entity)

    ################################################################
    # DNS
    ################################################################

    @rest_call('post')
    def add_resource_record(
            self,
            absolute_name: str,
            view_id,
            ip_address: str,
            ttl: int = 300,
            obj_type: str = 'HostRecord',
            properties: str = '',
    ):
        """
        Add a resource record.

        :param absolute_name:
        :param view_id:
        :param ip_address:
        :param ttl:
        :param obj_type:
            Valid object types:
                AliasRecord
                HINFORecord
                HostRecord
                MXRecord
                TXTRecord
        :param properties:
        :return:
        """
        method = 'addResourceRecord'
        params = {
            'absoluteName': absolute_name,
            'properties': properties,
            'rdata': ip_address,
            'ttl': ttl,
            'type': obj_type,
            'viewId': view_id
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_resource_record_by_hint(
            self,
            hint: str,
            count: int = 10,
            start: int = 0,
            retrieve_fields=False
    ):
        """
        Retrieve a host record by hint

        :param count:
        :param hint:
        :param start:
        :param retrieve_fields:
        :return:
        """
        if retrieve_fields:
            options = f'hint={hint}|retrieveFields=true'
        else:
            options = f'hint={hint}|retrieveFields=false'
        method = 'getHostRecordsByHint'
        params = {
            'count': count,
            'options': options,
            'start': start,
        }
        data = None
        return method, params, data

    ################################################################
    # SEARCHES
    ################################################################
    @rest_call('get')
    def custom_search(self, obj_type=None, start=0, count=1000, filters=None, include_ha=False):
        method = 'customSearch'
        if filters is None:
            filters = {}

        if obj_type is None:
            obj_type = 'IP4Address'

        # Convert filters to key=value string
        kv_filters = [f'{key}={value}' for key, value in filters.items()]

        params = {
            'filters': kv_filters,
            'type': obj_type,
            'start': start,
            'count': count,
            'includeHA': include_ha
        }
        data = None
        return method, params, data

    @rest_call('get')
    def search_by_object_types(self, keyword, obj_type, start=0, count=10, include_ha=False):
        method = 'searchByObjectTypes'
        params = {
            'keyword': keyword,
            'types': obj_type,
            'start': start,
            'count': count,
            'includeHA': include_ha
        }
        data = None
        return method, params, data

    def search_ip_by_name(self, keyword, start=0, count=100):
        return self.search_by_object_types(keyword, 'IP4Address', start, count)

    def search_ip_by_mac(self, keyword, start=0, count=100):
        return self.search_by_object_types(keyword, 'MACAddress', start, count)

    def search_ip_by_host(self, keyword, start=0, count=100):
        return self.search_by_object_types(keyword, 'HostRecord', start, count)

    @rest_call('get')
    def search_by_category(self, keyword, category, start=0, count=10, include_ha=False):
        method = 'searchByCategory'
        params = {
            'keyword': f'{keyword}*',
            'category': category,
            'count': count,
            'start': start,
            'includeHA': include_ha
        }
        data = None
        return method, params, data

    ################################################################
    # NETWORK STUFF
    ################################################################

    @rest_call('get')
    def get_entity_by_cidr(self, parent_id, cidr, obj_type):
        """
        config.id only works for top-level blocks, parent_id must literally be the parent object's id
        """
        method = 'getEntityByCIDR'
        params = {
            'parentId': parent_id,
            'cidr': cidr,
            'type': obj_type
        }
        data = None
        return method, params, data

    def get_network_by_cidr(self, parent_id, cidr):
        return self.get_entity_by_cidr(parent_id, cidr, 'IP4Network')

    def get_block_by_cidr(self, parent_id, cidr):
        return self.get_entity_by_cidr(parent_id, cidr, 'IP4Block')

    @rest_call('get')
    def get_entity_by_range(self, parent_id, ipv4_address1, ipv4_address2, obj_type):
        method = 'getEntityByRange'
        params = {
            'parentId': parent_id,
            'address1': ipv4_address1,
            'address2': ipv4_address2,
            'type': obj_type,
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_ip_ranged_by_ip(self, parent_id, ipv4_address, obj_type):
        method = 'getIPRangedByIP'
        if isinstance(ipv4_address, list):
            search_address = ipv4_address[0]
        elif isinstance(ipv4_address, str):
            search_address = ipv4_address
        else:
            raise TypeError('Invalid type for ipv4_address')
        # Remove CIDR notation
        search_address = search_address.split('/')[0]
        params = {
            'containerId': parent_id,
            'type': obj_type,
            'address': search_address
        }
        data = None
        return method, params, data

    def get_network(self, ipv4_address):
        return self.get_ip_ranged_by_ip(self.config_id, ipv4_address, 'IP4Network')

    def get_network_by_ip(self, ipv4_address):
        """
        :param ipv4_address: ip address in string format
        :return: json object of the network

        :example:
        {
            'id': 48323,
            'name':
            'YIT Users',
            'type':
            'IP4Network',
            'properties': 'VlanId=800|vrf=default|CIDR=10.8.0.0/23|gateway=10.8.0.1|'
        }
        """
        return self.get_ip_ranged_by_ip(self.config_id, ipv4_address, 'IP4Network')

    def get_block_by_ip(self, ipv4_address):
        return self.get_ip_ranged_by_ip(self.config_id, ipv4_address, 'IP4Block')

    def get_dhcp_scope_by_ip(self, ipv4_address):
        return self.get_ip_ranged_by_ip(self.config_id, ipv4_address, 'DHCP4Range')

    @rest_call('post')
    def assign_ipv4network(self, parent_id, cidr, properties_dict):
        method = 'addIP4Network'
        properties = '|'.join(f'{key}={val}' for key, val in properties_dict.items())
        params = {
            'blockId': parent_id,
            'CIDR': cidr,
            'properties': properties
        }
        data = None
        return method, params, data

    ################################################################
    # IP ADDRESS STUFF
    ################################################################

    @rest_call('get')
    def get_ip_address(self, ip_addr, parent_id=None):
        """
        Retrieve an IP address object by its address
        :param ip_addr:
        :param parent_id:
        :return: dict
        :example:
        Record found:
        {
          'id': 58132,
          'name': None,
          'type': 'IP4Address',
          'properties': 'macAddress=00-07-4D-63-93-09|address=10.8.0.201|state=DHCP_RESERVED|'
        }
        Record not found:
        {
          'id': 0,
          'name': None,
          'type': None,
          'properties': None
        }
        """
        method = 'getIP4Address'
        params = {
            'containerId': self.config_id if parent_id is None else parent_id,
            'address': ip_addr
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_next_ip_address(self, network_id, offset=None, dhcp_exclude=True):
        method = 'getNextIP4Address'
        excluderange = str(dhcp_exclude).lower()
        properties = f'excludeDHCPRange={excluderange}|'
        if offset is not None:
            properties += f'offset={offset}|'
        params = {
            'parentId': network_id,
            'properties': properties
        }
        data = None
        return method, params, data

    @rest_call('post')
    def assign_next_ip_address(
            self,
            parent_id,
            hostname,
            mac_address=None,
            host_info='',
            action='MAKE_STATIC',
            properties='',
            offset=None
    ):
        method = 'assignNextAvailableIP4Address'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        properties += f'name={hostname}|'
        if offset is not None:
            properties += f'offset={offset}|'
        params = {
            'configurationId': self.config_id,
            'parentId': parent_id,
            'macAddress': mac_address,
            'hostInfo': host_info,
            'action': action,
            'properties': properties
        }
        data = None
        return method, params, data

    @rest_call('post')
    def add_tag(self, parent_id, name, properties=''):
        method = 'addTag'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        params = {
            'parentId': parent_id,
            'name': name,
            'properties': properties,
        }
        data = None
        return method, params, data

    @rest_call('put')
    def link_entities(self, entity_id_1, entity_id_2, properties=''):
        method = 'linkEntities'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        params = {
            'entity1Id': entity_id_1,
            'entity2Id': entity_id_2,
            'properties': properties,
        }
        data = None
        return method, params, data

    @rest_call('post')
    def add_ip_block_by_cidr(self, parent_id, cidr, addr_name, properties=''):
        method = 'addIP4BlockByCIDR'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        properties += f'name={addr_name}|'
        params = {
            'parentId': parent_id,
            'CIDR': cidr,
            'properties': properties
        }
        data = None
        return method, params, data

    @rest_call('post')
    def add_ip_network_by_cidr(self, block_id, cidr, name, properties=''):
        method = 'addIP4Network'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        properties += f'name={name}|'
        properties += 'gateway='
        params = {
            'blockId': block_id,
            'CIDR': cidr,
            'properties': properties,
        }
        data = None
        return method, params, data

    @rest_call('post')
    def add_device(self, name, device_type_id, device_subtype_id, ipv4_addresses, ipv6_addresses, properties=''):
        method = 'addDevice'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        params = {
            'configurationId': self.config_id,
            'name': name,
            'deviceTypeId': str(device_type_id),
            'deviceSubtypeId': str(device_subtype_id),
            'ip4Addresses': str(ipv4_addresses),
            'ipv6Addresses': str(ipv6_addresses),
            'properties': properties,
        }
        data = None
        return method, params, data

    @rest_call('post')
    def assign_ip_address(
            self,
            hostname,
            ipv4_address,
            mac_address='',
            host_info='',
            action='MAKE_STATIC',
            properties=''
    ):
        method = 'assignIP4Address'
        if isinstance(properties, dict):
            properties = self.prop_d2s(properties)
        properties += f'name={hostname}|'
        params = {
            'configurationId': self.config_id,
            'ip4Address': str(ipv4_address),
            'macAddress': mac_address,
            'hostInfo': host_info,
            'action': action,
            'properties': properties,
        }
        data = None
        return method, params, data

    def assign_ip_address_pair(self, net1, net2, hostname1, hostname2=None):
        """
        Assigns matching addresses in two separate, but equal-sized, networks
        The networks are expected to be in CIDR notation
        """
        if hostname2 is None:
            hostname2 = hostname1
        # Get Network Objects and set dhcp_offset based on env
        net1 = ip_network(unicode(net1))
        net2 = ip_network(unicode(net2))
        if net1.netmask != net2.netmask:
            raise ValueError('net1 and net2 CIDR prefixes are not equal')
        bam_net_1 = self.get_network(str(net1.network_address))
        bam_net_2 = self.get_network(str(net2.network_address))
        if net1.prefixlen > 24:
            dhcp_offset = 1
        else:
            dhcp_offset = 31
        mask = int(net1.netmask) ^ 2 ** 32 - 1  # mask to determine ip's place in network
        # Ensure Hostname doesn't already exist in BAM
        found_ip = False
        response1 = self.get_entity_by_name(bam_net_1['id'], hostname1, 'IP4Address')
        response2 = self.get_entity_by_name(bam_net_2['id'], hostname2, 'IP4Address')
        if any(r['properties'] is not None for r in [response1, response2]):
            bam_ip_list = [self.entity_to_json(response1), self.entity_to_json(response2)]
            found_ip = True
        # If hostname doesn't exist, begin looping through networks for available address pairs
        while not found_ip and dhcp_offset < mask:
            dhcp_offset1 = str(net1.network_address + dhcp_offset)
            dhcp_offset2 = str(net2.network_address + dhcp_offset)
            ip1 = ip_address(self.get_next_ip_address(bam_net_1['id'], offset=dhcp_offset1))
            ip2 = ip_address(self.get_next_ip_address(bam_net_2['id'], offset=dhcp_offset2))
            if any(ip is None for ip in [ip1, ip2]):
                print('ERROR: out of IPs :(')
                found_ip = True
            else:
                # use mask to determine the ip's network index, e.g. in 10.20.30.0/23 10.20.31.15 = 271
                num1 = int(ip1) & int(mask)
                num2 = int(ip2) & int(mask)
                # if the ip's have the same network index, go ahead with assignment
                if num1 == num2:
                    ipObj1 = self.assign_ip_address(hostname1, str(ip1))
                    ipObj2 = self.assign_ip_address(hostname2, str(ip2))
                    bam_ip_list = [ipObj1, ipObj2]
                    found_ip = True
                # if the ip's have different indexes, continue looking at the highest of the two indexes
                elif num1 > num2:
                    dhcp_offset = num1 - 1
                else:
                    dhcp_offset = num2 - 1
        return bam_ip_list

    ################################################################
    # MAC ADDRESS STUFF
    ################################################################

    @rest_call('get')
    def get_mac_address(self, mac):
        method = 'getMACAddress'
        params = {
            'configurationId': self.config_id,
            'macAddress': mac.replace('.', '').replace(':', '').replace('-', '')
        }
        data = None
        return method, params, data

    @rest_call('post')
    def create_mac_address(self, mac, name, properties):
        method = 'addMACAddress'
        if isinstance(properties, dict):
            properties_string = f'name={name}|' + self.prop_d2s(properties)
        else:
            properties_string = f'name={name}|' + properties
        params = {
            'configurationId': self.config_id,
            'macAddress': mac.replace('.', '').replace(':', '').replace('-', ''),
            'properties': properties_string
        }
        data = None
        return method, params, data

    ################################################################
    # ROLE AND DEPLOYMENT STUFF
    ################################################################

    @rest_call('get')
    def get_deployment_roles(self, entity_id):
        method = 'getDeploymentRoles'
        params = {
            'entityId': entity_id
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_server_for_role(self, role_id):
        method = 'getServerForRole'
        params = {
            'roleId': role_id
        }
        data = None
        return method, params, data

    @rest_call('get')
    def get_deployment_status(self, server_id):
        method = 'getServerDeploymentStatus'
        params = {
            'serverId': server_id,
            'properties': ''
        }
        data = None
        return method, params, data

    @rest_call('post')
    def deploy_server(self, server_id):
        method = 'deployServer'
        params = {
            'serverId': server_id
        }
        data = None
        return method, params, data

    @rest_call('post')
    def deploy_server_config(self, server_id, services='DHCP', full=False):
        method = 'deployServerConfig'
        properties = f'ObjectProperties.services={services}'
        if full and 'DNS' in services:
            properties += '|forceDNSFullDeployment=true'
        params = {
            'serverId': server_id,
            'properties': properties
        }
        data = None
        return method, params, data

    @rest_call('post')
    def deploy_server_services(self, server_id, services='DHCP'):
        method = 'deployServerServices'
        params = {
            'serverId': server_id,
            'services': f'services={services}'
        }
        data = None
        return method, params, data

    def queue_servers(self, network_id, server_set=None):
        """
        Given a set and a network_id, determines the primary
        and backup servers for the network and adds them to the
        set. The resulting set is then returned.
        """
        if server_set is None:
            server_set = set()
        deploy_roles = self.get_deployment_roles(network_id)
        server_primary = self.get_server_for_role(deploy_roles[0]['id'])
        server_backup_id = bluecat_data.adonis_pairs[server_primary['id']]
        server_set.add(server_primary['id'])
        server_set.add(server_backup_id)
        return server_set

    def deploy_dhcp_and_monitor(self, server_set):
        """Given a set of servers to deploy, each server will be
        deployed. The deployment status will be followed until all
        have terminated in some way.
        """
        for server in server_set:
            self.deploy_server_services(server, 'DHCP')
        self.monitor_server_deployment(server_set)

    def monitor_server_deployment(self, server_set):
        """Given a set of servers that have been deployed, the status
        of each will be continuously polled until all have reached a
        final state.
        """
        for server in server_set:
            status = self.get_deployment_status(server)
            self.logger.info(f'{bluecat_data.adonis_id_map[server]} - {bluecat_data.deployment_status[status]}')
        while len(server_set) > 0:
            sleep(2)
            servers = list(server_set)
            for server in servers:
                status = self.get_deployment_status(server)
                if status not in [-1, 0, 1]:
                    self.logger.info(f'{bluecat_data.adonis_id_map[server]} - {bluecat_data.deployment_status[status]}')
                    server_set.remove(server)


################################################################
# IF RUN DIRECTLY, MOSTLY FOR TESTING
################################################################

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('creds')
    parser.add_argument('-l', '--loglevel', choices=['critical', 'error', 'warning', 'info', 'debug'],
                        default='critical', help='enable logging')
    cli_args = parser.parse_args()
    # Load credentials
    with open(cli_args.creds) as f:
        creds = json.load(f)
    # Enable logging if requested
    if cli_args.loglevel:
        level = getattr(logging, cli_args.loglevel.upper())
        logging.basicConfig(level=level)
