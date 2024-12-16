#!/usr/bin/python
import ipaddress


def properties_s2d(prop_string):
    """
    Convert a string of properties to a dictionary
    :param prop_string:
    :return: dictionary of properties:
    """
    return {p[0]: p[1] for p in [pair.split('=') for pair in prop_string.split('|')[:-1]]}


def properties_d2s(prop_dict):
    """
    Convert a dictionary of properties to a string
    :param prop_dict:
    :return: string of properties:
    """
    return '|'.join(['='.join(pair) for pair in prop_dict.items()]) + '|'


def convert_ip_to_bind(ip_address: str):
    """
    Function to convert an IP address to a BIND format. Supports IPv4 and IPv6.

    :param ip_address:
    :return: BIND formatted IP address
    """
    try:
        ip_address = ipaddress.ip_address(ip_address)
        if ip_address.version == 4:
            return f'A {ip_address}'
        elif ip_address.version == 6:
            return f'AAAA {ip_address}'
        else:
            return None
    except Exception as e:
        print(f'Error: {e}')


def validate_ip_address(ip_address):
    """
    Function that validates that a string is a valid IP address. Supports IPv4 and IPv6.
    :param ip_address:
    :return:
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except Exception as e:
        print(f'Error: {e}')
        return False


def validate_fqdn(fqdn):
    """
    Function that accepts a string and validates that it is a valid fully qualified domain name (FQDN).
    :param fqdn:
    :return:
    """
    try:
        fqdn = fqdn.lower()
        if fqdn[-1] == '.':
            fqdn = fqdn[:-1]
        if len(fqdn) > 255:
            return False
        labels = fqdn.split('.')
        for label in labels:
            if len(label) > 63:
                return False
            if label[-1] == '-':
                return False
        if fqdn[-1] == '-':
            return False
        return True
    except Exception as e:
        print(f'Error: {e}')
        return False
