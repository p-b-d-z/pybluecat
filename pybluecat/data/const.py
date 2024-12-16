#!/usr/bin/python

# Bluecat action values
deployment_status = {
    -1: 'EXECUTING',
    0: 'INITIALIZING',
    1: 'QUEUED',
    2: 'CANCELLED',
    3: 'FAILED',
    4: 'NOT_DEPLOYED',
    5: 'WARNING',
    6: 'INVALID',
    7: 'DONE',
    8: 'NO_RECENT_DEPLOYMENT'
}

# Valid HTTP request methods
http_request_methods = [
    'GET',
    'POST',
    'PATCH',  # Only some updates, most use PUT
    'PUT',
    'DELETE'
]
# HTTP response codes
http_response_codes = {
    '200': 'OK',
    '201': 'Created',
    '202': 'Accepted',
    '204': 'No Content',
    '308': 'Permanent Redirect',
    '400': 'Bad Request',
    '401': 'Unauthorized',
    '403': 'Forbidden',
    '404': 'Not Found',
    '405': 'Method Not Allowed',
    '406': 'Not Acceptable',
    '409': 'Conflict',
    '415':  'Unsupported Media Type',
    '429': 'Too Many Requests',
    '500': 'Internal Server Error',
    '501': 'Not Implemented',
}
ip_action_values = [
        'MAKE_STATIC',
        'MAKE_RESERVED',
        'MAKE_DHCP_RESERVED'
    ]

# Bluecat session values
proxies = {
    'http': None,
    'https': None
}

ssl_verify = False

headers = {
    'Content-Type': 'application/json'
}

# Legacy adonis values

adonis_pairs = {}

adonis_id_map = {}
