import argparse
from io import StringIO
import simplejson as json
from dateutil.parser import isoparse
from datetime import datetime, timedelta, timezone
import sys
import psycopg2
from psycopg2.extras import execute_values
from _pybgpstream import BGPStream, BGPRecord, BGPElem
import itertools

def date_parse_hook(json_dict):
    ret = {}
    for (key, value) in json_dict.items():
        if key in ['not_before', 'not_after', 'time', 'validation_time']:
            ret[key] = isoparse(value)
        else:
            ret[key] = value
    return ret

def schema_helper(obj, key, path=''):
    if key not in obj:
        print("missing field '{}' in input".format(path+key), file=sys.stderr)
        exit(0)

def assert_schema(obj):
    schema_helper(obj, 'serial')
    schema_helper(obj, 'not_before')
    schema_helper(obj, 'not_after')
    schema_helper(obj, 'kid')
    schema_helper(obj, 'acme_client_address')
    schema_helper(obj, 'public_key_fingerprint')
    schema_helper(obj, 'identifiers')
    for i, identifier in enumerate(obj['identifiers']):
        schema_helper(identifier, 'identifier', 'identifiers[{}].'.format(i))
        schema_helper(identifier, 'addresses', 'identifiers[{}].'.format(i))
        for j, address in enumerate(identifier['addresses']):
            schema_helper(address, 'client', 'identifiers[{}].addresses[{}].'.format(i,j))
            schema_helper(address, 'server', 'identifiers[{}].addresses[{}].'.format(i,j))
            schema_helper(address, 'time', 'identifiers[{}].addresses[{}].'.format(i,j))
