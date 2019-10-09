import argparse
import simplejson as json
from dateutil.parser import isoparse
from datetime import datetime, timedelta
import sys

WINDOW = timedelta(days=10)

def parse_args():
    parser = argparse.ArgumentParser(description='Anomaly detection in BGP+ACME data')
    parser.add_argument('--database', '-d', type=str, nargs=1, default="localhost:5432", help='Database network location')
    parser.add_argument('--input', '-i', type=str, nargs=1, default='./in.jsonl', help='Input certificate requests to classify')
    parser.add_argument('--update_database', '-u', action="store_true", default=False)
    return parser.parse_args()

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


def get_time_range(args):
    start = None
    end = None
    with open(args.input) as f:
        for l in f:
            obj = json.loads(l,  object_hook=date_parse_hook)
            print(obj)
            assert_schema(obj)
            for i, identifier in enumerate(obj['identifiers']):
                for j, address in enumerate(identifier['addresses']):
                    if start == None or address['time'] < start:
                        start = address['time']
                    if end == None or address['time'] > end:
                        end = address['time']
    return (start-WINDOW, end)

def update_bgp(args):

    pass

def main():
    args = parse_args()
    (start, end) = get_time_range(args)

if __name__== "__main__":
    main()
