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

from parse import *
from bgp import *

def get_parsed_certificates(filename):
    with open(filename) as f:
        for l in f:
            obj = json.loads(l,  object_hook=date_parse_hook)
            yield obj

def get_time_range(args):
    start = None
    end = None
    for obj in get_parsed_certificates(args.input):
        assert_schema(obj)
        for i, identifier in enumerate(obj['identifiers']):
            for j, address in enumerate(identifier['addresses']):
                if start == None or address['time'] < start:
                    start = address['time']
                if end == None or address['time'] > end:
                    end = address['time']
    return (start-WINDOW, end)

def upload_certificates(args):
    conn = psycopg2.connect('host={} user=postgres password=example'.format(args.database))
    cur = conn.cursor()
    updates = StringIO()
    i = 0
    for obj in get_parsed_certificates(args.input):
        weak_assert_schema(obj)
        for identifier in obj['identifiers']:
            for address in identifier['addresses']:
                i+=1
                value = (obj['serial'], obj['kid'], obj['acme_client_address'], obj['not_before'], obj['not_after'], obj['public_key_fingerprint'], identifier['identifier'], address['client'], address['server'], address['time'])
                updates.write('\t'.join(map(str, value))+'\n')
                if i % 1000000 == 0:
                    updates.seek(0)
                    cur.copy_from(file=updates, table='issued_certificates', columns=('serial', 'kid', 'acme_client_address', 'not_before', 'not_after', 'public_key_fingerprint', 'identifier', 'validation_client_address', 'validation_server_address', 'validation_time'))
                    updates = StringIO()
            updates.seek(0)
            cur.copy_from(file=updates, table='issued_certificates', columns=('serial', 'kid', 'acme_client_address', 'not_before', 'not_after', 'public_key_fingerprint', 'identifier', 'validation_client_address', 'validation_server_address', 'validation_time'))
    conn.commit()
    conn.close()

def parse_args():
    parser = argparse.ArgumentParser(description='Anomaly detection in BGP+ACME data')
    parser.add_argument('--database', '-d', type=str, nargs=1, default="localhost", help='Database network location')
    parser.add_argument('--input', '-i', type=str, nargs=1, default='./in.jsonl', help='Input certificate requests to classify')
    parser.add_argument('--update_certificates', '-u', action="store_true", default=False)
    parser.add_argument('--only_insert_certificates', '-c', action="store_true", default=False, help='Only insert the certificates specified by --input to the database; constraints are relaxed on ACME-centric data')
    return parser.parse_args()

def main():
    args = parse_args()
    #load model
    if not args.only_insert_certificates:
        (start, end) = get_time_range(args)
        print(start, "->", end)
        update_bgp(args, start, end)

        #for each input
            #extract features
            #get score
        #get N most aberrant issuances and links to RIPEstat

    #dump certificates
    if args.only_insert_certificates or args.update_certificates:
        upload_certificates(args)




if __name__== "__main__":
    main()
