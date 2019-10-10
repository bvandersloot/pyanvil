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

WINDOW = timedelta(days=10)

def parse_args():
    parser = argparse.ArgumentParser(description='Anomaly detection in BGP+ACME data')
    parser.add_argument('--database', '-d', type=str, nargs=1, default="localhost", help='Database network location')
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

def get_ribs(collector, start, period):
    stream = BGPStream()
    rec = BGPRecord()
    stream.add_filter('collector',collector)
    stream.add_interval_filter(int(start.timestamp()) - period,int(start.timestamp()))
    stream.add_filter('record-type', 'ribs')
    stream.start()
    while(stream.get_next_record(rec)):
        if rec.status == "valid":
            elem = rec.get_next_elem()
            while(elem):
                yield (rec.project, rec.collector, datetime.utcfromtimestamp(rec.time).isoformat(), elem.peer_address, elem.peer_asn, elem.fields['prefix'], elem.fields['as-path'])
                elem = rec.get_next_elem()

def update_bgp(args, start, end):
    conn = psycopg2.connect('host={} user=postgres password=example'.format(args.database))
    cur = conn.cursor()
    cur.execute('select * from bgp_metadata;')
    rows = cur.fetchall()
    for row in rows:
        (project, collector, period, old_start, old_end) = row
        if old_start != None and old_end != None:
            old_start = isoparse(old_start)
            old_end = isoparse(old_end)
            if start >= old_start and end <= old_end:
                continue
        else:
            old_start = datetime(1970,1,1,tzinfo=timezone.utc)
            old_end = datetime(1970,1,1,tzinfo=timezone.utc)
        if old_start > start or old_end + timedelta(days=1) < start:
            cur.execute('delete from bgp_rib where project = %s and collector = %s', (project, collector))
            i = 0
            f = StringIO()
            for value in get_ribs(collector, start, period):
                i+=1
                f.write('\t'.join(map(str, value))+'\n')
                if i % 1000000 == 0:
                    f.seek(0)
                    cur.copy_from(file=f, table='bgp_rib', columns=('project', 'collector', 'time', 'peer_addr', 'peer_asn', 'prefix', 'as_path'))
                    f = StringIO()
                    print(i)
        #extend end
        #roll beginning
        print(row)
    conn.close()

def main():
    args = parse_args()
    #load model
    (start, end) = get_time_range(args)
    update_bgp(args, start, end)
    #for each input
        #extract features
        #get score
    #get N most aberrant issuances and links to RIPEstat
    #dump certificates

if __name__== "__main__":
    main()
