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

def parse_args():
    parser = argparse.ArgumentParser(description='Anomaly detection in BGP+ACME data')
    parser.add_argument('--database', '-d', type=str, nargs=1, default="localhost", help='Database network location')
    parser.add_argument('--input', '-i', type=str, nargs=1, default='./in.jsonl', help='Input certificate requests to classify')
    parser.add_argument('--update_certificates', '-u', action="store_true", default=False)
    return parser.parse_args()

def main():
    args = parse_args()
    #load model
    (start, end) = get_time_range(args)
    print(start, "->", end)
    update_bgp(args, start, end)
    #for each input
        #extract features
        #get score
    #get N most aberrant issuances and links to RIPEstat
    #dump certificates

if __name__== "__main__":
    main()
