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

WINDOW = timedelta(days = 10)

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

def get_updates(collector, start, end):
    print("getting updates for {} from {} to {}".format(collector, start, end))
    stream = BGPStream()
    rec = BGPRecord()
    stream.add_filter('collector',collector)
    stream.add_interval_filter(int(start.timestamp()), int(end.timestamp()))
    stream.add_filter('record-type', 'updates')
    stream.start()
    while(stream.get_next_record(rec)):
        if rec.status == "valid":
            elem = rec.get_next_elem()
            while(elem):
                if elem.type == 'A':
                    yield ('A', rec.project, rec.collector, datetime.utcfromtimestamp(rec.time).isoformat(), elem.peer_address, elem.peer_asn, elem.fields['prefix'], elem.fields['as-path'])
                elif elem.type == 'W':
                    yield ('W', rec.project, rec.collector, datetime.utcfromtimestamp(rec.time).isoformat(), elem.peer_address, elem.peer_asn, elem.fields['prefix'], None)
                elem = rec.get_next_elem()

def reset_rib_database(cur, project, collector, start, period, end):
    print("resetting rib for {} from {}".format(collector, start))
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
    f.seek(0)
    cur.copy_from(file=f, table='bgp_rib', columns=('project', 'collector', 'time', 'peer_addr', 'peer_asn', 'prefix', 'as_path'))

def extend_updates(cur, collector, old_end, end):
    updates = StringIO()
    i = 0
    for value in get_updates(collector, old_end, end):
        i+=1
        updates.write('\t'.join(map(str, value))+'\n')
        if i % 1000000 == 0:
            updates.seek(0)
            cur.copy_from(file=updates, table='bgp_update', columns=('kind', 'project', 'collector', 'time', 'peer_addr', 'peer_asn', 'prefix', 'as_path'))
            updates = StringIO()
    updates.seek(0)
    cur.copy_from(file=updates, table='bgp_update', columns=('kind', 'project', 'collector', 'time', 'peer_addr', 'peer_asn', 'prefix', 'as_path'))

def roll_updates_to_rib(cur, collector, start):
    print("rolling updates for {} to {}".format(collector, start))
    cur.execute('''
    update bgp_rib
    set time=t.time, peer_asn=t.peer_asn, prefix=t.prefix, as_path=t.as_path
    from (
        select *
        from bgp_update as t
        where collector = %s and time <= %s and
        NOT EXISTS (
            SELECT *
            FROM bgp_update AS witness
            WHERE witness.time > t.time
                and witness.collector = t.collector
                and witness.prefix = t.prefix
                and witness.peer_addr = t.peer_addr
        )
    ) as t
    where bgp_rib.collector = t.collector
        and bgp_rib.prefix = t.prefix
        and bgp_rib.peer_addr = t.peer_addr
        and t.kind = 'A'
    ''', (collector, start))

    cur.execute('''
    delete from bgp_rib
    using (
        select *
        from bgp_update as t
        where collector = %s and time <= %s and
        NOT EXISTS (
            SELECT *
            FROM bgp_update AS witness
            WHERE witness.time > t.time
                and witness.collector = t.collector
                and witness.prefix = t.prefix
                and witness.peer_addr = t.peer_addr
        )
    ) as t
    where bgp_rib.collector = t.collector
        and bgp_rib.prefix = t.prefix
        and bgp_rib.peer_addr = t.peer_addr
        and t.kind = 'W'
    ''', (collector, start))

    cur.execute('''
    delete from bgp_update
    where time <= %s''', (start,))

def update_bgp(args, start, end):
    conn = psycopg2.connect('host={} user=postgres password=example'.format(args.database))
    cur = conn.cursor()
    cur.execute('select * from bgp_metadata;')
    rows = cur.fetchall()
    for row in rows:
        (project, collector, period, old_start, old_end) = row
        if old_start != None and old_end != None:
            if start >= old_start and end <= old_end:
                #continue
                pass
        else:
            old_start = datetime(1970,1,1,tzinfo=timezone.utc)
            old_end = datetime(1970,1,1,tzinfo=timezone.utc)
        print(old_start, "->", old_end)
        if old_start > start or old_end + timedelta(days=1) < start:
            reset_rib_database(cur, project, collector, start, period, end)
            old_start = start
            old_end = start
        if old_end < end:
            extend_updates(cur, collector, old_end, end)
        if old_start < start:
            roll_updates_to_rib(cur, collector, start)
        cur.execute('update bgp_metadata set rib_time = %s, update_to = %s  where project = %s and collector = %s', (start, end, project, collector))
    conn.commit()
    conn.close()
