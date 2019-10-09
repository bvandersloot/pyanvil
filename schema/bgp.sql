CREATE EXTENSION IF NOT EXISTS ip4r;

create table bgp_announce (
	id serial primary key,
	project varchar not null,
	collector varchar not null,
	time timestamptz not null,
	peer_addr ipaddress not null,
	peer_asn integer not null,
	prefix iprange not null,
	as_path varchar not null 
);

create table bgp_withdraw (
	id serial primary key,
	project varchar not null,
	collector varchar not null,
	time timestamptz not null,
	peer_addr ipaddress not null,
	peer_asn integer not null,
	prefix iprange not null 
);

create table bgp_rib (
	id serial primary key,
	project varchar not null,
	collector varchar not null,
	time timestamptz not null,
	peer_addr ipaddress not null,
	peer_asn integer not null,
	prefix iprange not null,
	as_path varchar not null 
);

CREATE INDEX i_announce_prefix ON bgp_announce USING gist (prefix);
CREATE INDEX i_withdraw_prefix ON bgp_withdraw USING gist (prefix);
CREATE INDEX i_rib_prefix ON bgp_rib USING gist (prefix);

CREATE INDEX i_announce_time ON bgp_announce(time);
CREATE INDEX i_withdraw_time ON bgp_withdraw(time);
CREATE INDEX i_rib_time ON bgp_rib(time);

CREATE TABLE bgp_metadata (
	project varchar not null,
	collector varchar not null,
	period integer not null,
	rib_time timestamptz,
	update_to timestamp,
	PRIMARY KEY (project, collector)
);


-- curl -g 'https://bgpstream.caida.org/broker/meta/projects?human' | jq -r '.data.projects[].collectors | with_entries(select(.value.project != "caida-bmp")) | to_entries | .[] | [.value.project, .key, .value.dataTypes.ribs.dumpPeriod] | @tsv' |          awk $'{print "INSERT INTO bgp_metadata VALUES (\'"$1"\', \'"$2"\', "$3", null, null);"}'
/*
INSERT INTO bgp_metadata VALUES ('ris', 'rrc00', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc01', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc02', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc03', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc04', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc05', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc06', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc07', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc08', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc09', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc10', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc11', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc12', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc13', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc14', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc15', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc16', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc18', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc19', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc20', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc21', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc22', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('ris', 'rrc23', 28800, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views2', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views3', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views4', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views6', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.eqix', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.isc', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.kixp', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.jinx', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.linx', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.telxatl', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.sydney', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.saopaulo', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.nwax', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.perth', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.sg', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.sfmix', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.soxrs', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.chicago', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.napafrica', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.flix', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.chile', 7200, null, null);
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.amsix', 7200, null, null);
*/
INSERT INTO bgp_metadata VALUES ('routeviews', 'route-views.wide', 7200, null, null);
