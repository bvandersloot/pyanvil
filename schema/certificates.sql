CREATE EXTENSION IF NOT EXISTS ip4r;

create table issued_certificates (
	id serial primary key,
	serial integer not null,
	kid varchar,
	acme_client_address ipaddress,
	not_before timestamptz not null,
	not_after timestamptz not null,
	public_key_fingerprint varchar not null,
	identifier varchar not null,
	validation_client_address ipaddress,
	validation_server_address ipaddress,
	validation_time timestamptz not null
);

