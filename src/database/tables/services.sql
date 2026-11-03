/*
The service table is used to store information for generating machine to machine auth
tokens. The machines name and secret are loaded by a definition file on service startup.

- service_identifier The unique name of the service something like "payments-service-hash"
- secret A randomly generated secret token provided by the auth server to allow registering
services to the authentication service.
- token_lineage The token lineage is a special UUIDv4 which is used to track which tokens
are valid. If a token lineage does not match an incoming JWT it is not valid.
*/
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE,
    token_lineage TEXT NOT NULL UNIQUE
);
