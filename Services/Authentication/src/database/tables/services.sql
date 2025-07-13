/*
The service table is used to store information for generating machine to machine auth
tokens. The machines name and secret are loaded by a definition file on service startup.

- service The unique name of the service something like "payments-service"
- secret A randomly generated secret token for the service that can be used when creating
tokens. This is similar to a password for users when doing basic auth.
*/
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE
);
