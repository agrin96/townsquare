/*
Users table will store simple login information for a user
A user is foreign keyed to a scopes table which may or may
not be used.

- identifier This is a client created UUIDv4 that allows quick lookups between services
- email The user provided emial. Either via basic auth or something like google.
- hashed_password The hashed password of the user. May be null if using OAuth 
*/
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    hashed_password TEXT
);
CREATE INDEX IF NOT EXISTS idx_user_email ON users (email);
