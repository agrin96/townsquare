/*
A scope represents a type of permission. We call this a scope because we are associating
it with the JWT token definition of a scope.
*/
CREATE TABLE IF NOT EXISTS scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    scope TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_scopes_provider ON scopes(provider);
