/*
A scope group represents a collection of scopes which reflect a "role". e.g. ADMIN, USER,
SUPERUSER. These roles can be arbitrarily defined.
*/
CREATE TABLE IF NOT EXISTS scope_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name TEXT UNIQUE
);
