/*
A scope group represents a collection of scopes which reflect a "role". e.g. ADMIN, USER,
SUPERUSER. These roles can be arbitrarily defined.
- `token_lifespan` This is default number of seconds a token generated with this
scope_group should live
*/
CREATE TABLE IF NOT EXISTS group_token_lifespan (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    token_lifespan INTEGER NOT NULL,
    FOREIGN KEY(group_id) REFERENCES scope_groups(id) ON DELETE CASCADE
);
