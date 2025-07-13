/*
A scope can belong to multiple groups or no groups at all so we need to establish a 
group-scope relationship.
*/
CREATE TABLE IF NOT EXISTS scope_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER,
    scope_group_id INTEGER,
    FOREIGN KEY(scope_id) REFERENCES scopes(id) ON DELETE CASCADE,
    FOREIGN KEY(scope_group_id) REFERENCES scope_groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scope_assignment_scope_id_scope_group_id
ON scope_assignments (scope_id, scope_group_id);
