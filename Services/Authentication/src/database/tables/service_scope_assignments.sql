/*
This table manages scope assignments for users. A user can recieve multiple scopes 
(read "permissions") which define their permission set.
*/
CREATE TABLE IF NOT EXISTS service_scope_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER,
    scope_id INTEGER,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS service_scope_assignments_service_id_scope_id
ON service_scope_assignments (service_id, scope_id);
