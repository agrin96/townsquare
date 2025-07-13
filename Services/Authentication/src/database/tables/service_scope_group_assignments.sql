/*
Manages scope group ("role") assignments for users. Each scope group is made up of 
several scopes and will have to be linked through the scope assignments table. Note that
a user can have duplicate scope assignments which show up as an explicit scope and as a
part of one or more groups.
*/
CREATE TABLE IF NOT EXISTS service_scope_group_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER,
    scope_group_id INTEGER,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    FOREIGN KEY (scope_group_id) REFERENCES scope_groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_service_scope_group_assignments_service_id_scope_group_id
ON service_scope_group_assignments (service_id, scope_group_id);
