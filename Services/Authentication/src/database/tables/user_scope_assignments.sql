/*
This table manages scope assignments for users. A user can recieve multiple scopes 
(read "permissions") which define their permission set.
*/
CREATE TABLE IF NOT EXISTS user_scope_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    scope_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_scope_assignments_user_id_scope_id
ON user_scope_assignments (user_id, scope_id);
