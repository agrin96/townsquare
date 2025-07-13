from __future__ import annotations
from enum import Enum
from database.models import Scope
from database.connector import SqliteDatabase



class ScopeValues(Enum):
    status               = Scope(scope = ('authentication', 'status'))
    user_self_read       = Scope(scope = ('authentication', 'user', 'self', 'read'))
    user_self_deregister = Scope(scope = ('authentication', 'user', 'self', 'deregister'))
    user_self_full       = Scope(scope = ('authentication', 'user', 'self'))
    user_register        = Scope(scope = ('authentication', 'user', 'register'))
    auth_full            = Scope(scope = ('authentication',))

    @property
    def scope_string(self) -> str:
        return self.value.model_dump()['scope']



def insert_scope_values(database: SqliteDatabase):
    '''### Summary
    Populates our scopes table with an initial set of values to dictate minimal required
    permissions for the authentication service. Run this in a lifecycle event'''
    with database:
        database.executemany(
            statements = 'INSERT OR IGNORE INTO scopes VALUES (NULL, @scope);',
            sequenceofbindings = [scope.value.model_dump() for scope in ScopeValues]
        )
