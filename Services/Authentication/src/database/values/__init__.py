from __future__ import annotations
from enum import Enum
from argon2 import PasswordHasher

from runtime import runtime_settings
from database.models import Scope
from database.methods import users, scopes
from database.connector import SqliteDatabase



class ScopeValues(Enum):
    status                   = Scope(scope = ('authentication', 'status'))
    token_refreh             = Scope(scope = ('authentication', 'token', 'refresh'))
    user_self_read           = Scope(scope = ('authentication', 'user', 'self', 'read'))
    user_self_deregister     = Scope(scope = ('authentication', 'user', 'self', 'deregister'))
    user_self_full           = Scope(scope = ('authentication', 'user', 'self'))
    user_register            = Scope(scope = ('authentication', 'user', 'register'))
    admin_lineage_invalidate = Scope(scope = ('authentication', 'admin', 'user', 'lineage', 'invalidate'))
    admin_user_full          = Scope(scope = ('authentication', 'admin', 'user'))
    admin_service            = Scope(scope = ('authentication',))

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



def create_serivice_admin(database: SqliteDatabase):
    '''### Summary
    Create a default service level admin user for this service. The service admin role
    has a password which is generated from the service env. This is set only once.'''
    hashed_password = PasswordHasher().hash(
        password = runtime_settings.service_password,
        salt = runtime_settings.hashing_salt,
    )

    database.execute('BEGIN')
    admin_user = users.create(
        database = database,
        email = 'service-admin',
        hashed_password = hashed_password, 
        ignore_if_exists = True,
    )
    scopes.assign_scopes(
        database = database,
        user_id = admin_user.id,
        assignments = [ScopeValues.admin_service.value]
    )
    database.execute('COMMIT')



def create_initial_key(database: SqliteDatabase):
    pass
