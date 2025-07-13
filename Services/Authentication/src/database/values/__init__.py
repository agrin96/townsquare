from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from textwrap import dedent
from datetime import timedelta

from database.models import Scope
from database.connector import SqliteDatabase
from database.models.scope import DatabaseScope
from database.models.scope_group import (
    ScopeGroup,
    DatabaseScopeGroup,
)



class ScopeGroupTokenLifetimes(Enum):
    ADMIN = timedelta(minutes = 30)
    USER = timedelta(minutes = 60)



class ScopeValues(Enum):
    status               = Scope(scope = ('authentication', 'status'))
    self_full            = Scope(scope = ('authentication', 'self'))
    register             = Scope(scope = ('authentication', 'register'))
    deregister           = Scope(scope = ('authentication', 'deregister'))
    authentication_admin = Scope(scope = ('authentication',))
 

@dataclass
class Permission[T]:
    level: int
    group: ScopeGroup


class ScopeGroupValues(Enum):
    visitor = ScopeGroup(
        group = 'VISITOR',
        scopes = []
    )
    basic_user = ScopeGroup(
        group = 'USER',
        scopes = [ ScopeValues.self_full.value ]
    )
    authentication_admin = ScopeGroup(
        group = 'ADMIN',
        scopes = [ ScopeValues.authentication_admin.value ]
    )



def insert_scope_values(database: SqliteDatabase):
    with database:
        database.executemany(
            statements = 'INSERT OR IGNORE INTO scopes VALUES (NULL, @scope);',
            sequenceofbindings = [scope.value.model_dump() for scope in ScopeValues]
        )



def insert_scope_group_values(database: SqliteDatabase):
    with database:
        database.executemany(
            statements = 'INSERT OR IGNORE INTO scope_groups VALUES ( NULL, @group );',
            sequenceofbindings = [{'group': v.value.group} for v in ScopeGroupValues]
        )

    current_scope_groups = database.fetchall(
        statements = 'SELECT * FROM scope_groups;',
        return_type = DatabaseScopeGroup,
    ) 

    current_scopes = database.fetchall(
        statements = 'SELECT * FROM scopes;',
        return_type = DatabaseScope,
    ) 

    identified_groups: dict[int, ScopeGroup] = {}
    for member in ScopeGroupValues:
        for current_group in current_scope_groups:
            if current_group.group_name == member.value.group:
                identified_groups[current_group.id] = member.value   

    assignments: list[dict[str, int]] = []
    for group_id, group in identified_groups.items():
        for assigned_scope in group.scopes:
            for current_scope in current_scopes:
                if hash(current_scope) == hash(assigned_scope):
                    assignments.append({
                        'scope': current_scope.id,
                        'scope_group': group_id,
                    })

    with database:
        database.executemany(
            statements = dedent('''
                INSERT OR IGNORE INTO scope_assignments VALUES (
                    NULL,
                    @scope,
                    @scope_group
                );
            '''),
            sequenceofbindings = assignments,
        )

