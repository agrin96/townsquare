from __future__ import annotations
from textwrap import dedent

from fastapi import HTTPException
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR
from database.models.scope import DatabaseScope
from database.connector import SqliteDatabase
from database.models import (
    User,
    Scope,
    ScopeGroup,
    DatabaseUser,
)
from database.models.scope_group import DatabaseScopeGroup



def fetch_user_scopes(database: SqliteDatabase, user_id: int) -> list[Scope]:
    return database.fetchall(
        statements = dedent('''
            SELECT
                scope 
            FROM (
                (
                    SELECT scope_id
                    FROM user_scope_assignments
                    WHERE user_id = @id
                ) a
                INNER JOIN scopes b
                ON a.scope_id = b.id
            )
        '''),
        return_type = Scope,
        bindings = {'id': user_id}
    )



def fetch_user_scope_groups(database: SqliteDatabase, user_id: int) -> list[ScopeGroup]:
    groups = database.fetchall(
        statements = dedent('''
            SELECT
              b.id,
              b.group_name
            FROM (
                (
                    SELECT scope_group_id
                    FROM user_scope_group_assignments
                    WHERE user_id = @id
                ) a
                INNER JOIN scope_groups b
                ON a.scope_group_id = b.id
            )
        '''),
        return_type = DatabaseScopeGroup,
        bindings = {'id': user_id}
    )

    constructed_groups = []
    for group in groups:
        group_scopes = database.fetchall(
            statements = dedent('''
                SELECT b.* 
                FROM (
                    (
                        SELECT scope_id
                        FROM scope_assignments
                        WHERE scope_group_id = @id
                    ) a
                    INNER JOIN scopes b
                    ON a.scope_id = b.id
                )
            '''),
            return_type = DatabaseScope,
            bindings = {'id': group.id}
        ) 
        constructed_groups.append(
            ScopeGroup(
                group = group.group_name,
                scopes = [Scope(scope = scope.scope) for scope in group_scopes]
            )
        )
    return constructed_groups



def fetch_scope_group(database: SqliteDatabase, group: str) -> ScopeGroup:
    group_scopes = database.fetchall(
        statements = dedent('''
            WITH group_id AS (
                SELECT id FROM scope_groups WHERE group_name=@group_name
            )
            SELECT b.* 
            FROM (
                (
                    SELECT scope_id
                    FROM scope_assignments a 
                    INNER JOIN group_id b
                    ON a.scope_group_id = b.id
                ) a
                INNER JOIN scopes b
                ON a.scope_id = b.id
            )
        '''),
        return_type = DatabaseScope,
        bindings = {'group_name': group}
    ) 
    return ScopeGroup(
        group = group,
        scopes = [Scope(scope = scope.scope) for scope in group_scopes]
    )




def fetch_user_for_basic_auth(
    database: SqliteDatabase,
    email: str,
    hashed_password: str,
) -> User | None:
    user = database.fetchone(
        return_type = DatabaseUser,
        statements = dedent('''
            SELECT
              id,
              identifier,
              email,
              hashed_password
            FROM users
            WHERE
              email = @email
              AND hashed_password = @hashed_password 
        '''),
        bindings = {
            'email': email,
            'hashed_password': hashed_password,
        }
    )
    if user is None:
        return None

    return User(
        identifier = user.identifier,
        email = user.email,
        scopes = fetch_user_scopes(database = database, user_id = user.id),
        scope_groups = fetch_user_scope_groups(database = database, user_id = user.id),
    )



def fetch_user_for_email(database: SqliteDatabase, email: str) -> User | None:
    user = database.fetchone(
        statements = 'SELECT * FROM users WHERE email = @email',
        return_type = DatabaseUser,
        bindings = {'email': email}
    )
    if not user:
        return None

    return User(
        identifier = user.identifier,
        email = user.email,
        scopes = fetch_user_scopes(database = database, user_id = user.id),
        scope_groups = fetch_user_scope_groups(database = database, user_id = user.id),
    )



def does_user_email_exist(database: SqliteDatabase, email: str) -> bool:
    result = fetch_user_for_email(database = database, email = email)
    return result is not None



def fetch_user_for_identifier(database: SqliteDatabase, identifier: str) -> User | None:
    user = database.fetchone(
        return_type = DatabaseUser,
        statements = dedent('''
            SELECT
              id,
              identifier,
              email,
              hashed_password
            FROM users
            WHERE
              identifier = @identifier
        '''),
        bindings = {
            'identifier': identifier,
        }
    )
    if user is None:
        return None

    return User(
        identifier = user.identifier,
        email = user.email,
        scopes = fetch_user_scopes(database = database, user_id = user.id),
        scope_groups = fetch_user_scope_groups(database = database, user_id = user.id),
    )



def create_user(database: SqliteDatabase, email: str, hashed_password: str) -> DatabaseUser:
    user = DatabaseUser(
        email = email,
        hashed_password = hashed_password,
    )
    database.execute(
        statements = dedent('''
            INSERT INTO users VALUES (
                NULL,
                @identifier,
                @email,
                @hashed_password
            ) 
        '''),
        bindings = {
            'identifier': str(user.identifier),
            'email': user.email,
            'hashed_password': user.hashed_password,
        }
    )
    created_user = database.fetchone(
        'SELECT * FROM users WHERE identifier=?',
        return_type = DatabaseUser,
        bindings = (str(user.identifier),)
    )
    if created_user is None:
        raise HTTPException(status_code = HTTP_500_INTERNAL_SERVER_ERROR)
    return created_user



def assign_scopes_to_user(
    database: SqliteDatabase,
    user: DatabaseUser,
    assignments: list[Scope],
):
    if not assignments:
        return

    assignments_string = ','.join(f"('{s.scope}')" for s in assignments)
    missing_scopes = database.simple_fetchall(
        statements = dedent(f'''
            WITH candidate_values(scope) AS ( VALUES {assignments_string} )
            SELECT scope
            FROM candidate_values
            WHERE scope NOT IN (SELECT scope FROM scopes) 
        ''')
    )
    if missing_scopes:
        unrecognized = [ v['scope'] for v in missing_scopes ]
        print(
            f'Unrecognized scopes. Scopes must be registered before assignment.'
            f' Unrecognized = {unrecognized}'
        )
        raise HTTPException(status_code = HTTP_500_INTERNAL_SERVER_ERROR)

    assignments_string = ','.join(f"'{s.scope}'" for s in assignments)
    scopes = database.fetchall(
        statements = f'SELECT * FROM scopes WHERE scope IN ({assignments_string})',
        return_type = DatabaseScope,
    )
    database.executemany(
        statements = dedent('''
            INSERT INTO user_scope_assignments VALUES (
                NULL,
                @user,
                @scope
            );
        '''),
        sequenceofbindings = [{'user': user.id, 'scope': s.id} for s in scopes]
    )



def assign_scope_groups_to_user(
    database: SqliteDatabase,
    user: DatabaseUser,
    assignments: list[ScopeGroup],
):
    if not assignments:
        return

    assignments_string = ','.join(f"('{s.group}')" for s in assignments)
    missing_groups = database.simple_fetchall(
        statements = dedent(f'''
            WITH candidate_values(group_name) AS ( VALUES {assignments_string} )
            SELECT group_name
            FROM candidate_values
            WHERE group_name NOT IN (SELECT group_name FROM scope_groups)
        ''')
    )
    if missing_groups:
        unrecognized = [ v['group_name'] for v in missing_groups ]
        print( 
            'Unrecognized scope groups. Scope groups must be registered before'
            f' assignment. Unrecognized = {unrecognized}'
        )
        raise HTTPException(status_code = HTTP_500_INTERNAL_SERVER_ERROR)

    assignments_string = ','.join(f"'{s.group}'" for s in assignments)
    scope_groups = database.fetchall(
        statements = dedent(f'''
            SELECT * 
            FROM scope_groups
            WHERE group_name IN ({assignments_string});
        '''),
        return_type = DatabaseScopeGroup,
    )
    print([{'user': user.id, 'scope_group': s.id} for s in scope_groups])
    database.executemany(
        statements = dedent('''
            INSERT INTO user_scope_group_assignments VALUES (
                NULL,
                @user,
                @scope_group
            );
        '''),
        sequenceofbindings = [{'user': user.id, 'scope_group': s.id} for s in scope_groups]
    )



__all__ = [
    'create_user',
    'fetch_user_scopes',
    'does_user_email_exist',
    'fetch_user_scope_groups',
    'fetch_user_for_basic_auth',
    'fetch_user_for_identifier',
]

