from __future__ import annotations
from textwrap import dedent
from fastapi import HTTPException, status
from database.connector import SqliteDatabase
from database.models.scope import DatabaseScope, Scope



def get_user_scopes(database: SqliteDatabase, user_id: int) -> list[Scope]:
    return database.fetchall(
        statements = dedent('''--sql
            SELECT
                scope,
                provider
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



def get_service_scopes(database: SqliteDatabase, service_id: int) -> list[Scope]:
    return database.fetchall(
        statements = dedent('''
            SELECT
                scope,
                provider
            FROM (
                (
                    SELECT scope_id
                    FROM service_scope_assignments 
                    WHERE service_id = @id
                ) a
                INNER JOIN scopes b
                ON a.scope_id = b.id
            )
        '''),
        return_type = Scope,
        bindings = {'id':  service_id}
    )



def get(database: SqliteDatabase, provider: str | None = None) -> list[DatabaseScope]:
    if provider:
        return database.fetchall(
            statements = 'SELECT * FROM scopes WHERE provider=@provider',
            return_type = DatabaseScope,
            bindings = {'provider': provider}
        )

    return database.fetchall(
        statements = 'SELECT * FROM scopes',
        return_type = DatabaseScope,
    )



def assign_scopes_to_user(
    database: SqliteDatabase,
    user_id: int,
    assignments: list[Scope],
):
    if not assignments:
        return

    assignments_string = ','.join(f"('{(s)}')" for s in assignments)
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
        raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER_ERROR)

    assignments_string = ','.join(f"'{s}'" for s in assignments)
    scopes = database.fetchall(
        statements = f'SELECT * FROM scopes WHERE scope IN ({assignments_string})',
        return_type = DatabaseScope,
    )
    database.executemany(
        statements = dedent('''
            INSERT OR IGNORE INTO user_scope_assignments VALUES (
                NULL,
                @user,
                @scope
            );
        '''),
        sequenceofbindings = [{'user': user_id, 'scope': s.id} for s in scopes]
    )



    
def assign_scopes_to_service(
    database: SqliteDatabase,
    service_id: int,
    assignments: list[Scope],
):
    if not assignments:
        return

    assignments_string = ','.join(f"('{(s)}')" for s in assignments)
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
        raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER_ERROR)

    assignments_string = ','.join(f"'{s}'" for s in assignments)
    scopes = database.fetchall(
        statements = f'SELECT * FROM scopes WHERE scope IN ({assignments_string})',
        return_type = DatabaseScope,
    )
    database.executemany(
        statements = dedent('''
            INSERT OR IGNORE INTO service_scope_assignments VALUES (
                NULL,
                @service,
                @scope
            );
        '''),
        sequenceofbindings = [{'service': service_id, 'scope': s.id} for s in scopes]
    )



def insert(database: SqliteDatabase, scope: Scope, ignore_if_exists: bool = False):
    database.execute(
        statements = dedent(f'''
            INSERT{' OR IGNORE ' if ignore_if_exists else ' '}INTO scopes VALUES (
                NULL,
                @provider,
                @scope
            )
        '''),
        bindings = {'scope': str(scope), 'provider': scope.provider} 
    )
