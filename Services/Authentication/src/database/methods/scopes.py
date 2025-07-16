from __future__ import annotations
from textwrap import dedent
from fastapi import HTTPException, status
from database.connector import SqliteDatabase
from database.models.scope import DatabaseScope, Scope



def get_scopes(database: SqliteDatabase, user_id: int) -> list[Scope]:
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



def assign_scopes(
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

