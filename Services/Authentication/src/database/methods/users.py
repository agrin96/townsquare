from __future__ import annotations
from textwrap import dedent

from fastapi import HTTPException
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR
from database.models.scope import DatabaseScope
from database.connector import SqliteDatabase
from database.models import (
    User,
    Scope,
    DatabaseUser,
)



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



def get_by_auth(
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
        scopes = get_scopes(database = database, user_id = user.id),
    )



def get_by_email(database: SqliteDatabase, email: str) -> User | None:
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
        scopes = get_scopes(database = database, user_id = user.id),
    )



def does_email_exist(database: SqliteDatabase, email: str) -> bool:
    result = get_by_email(database = database, email = email)
    return result is not None



def get_by_identifier(database: SqliteDatabase, identifier: str) -> User | None:
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
        scopes = get_scopes(database = database, user_id = user.id),
    )



def create(database: SqliteDatabase, email: str, hashed_password: str) -> DatabaseUser:
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



def assign_scopes(
    database: SqliteDatabase,
    user: DatabaseUser,
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
        raise HTTPException(status_code = HTTP_500_INTERNAL_SERVER_ERROR)

    assignments_string = ','.join(f"'{s}'" for s in assignments)
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

