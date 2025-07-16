from __future__ import annotations
from uuid import UUID, uuid4
from textwrap import dedent

from fastapi import status
from fastapi import HTTPException
from database.connector import SqliteDatabase
from database.models import User, DatabaseUser
from .scopes import get_scopes



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
              token_lineage,
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
        token_lineage = user.token_lineage,
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
        token_lineage = user.token_lineage,
        scopes = get_scopes(database = database, user_id = user.id),
    )



def does_email_exist(database: SqliteDatabase, email: str) -> bool:
    result = get_by_email(database = database, email = email)
    return result is not None



def get_by_identifier(database: SqliteDatabase, identifier: UUID | str) -> User | None:
    user = database.fetchone(
        return_type = DatabaseUser,
        statements = dedent('''
            SELECT
              id,
              identifier,
              token_lineage,
              email,
              hashed_password
            FROM users
            WHERE
              identifier = @identifier
        '''),
        bindings = {
            'identifier': identifier if isinstance(identifier, str) else str(identifier),
        }
    )
    if user is None:
        return None

    return User(
        identifier = user.identifier,
        email = user.email,
        token_lineage = user.token_lineage,
        scopes = get_scopes(database = database, user_id = user.id),
    )



def get_by_id(database: SqliteDatabase, id: int) -> User | None:
    user = database.fetchone(
        return_type = DatabaseUser,
        statements = dedent('''
            SELECT
              id,
              identifier,
              token_lineage,
              email,
              hashed_password
            FROM users
            WHERE
              identifier = @identifier
        '''),
        bindings = {'id': id}
    )
    if user is None:
        return None

    return User(
        identifier = user.identifier,
        email = user.email,
        token_lineage = user.token_lineage,
        scopes = get_scopes(database = database, user_id = user.id),
    )



def create(
    database: SqliteDatabase,
    email: str,
    hashed_password: str,
    ignore_if_exists: bool = False,
) -> DatabaseUser:
    database.execute(
        statements = dedent(f'''
            INSERT{' OR IGNORE ' if ignore_if_exists else ' '}INTO users VALUES (
                NULL,
                @identifier,
                @lineage,
                @email,
                @hashed_password
            ) 
        '''),
        bindings = {
            'identifier': str(uuid4()),
            'email': email,
            'lineage': str(uuid4()),
            'hashed_password': hashed_password,
        }
    )
    created_user = database.fetchone(
        statements = 'SELECT * FROM users WHERE email = @email',
        return_type = DatabaseUser,
        bindings = {'email': email}
    )
    if created_user is None:
        raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER_ERROR)
    return created_user



def delete(database: SqliteDatabase, user: User):
    database.execute('BEGIN')
    database.execute(
        statements = dedent('''
            DELETE FROM user_scope_assignments
            WHERE user_id = (
                SELECT id FROM users WHERE identifier=@identifier
            );
        '''),
        bindings = {'identifier': str(user.identifier)},
    ) 
    database.execute(
        statements = dedent('''
            DELETE FROM users 
            WHERE identifier=@identifier;
        '''),
        bindings = {'identifier': str(user.identifier)},
    ) 
    database.execute('COMMIT')



def update_lineage(database: SqliteDatabase, user: User) -> User:
    new_lineage = uuid4()
    database.execute(
        statements = dedent('''
            UPDATE users
            SET token_lineage=@lineage
            WHERE identifier=@identifier
        '''),
        bindings = {
            'lineage': str(new_lineage),
            'identifier': str(user.identifier),
        }
    )
    user.token_lineage = new_lineage
    return user
