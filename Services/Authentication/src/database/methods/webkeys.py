from __future__ import annotations
from uuid import UUID
from textwrap import dedent
from fastapi import HTTPException, status

from database.connector import SqliteDatabase
from database.models.jwk import DatabaseWebKey, WebKey



def get_keys(database: SqliteDatabase) -> list[WebKey]:
    databasekeys = database.fetchall(
        return_type = DatabaseWebKey,
        statements = 'SELECT * FROM json_web_keys ',
    )
    return sorted(
        [key.webkey for key in databasekeys],
        key = lambda v: v.not_valid_after,
        reverse = True,
    )



def get_latest_key(database: SqliteDatabase) -> WebKey:
    webkeys = get_keys(database = database)
    sorted_keys = sorted(
        webkeys,
        key = lambda v: v.not_valid_after,
        reverse = True
    )
    if not sorted_keys:
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail = 'no webkeys available',
        )
    return sorted_keys[0]



def get_key_for_id(database: SqliteDatabase, key_id: UUID) -> WebKey:
    databasekey = database.fetchone(
        statements = dedent('''
            SELECT * FROM json_web_keys WHERE key_id=@id
        '''),
        return_type = DatabaseWebKey,
        bindings = {'id': key_id},
    ) 
    if databasekey is None:
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail = 'no key found for keyid'
        )
    return databasekey.webkey



def insert(database: SqliteDatabase, key: WebKey):
    database.execute(
        statements = dedent('''
            INSERT INTO json_web_keys VALUES (
                @key_id,
                @algorithm,
                @key_type,
                @use,
                @private_pem,
                @certificate
            );
        '''),
        bindings = key.model_dump(),
    )
 


def delete(database: SqliteDatabase, key: WebKey):
    database.execute(
        statements = dedent('''
            DELETE FROM json_web_keys
            WHERE key_id=@id
        '''),
        bindings = {'id': str(key.key_id)},
    )
