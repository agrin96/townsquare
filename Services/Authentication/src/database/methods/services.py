from __future__ import annotations
from uuid import UUID, uuid4
from textwrap import dedent

from fastapi import status
from fastapi import HTTPException
from database.connector import SqliteDatabase
from database.models.service import DatabaseService, Service
from .scopes import get_service_scopes



def get_for_credentials(
    database: SqliteDatabase,
    service_name: str,
    secret: str,
) -> Service | None:
    service = database.fetchone(
        return_type = DatabaseService,
        statements = dedent('''
            SELECT
              id,
              service_name,
              token_lineage,
              secret 
            FROM services 
            WHERE
              service_name = @service
              AND secret = @secret 
        '''),
        bindings = {
            'service': service_name,
            'secret': secret,
        }
    )
    if service is None:
        return None

    return Service(
        service_name = service.service_name,
        token_lineage = service.token_lineage,
        scopes = get_service_scopes(database = database, service_id = service.id),
    )



def get_by_name(database: SqliteDatabase, service_name: UUID | str) -> Service | None:
    service = database.fetchone(
        return_type = DatabaseService,
        statements = dedent('''
            SELECT
              id,
              service_name,
              token_lineage,
              secret 
            FROM services 
            WHERE service_name = @service
        '''),
        bindings = {
            'service': service_name if isinstance(service_name, str) else str(service_name),
        }
    )
    if service is None:
        return None

    return Service(
        service_name = service.service_name,
        token_lineage = service.token_lineage,
        scopes = get_service_scopes(database = database, service_id = service.id),
    )



def get_by_id(database: SqliteDatabase, id: int) -> Service | None:
    service = database.fetchone(
        return_type = DatabaseService,
        statements = dedent('''
            SELECT
              id,
              token_lineage,
              service_name,
              secret 
            FROM services 
            WHERE id = @id
        '''),
        bindings = {'id': id}
    )
    if service is None:
        return None

    return Service(
        service_name = service.service_name,
        token_lineage = service.token_lineage,
        scopes = get_service_scopes(database = database, service_id = service.id),
    )



def create(
    database: SqliteDatabase,
    service_name: str,
    secret: str,
    ignore_if_exists: bool = False,
) -> DatabaseService:
    database.execute(
        statements = dedent(f'''
            INSERT{' OR IGNORE ' if ignore_if_exists else ' '}INTO services VALUES (
                NULL,
                @service,
                @secret,
                @lineage,
            ) 
        '''),
        bindings = {
            'service': service_name,
            'lineage': str(uuid4()),
            'secret': secret,
        }
    )
    created_service = database.fetchone(
        statements = 'SELECT * FROM services WHERE service_name = @name',
        return_type = DatabaseService,
        bindings = {'name': service_name }
    )
    if created_service is None:
        raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER_ERROR)
    return created_service




def delete(database: SqliteDatabase, service: Service):
    database.execute('BEGIN')
    database.execute(
        statements = dedent('''
            DELETE FROM service_scope_assignments 
            WHERE service_id = (
                SELECT id FROM services WHERE service_name = @name 
            );
        '''),
        bindings = {'name': str(service.service_name)},
    ) 
    database.execute(
        statements = dedent('''
            DELETE FROM services 
            WHERE service_name = @name;
        '''),
        bindings = {'name': str(service.service_name)},
    ) 
    database.execute('COMMIT')



def update_lineage(database: SqliteDatabase, service: Service) -> Service:
    new_lineage = uuid4()
    database.execute(
        statements = dedent('''
            UPDATE services 
            SET token_lineage = @lineage
            WHERE service_name = @name 
        '''),
        bindings = {
            'lineage': str(new_lineage),
            'name': str(service.service_name),
        }
    )
    service.token_lineage = new_lineage
    return service
