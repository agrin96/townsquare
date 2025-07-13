from __future__ import annotations
from typing import Annotated, Any
from collections.abc import Generator


from runtime import runtime_settings
from database.connector import SqliteDatabase
from database.models import Scope, ScopeGroup



class SecurityScope(str):
    def __init__(
        self,
        scopes: list[Scope] | None = None,
        scope_groups: list[ScopeGroup] | None = None,
    ) -> None:
        self.scopes = scopes or [] 
        self.scope_groups = scope_groups or [] 


    def __new__(
        cls,
        scopes: list[Scope] | None = None,
        scope_groups: list[ScopeGroup] | None = None,
    ):
        values = set() 
        if scopes:
            values = values.union({str(v) for v in scopes})
        if scope_groups:
            values = values.union({str(v) for v in scope_groups})
        return str.__new__(cls, 'scopedsecurity ' + ' '.join(values))



async def database_dependency():
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    try:
        yield database
    finally:
        database.close()




__all__ = [
    'SecurityScope',
    'database_dependency'
]

