from __future__ import annotations
from runtime import runtime_settings
from database.connector import SqliteDatabase



async def database_dependency():
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    try:
        yield database
    finally:
        database.close()




__all__ = [
    'database_dependency'
]

