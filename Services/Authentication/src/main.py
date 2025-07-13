from __future__ import annotations
from textwrap import dedent

from fastapi import FastAPI
from database.models.scope import DatabaseScope
from runtime import runtime_settings
from contextlib import asynccontextmanager
from database.connector import SqliteDatabase
from database.tables import (
    drop_tables,
    create_tables,
)
import routers
from database.values import ScopeGroupValues, ScopeValues, insert_scope_group_values, insert_scope_values
from database.models.scope_group import DatabaseScopeGroup
from database.methods import fetch_user_for_email



@asynccontextmanager
async def lifespan(app: FastAPI):
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    create_tables(database = database) 
    insert_scope_values(database = database)
    insert_scope_group_values(database = database)

    yield
    # drop_tables(database = database)
    database.close()
    


app = FastAPI(lifespan = lifespan)
app.include_router(routers.user.router)



def main():
    # database = SqliteDatabase(':memory:') 
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    user = fetch_user_for_email(database = database, email = 'aleksandr@gmail.com')
    print(user)
    token = user.token_data
    print(token.scope_groups[0].scopes)
    print(token.model_dump())

    output = database.simple_fetchall('SELECT * FROM user_scope_group_assignments')
    print('ASSIGNMNETS:\n', output)


if __name__ == "__main__":
    main()
