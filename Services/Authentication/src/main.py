from __future__ import annotations

from fastapi import FastAPI
from runtime import runtime_settings
from contextlib import asynccontextmanager

import routers
from database.connector import SqliteDatabase
from database.tables import create_tables
from database.values import ScopeValues, insert_scope_values



@asynccontextmanager
async def lifespan(app: FastAPI):
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    create_tables(database = database) 
    insert_scope_values(database = database)

    yield
    # drop_tables(database = database)
    database.close()
    


app = FastAPI(lifespan = lifespan)
app.include_router(routers.user.router)



def main():
    # database = SqliteDatabase(':memory:') 
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    # user = fetch_user_for_email(database = database, email = 'aleksandr@gmail.com')
    # is_subscope = ScopeValues.user_self_full.value.contains_scope(scope = ScopeValues.user_self_read.value)
    # print(is_subscope)
    #
    # is_subscope = ScopeValues.user_self_read.value.contains_scope(scope = ScopeValues.user_self_full.value)
    # print(is_subscope)


if __name__ == "__main__":
    main()
