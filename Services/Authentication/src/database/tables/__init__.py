import os
from database import SqliteDatabase



ordered_tables = [
    'scopes',
    'scope_groups',
    'group_token_lifespan',
    'scope_assignments',
    'users',
    'user_scope_assignments',
    'user_scope_group_assignments',
    'services',
    'service_scope_assignments',
    'service_scope_group_assignments',
]



def create_tables(database: SqliteDatabase, directory: str = './Database/Tables/'):
    directory_files = [ 
        file for file in os.listdir(directory) 
        if file.endswith('.sql')
    ]

    with database:
        for table_name in ordered_tables:
            idx = directory_files.index(f'{table_name}.sql')
            if idx == -1:
                raise ValueError(f'table {table_name} not found in directory.')

            with open(directory + directory_files[idx], 'r') as file:
                table_definition = file.read()
                print(f'Creating table {table_name}')
                database.execute(statements = table_definition)



def drop_tables(database: SqliteDatabase):
    with database:
        for table_name in reversed(ordered_tables):
            print(f'Dropping {table_name}')
            database.execute(statements = f'DROP TABLE IF EXISTS {table_name}')



__all__ = [
    'ordered_tables',
    'create_tables',
    'drop_tables',
]
