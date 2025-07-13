import os
from database import SqliteDatabase



# NOTE: Define table initialization order here. MUST match file names. Using table names
# is reccomended!
ordered_tables = [
    'scopes',
    'users',
    'user_scope_assignments',
    'services',
    'service_scope_assignments',
]



def create_tables(database: SqliteDatabase, directory: str = './Database/Tables/'):
    '''### Summary
    Initialize database tables by reading in a directory of table definition files. The
    files are then executed in the order specified in this file via the `ordered_tables`
    definition. This ensures that dependencies/constraints are properly accounted for
    since SQLite cannot automatically resolve dependencies here.

    ### Parameters:
    - `database` A connection object
    - `directory` Path to a directory of table definition files like <table_name>.sql'''
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
    '''### Summary
    When we need to do a hard reset of our database we drop the defined tables in the
    reverse order of their creation. This ensures that foreign key cascade sare properly
    handled and we wont get errors thrown.'''
    with database:
        for table_name in reversed(ordered_tables):
            print(f'Dropping {table_name}')
            database.execute(statements = f'DROP TABLE IF EXISTS {table_name}')



__all__ = [
    'ordered_tables',
    'create_tables',
    'drop_tables',
]
