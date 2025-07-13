from __future__ import annotations
import os
import apsw
import apsw.bestpractice
from pathlib import Path
from typing import Any, cast
from pydantic import BaseModel



class SqliteDatabase(apsw.Connection):
    def __init__(
            self,
            database_file: Path | str,
            clean: bool = False,
        ):
        '''### Summary
        Extension of the regular apsw.Connection class with some additions for quality of
        life and automatic database instantiation from a file.

        ### Parameters
        - `database_file` The path or filename of a sqlite database ending in
        the .sqlite extension
        - `clean` The existing databse tables will be overwritten from the 
        definitions file.'''
        apsw.bestpractice.apply(apsw.bestpractice.recommended)

        if isinstance(database_file, Path):
            database_file = database_file.resolve().absolute().as_posix()
        
        if database_file != ':memory:':
            folders, _ = database_file.rsplit("/", maxsplit = 1)
            os.makedirs(folders, exist_ok = True)

        super().__init__(filename = database_file)
        self.set_busy_timeout(5000)
        self.__query_column_names = []
        self.set_exec_trace(self.__execution_tracer)
        self.set_row_trace(self.__dictionary_row)


    def __execution_tracer(
            self,
            cursor: apsw.Cursor,
            sql: str,
            bindings: apsw.Bindings | None = None) -> bool:
        '''### Summary
        An execution tracer is run after the query is prepared but before it is
        run. This allows us to extract query details such as columns and the
        table names being queried, without running the query itself. This solves
        https://github.com/rogerbinns/apsw/issues/160'''
        # When using the context manager for transaction management it causes this
        # function to fire, so we detect that here and skip it.
        if "SAVEPOINT" in sql:
            return True
        
        columns = cursor.get_description()
        self.__query_column_names = [c[0] for c in columns]
        return True



    def __dictionary_row(self, cursor: apsw.Cursor, row: apsw.SQLiteValues) -> dict:
        '''### Summary
        This row tracer converts the each result into a dictionary. The
        execution tracer assures that we have the query column names available
        for the row and do not have to get them each time.'''
        column_names = self.__query_column_names
        return {name: value for name, value in zip(column_names, row)}



    def describe_table(self, table_name: str) -> str:
        '''### Summary
        Fetches the creation query of the given table.
        
        ### Returns
        A string of the SQL query which was used to create the table.'''
        rows = self.execute(
            '''--sql
            SELECT sql
            FROM sqlite_master
            WHERE type IN ('table','view')
            AND NAME = ?;
            ''',
            bindings = (table_name,)
        ).fetchall()
        assert len(rows) <= 1, F"More than one table named {table_name}. Impossible."
        return cast(dict, rows[0])["sql"]



    def list_tables(self) -> list[dict]:
        '''### Summary
        Queries the metadata table in sqlite for information on which tables and
        views are available.
        
        ### Returns
        A Dataframe with the table name and table type columns.'''
        cursor = self.execute(
            '''--sql
            SELECT name, type
            FROM sqlite_master
            WHERE
                type IN ('table','view')
                AND name NOT LIKE 'sqlite_%'
            UNION ALL
            SELECT name, type
            FROM sqlite_temp_master
            WHERE
                type IN ('table','view')
            ORDER BY 1;
            '''
        )
        return cast(list[dict], cursor.fetchall())


    def fetchone[Result: BaseModel](
            self,
            statements: str,
            return_type: type[Result],
            bindings: Any | None = None,
        ) -> Result | None:
        '''### Summary
        Execute a statement which fetches results and returns them as a list of
        dictionary values.
        
        ### Parameters
        `statements` There should only a single select statement otherwise sqlite
        will error as results weren't fetched between queries
        
        `bindings` Any query bindings/substitutions that need to be made.

        ### Returns
        A list of dictionaries of the results'''
        if "select" not in statements.lower():
            raise ValueError("Expected a select query.")
        
        cursor = self.execute(statements = statements, bindings = bindings)
        if (item := cursor.fetchone()) is not None:
            return return_type(**cast(dict[str,Any], item))
        return None 


    def simple_fetchone(
            self,
            statements: str,
            bindings: Any | None = None,
        ) -> dict[str, Any] | None:
        '''### Summary
        Execute a statement which fetches results and returns them as a list of
        dictionary values.
        
        ### Parameters
        `statements` There should only a single select statement otherwise sqlite
        will error as results weren't fetched between queries
        
        `bindings` Any query bindings/substitutions that need to be made.

        ### Returns
        A list of dictionaries of the results'''
        if "select" not in statements.lower():
            raise ValueError("Expected a select query.")
        
        cursor = self.execute(statements = statements, bindings = bindings)
        if (item := cursor.fetchone()) is not None:
            return cast(dict[str, Any], item) 
        return None 


    def fetchall[Result: BaseModel](
            self,
            statements: str,
            return_type: type[Result],
            bindings: Any | None = None,
        ) -> list[Result]:
        '''### Summary
        Execute a statement which fetches results and returns them as a list of
        pydantic model objects

        ### Parameters
        `statements` There should only a single select statement otherwise sqlite
        will error as results weren't fetched between queries

        `return_type`: The pydantic model which we should return. This class will be used
        as a constructor.
        
        `bindings` Any query bindings/substitutions that need to be made.

        ### Returns
        A list of dictionaries of the results'''
        if "select" not in statements.lower():
            raise ValueError("Expected a select query.")
        
        cursor = self.execute(statements = statements, bindings = bindings)
        items = cursor.fetchall()
        return [
            return_type(**element)
            for element in cast(list[dict[str, Any]], items)
        ]


    def simple_fetchall(
            self,
            statements: str,
            bindings: Any | None = None,
        ) -> list[dict[str, Any]]:
        '''### Summary
        Execute a statement which fetches results and returns them as a list of
        dictionary values.
        
        ### Parameters
        `statements` There should only a single select statement otherwise sqlite
        will error as results weren't fetched between queries
        
        `bindings` Any query bindings/substitutions that need to be made.

        ### Returns
        A list of dictionaries of the results'''
        if "select" not in statements.lower():
            raise ValueError("Expected a select query.")
        
        cursor = self.execute(statements = statements, bindings = bindings)
        items = cursor.fetchall()
        return cast(list[dict[str, Any]], items)
