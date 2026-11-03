from __future__ import annotations
from typing import Sequence
from uuid import UUID
from pydantic import BaseModel
from argon2 import PasswordHasher
from fastapi import (
    Depends,
    APIRouter,
    HTTPException,
    Security,
    status,
)
from database.values import ScopeValues
from database.connector import SqliteDatabase
from dependencies import database_dependency
from database.models import User
from database.models.scope import DatabaseScope, Scope
from .security import authenticate_user_token
from database.methods import users, scopes
from database.models.user import UserRequest



password_hasher = PasswordHasher()
router = APIRouter(
    prefix = '/admin',
    tags = ['admin'],
    dependencies = [],
)



AdminAuthenticationDependancy = Security(
    authenticate_user_token,
    scopes = [ScopeValues.admin_lineage_invalidate.scope_string]
)



class UpdatedLineage(BaseModel):
    previous: UUID
    new: UUID



@router.patch('/user/lineage', dependencies = [AdminAuthenticationDependancy])
def invalidate_token(
    request_data: UserRequest,
    database: SqliteDatabase = Depends(database_dependency),
) -> UpdatedLineage:
    '''### Summary
    Invalide the provided user's current token lineage. This will generate a new lineage
    and make all currently issued tokens invalid, requiring user re-authentication.
    
    ### Parameters
    - `request_data` The user information provided. Used to lookup the current user.'''
    user: User | None = None
    if request_data.id:
        user = users.get_by_id(database = database, id = request_data.id) 
    if request_data.email:
        user = users.get_by_email(database = database, email = request_data.email) 
    if request_data.identifier:
        user = users.get_by_identifier(database = database, identifier = request_data.identifier)
    if user is None:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = 'user does not exist',
        )

    previous_lineage = user.token_lineage
    updated_user = users.update_lineage(database = database, user = user)
    return UpdatedLineage(previous = previous_lineage, new = updated_user.token_lineage)



class RegisterScopeRequest(BaseModel):
    scopes: Sequence[str]
    provider: str = 'admin'



@router.post('/scopes', dependencies = [AdminAuthenticationDependancy])
def add_scopes(scope_values: RegisterScopeRequest, database: SqliteDatabase = Depends(database_dependency)):
    database.execute('BEGIN')
    for value in scope_values.scopes:
        scopes.insert(
            database = database,
            scope = Scope(scope = value, provider = scope_values.provider)
        )
    database.execute('COMMIT')



@router.get('/scopes', dependencies = [AdminAuthenticationDependancy])
def get_scopes(
    provider: str | None = None,
    database: SqliteDatabase = Depends(database_dependency),
) -> list[DatabaseScope]:
    return scopes.get(database = database, provider = provider)
