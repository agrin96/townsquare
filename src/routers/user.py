from __future__ import annotations
from typing import Annotated
from argon2 import PasswordHasher
from fastapi import (
    Depends,
    APIRouter,
    HTTPException,
    Response,
    Security,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from runtime import runtime_settings 
from database.values import ScopeValues
from database.connector import SqliteDatabase
from dependencies import database_dependency
from database.models import (
    User,
    UserPublic,
)
from .security import authenticate_user_token
from database.methods import users, scopes



password_hasher = PasswordHasher()
router = APIRouter(
    prefix = '/user',
    tags = ['user'],
    dependencies = [],
)



AuthenticatedUserDependency = Annotated[
    User,
    Security(
        authenticate_user_token,
        scopes = [ScopeValues.user_self_deregister.scope_string]
    )
]



@router.post('/')
async def create_new_user(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    database: SqliteDatabase = Depends(database_dependency),
):
    if users.does_email_exist(database = database, email = form.username):
        raise HTTPException(
            status_code = 409,
            detail = 'An account with that email address already exists'
        )
    hashed_password = password_hasher.hash(
        password = form.password,
        salt = runtime_settings.hashing_salt,
    )

    database.execute('BEGIN')
    new_user = users.create(
        database = database,
        email = form.username,
        hashed_password = hashed_password
    )
    scopes.assign_scopes_to_user(
        database = database,
        user_id = new_user.id,
        assignments = [
            ScopeValues.status.value,
            ScopeValues.user_self_full.value,
        ],
    )
    database.execute('COMMIT')
    return Response(status_code = status.HTTP_201_CREATED) 



@router.delete('/')
async def delete_user(
    current_user: AuthenticatedUserDependency ,
    database: SqliteDatabase = Depends(database_dependency),
):
    users.delete(database = database, user = current_user)



@router.get('/')
async def get_user(current_user: AuthenticatedUserDependency) -> UserPublic:
    return UserPublic(email = current_user.email, identifier = current_user.identifier) 
