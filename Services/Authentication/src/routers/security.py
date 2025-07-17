from __future__ import annotations
from uuid import UUID

import jwt
from typing import Annotated
from argon2 import PasswordHasher
from pydantic import BaseModel 
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from fastapi import (
    Depends,
    APIRouter,
    HTTPException,
    Response,
    Security,
    status,
)
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from starlette.status import HTTP_201_CREATED
from runtime import runtime_settings 
from database.connector import SqliteDatabase
from database.values import ScopeValues
from dependencies import database_dependency
from database.models import (
    User,
    TokenData,
    UserPublic,
)
from database.methods import users, scopes, webkeys
from database.models.scope import Scope
from database.models.user import UserRequest
from database.models.jwk import WebKey, WebKeyPublic


router = APIRouter(
    prefix = '/',
    tags = ['security'],
    dependencies = [],
)



class TokenPublic(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str | None = None



password_hasher = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl = router.prefix + '/token',
    refreshUrl = router.prefix + '/refresh',
)



def create_token(data: TokenData, webkey: WebKey, expires: timedelta | None = None):
    '''### Summary'''
    payload = data.model_dump() 
    if expires:
        expiration = datetime.now(tz = timezone.utc) + expires
        payload['exp'] = expiration

    return jwt.encode(
        payload = payload,
        key = webkey.private_pem,
        algorithm = webkey.algorithm.value,
    ) 
