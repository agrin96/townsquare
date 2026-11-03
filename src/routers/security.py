from __future__ import annotations
import jwt
from typing import Annotated
from argon2 import PasswordHasher
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from fastapi import (
    Depends,
    APIRouter,
    HTTPException,
    Security,
    status,
)
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from pydantic import BaseModel
from runtime import runtime_settings 
from dependencies import database_dependency

from database.values import ScopeValues
from database.models import User, TokenData
from database.methods import users, webkeys
from database.connector import SqliteDatabase
from database.models.scope import Scope
from database.models.jwk import WebKey, WebKeyPublic



router = APIRouter(
    tags = ['security'],
    dependencies = [],
)



password_hasher = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl = router.prefix + '/token',
    refreshUrl = router.prefix + '/refresh',
)


class TokenPublic(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str | None = None



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



def parse_token(token: str, database: SqliteDatabase) -> TokenData:
    keys = webkeys.get_keys(database = database)
    token_data: TokenData | None = None
    for key in keys:
        try:
            payload = jwt.decode(token, key.public_pem, algorithms = [key.algorithm])
            token_data = TokenData(**payload)
        except:
            pass
    if token_data is None:
        print('Unable to decode token')
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = 'unable to validate credentials',
        )
    return token_data



def authenticate_user_token(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
    database: SqliteDatabase = Depends(database_dependency),
) -> User:
    credential_validation_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = 'unable to validate credentials',
    )

    token_data = parse_token(token = token , database = database)
    user = users.get_by_identifier(database = database, identifier = token_data.subject)
    if user is None:
        print(f'User not found for token_data: {token_data.model_dump_json(indent = 2)}')
        raise credential_validation_exception

    # If someone tries to login with a previous token lineage this likely means the refresh
    # key was stolen at some point. We invalidate all existing tokens by creating a new 
    # token lineage.
    if token_data.lineage != user.token_lineage:
        print(f'Token lineage {token_data.lineage} does not match expected {user.token_lineage}')
        user = users.update_lineage(database = database, user = user)
        raise credential_validation_exception

    # The token has expired
    if token_data.expiration < datetime.now(tz = timezone.utc):
        credential_validation_exception.detail = 'expired'
        raise credential_validation_exception

    securities = [Scope(scope = value) for value in security_scopes.scopes]
    for security in securities:
        if not token_data.is_valid_scope(security):
            raise HTTPException(
                status_code = status.HTTP_403_FORBIDDEN,
                detail = 'insufficient permissions',
            )
    return user 



async def authenticate_password_credentials(
    email: str,
    password: str,
    database: SqliteDatabase,
) -> User:
    '''### Summary
    Verify the users' password and email (username in oauth terms) by checking against
    our database information.

    ### Parameters
    - `email` The users email
    - `password` The plain user password sent from the frontend
    - `database` database connector instance 

    ### Returns
    A User object if authentication succeeded'''
    hashed_password = password_hasher.hash(
        password = password,
        salt = runtime_settings.hashing_salt,
    )
    user = users.get_for_credentials(
        database = database,
        email = email,
        hashed_password = hashed_password,
    )
    if user is None:
        raise HTTPException(
            status_code = 400,
            detail = 'Incorrect username or password'
        )
    return user



@router.post('/token')
async def login_for_access_token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    database: SqliteDatabase = Depends(database_dependency),
) -> TokenPublic:
    '''### Summary'''
    user = await authenticate_password_credentials(
        email = form.username,
        password = form.password,
        database = database,
    )
    webkey = webkeys.get_latest_key(database = database)
    access_token = TokenData(
        sub = str(user.identifier),
        kid = webkey.key_id,
        lineage = user.token_lineage,
        scopes = user.scopes,
    )
    refresh_token = TokenData(
        sub = str(user.identifier),
        kid = webkey.key_id,
        lineage = user.token_lineage,
        scopes = [ScopeValues.token_refreh.value],
    )

    access_token = create_token(
        data = access_token,
        webkey = webkey,
        expires = runtime_settings.user_token_lifetime.access 
    )
    refresh_token = create_token(
        data = refresh_token,
        webkey = webkey,
        expires = runtime_settings.user_token_lifetime.refresh 
    )

    return TokenPublic(
        access_token = access_token,
        refresh_token = refresh_token,
        token_type = 'bearer',
    )



@router.post('/refresh')
async def refresh_tokens(
    current_user: Annotated[
        User,
        Security(
            authenticate_user_token,
            scopes = [ScopeValues.token_refreh.scope_string],
        )
    ],
    database: SqliteDatabase = Depends(database_dependency),
):
    '''### Summary
    Issue a new set of tokens for the current user. We issue both a new access_token and
    a new refresh_token for the same lineage value that is currently active.'''
    webkey = webkeys.get_latest_key(database = database)
    access_token = TokenData(
        sub = str(current_user.identifier),
        kid = webkey.key_id,
        lineage = current_user.token_lineage,
        scopes = current_user.scopes,
    )
    refresh_token = TokenData(
        sub = str(current_user.identifier),
        kid = webkey.key_id,
        lineage = current_user.token_lineage,
        scopes = [ScopeValues.token_refreh.value],
    )

    access_token = create_token(
        data = access_token,
        webkey = webkey,
        expires = timedelta(minutes = 10)
    )
    refresh_token = create_token(
        data = refresh_token,
        webkey = webkey,
        expires = timedelta(days = 30)
    )
    return TokenPublic(
        access_token = access_token,
        refresh_token = refresh_token,
        token_type = 'bearer',
    )




@router.get('/.well-known/jwks.json')
async def current_json_web_keys(
    database: SqliteDatabase = Depends(database_dependency),
) -> list[WebKeyPublic]:
    return [key.public for key in webkeys.get_keys(database = database)]

