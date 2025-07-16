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
    prefix = '/user',
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
    user = users.get_by_auth(
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



async def authenticate_token(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
    database: SqliteDatabase = Depends(database_dependency),
) -> User:
    credential_validation_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = 'unable to validate credentials',
    )
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
        raise credential_validation_exception

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
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = 'expired',
        ) 

    securities = [Scope(scope = value) for value in security_scopes.scopes]
    for security in securities:
        if not token_data.is_valid_scope(security):
            raise HTTPException(
                status_code = status.HTTP_403_FORBIDDEN,
                detail = 'insufficient permissions',
            )
    return user 



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



@router.post('/refresh')
async def refresh_tokens(
    current_user: Annotated[
        User,
        Security(
            authenticate_token,
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
    scopes.assign_scopes(
        database = database,
        user_id = new_user.id,
        assignments = [
            ScopeValues.status.value,
            ScopeValues.user_self_full.value,
        ],
    )
    database.execute('COMMIT')
    return Response(status_code = HTTP_201_CREATED) 



AuthenticatedUserDependency = Annotated[
    User,
    Security(
        authenticate_token,
        scopes = [ScopeValues.user_self_deregister.scope_string]
    )
]
@router.delete('/')
async def delete_user(
    current_user: AuthenticatedUserDependency ,
    database: SqliteDatabase = Depends(database_dependency),
):
    users.delete(database = database, user = current_user)



@router.get('/me')
async def get_user(current_user: AuthenticatedUserDependency) -> UserPublic:
    return UserPublic(email = current_user.email, identifier = current_user.identifier) 



InvalidateTokenDependency = Security(
    authenticate_token,
    scopes = [ScopeValues.admin_lineage_invalidate.scope_string]
)



class UpdatedLineage(BaseModel):
    previous: UUID
    new: UUID



@router.patch('/lineage', dependencies = [InvalidateTokenDependency])
async def invalidate_token(
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



@router.get('/.well-known/jwks.json')
async def current_json_web_keys(
    database: SqliteDatabase = Depends(database_dependency),
) -> list[WebKeyPublic]:
    return [key.public for key in webkeys.get_keys(database = database)]

