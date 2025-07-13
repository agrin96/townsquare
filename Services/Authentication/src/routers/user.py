from __future__ import annotations
from tokenize import group

import jwt
from typing import Annotated, cast
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
from fastapi.responses import RedirectResponse
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from starlette.status import HTTP_201_CREATED
from runtime import runtime_settings 
from database.connector import SqliteDatabase
from database.values import ScopeGroupValues, ScopeValues
from dependencies import SecurityScope, database_dependency
from database.models import (
    User,
    TokenData,
    UserPublic,
)
from database.methods import (
    assign_scope_groups_to_user,
    assign_scopes_to_user,
    create_user,
    does_user_email_exist,
    fetch_user_for_basic_auth,
    fetch_user_for_identifier,
)



router = APIRouter(
    prefix = '/user',
    tags = ['security'],
    dependencies = [],
)



password_hasher = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl = router.prefix + '/token')



class TokenPublic(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str | None = None



async def authenticate_user(
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
    user = fetch_user_for_basic_auth(
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



async def authenticate_user_by_token(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
    database: SqliteDatabase = Depends(database_dependency),
) -> User | RedirectResponse:
    credential_validation_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = 'unable to validate credentials',
    )
    try:
        payload = jwt.decode(token, runtime_settings.public_key, algorithms = [runtime_settings.algorithm])
        token_data = TokenData(**payload)
    except Exception as e:
        print(f'Unable to decode token: {e}')
        raise credential_validation_exception

    # The token has expired
    if token_data.expiration > datetime.now(tz = timezone.utc):
        return RedirectResponse(url = router.prefix + '/token') 

    user = fetch_user_for_identifier(database = database, identifier = token_data.subject)
    if user is None:
        print(f'User not found')
        raise credential_validation_exception

    securities = cast(list[SecurityScope], security_scopes.scopes)
    for security in securities:
        for scope_group in security.scope_groups:
            if not token_data.is_valid_scope_group(scope_group):
                raise HTTPException(
                    status_code = status.HTTP_403_FORBIDDEN,
                    detail = 'insufficient permissions',
                )
        for scope in security.scopes:
            if not token_data.is_valid_scope(scope):
                raise HTTPException(
                    status_code = status.HTTP_403_FORBIDDEN,
                    detail = 'insufficient permissions',
                )
    return user



def create_token(data: TokenData, expires: timedelta | None = None):
    '''### Summary'''
    payload = data.model_dump() 
    if expires:
        expiration = datetime.now(tz = timezone.utc) + expires
        payload['exp'] = expiration

    return jwt.encode(
        payload = payload,
        key = runtime_settings.secret_key,
        algorithm = runtime_settings.algorithm,
    ) 



@router.post('/token', response_model = TokenPublic)
async def login_for_access_token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    database: SqliteDatabase = Depends(database_dependency),
) -> TokenPublic:
    '''### Summary'''
    user = await authenticate_user(
        email = form.username,
        password = form.password,
        database = database,
    )
    token = create_token(data = user.token_data)
    return TokenPublic(access_token = token, token_type = 'bearer')



@router.post('/register')
async def register_user(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    database: SqliteDatabase = Depends(database_dependency),
):
    if does_user_email_exist(database = database, email = form.username):
        raise HTTPException(
            status_code = 409,
            detail = 'An account with that email address already exists'
        )
    hashed_password = password_hasher.hash(
        password = form.password,
        salt = runtime_settings.hashing_salt,
    )

    database.execute('BEGIN')
    new_user = create_user(
        database = database,
        email = form.username,
        hashed_password = hashed_password
    )
    assign_scopes_to_user(
        database = database,
        user = new_user,
        assignments = [],
    )
    assign_scope_groups_to_user(
        database = database,
        user = new_user,
        assignments = [
            ScopeGroupValues.basic_user.value,
        ],
    )
    database.execute('COMMIT')
    return Response(status_code = HTTP_201_CREATED) 



get_user_scopes = SecurityScope(
    scopes = [
        ScopeValues.self_full.value,
    ],
    scope_groups = [
        ScopeGroupValues.basic_user.value,
        ScopeGroupValues.authentication_admin.value,
    ]
)

UserDependancy = Annotated[
    User | RedirectResponse,
    Security(authenticate_user_by_token, scopes = [get_user_scopes])
]

@router.get('/current', response_model = UserPublic)
async def get_user(current_user: UserDependancy):
    if isinstance(current_user, User):
        return UserPublic(email = current_user.email) 
    # Redirect to login screen
    return current_user
