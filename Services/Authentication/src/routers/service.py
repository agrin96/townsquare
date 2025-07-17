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
    Response,
    Security,
    status,
)
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from runtime import runtime_settings 
from dependencies import database_dependency
from database.values import ScopeValues
from database.connector import SqliteDatabase
from database.models import TokenData
from database.models.scope import Scope

from .common import TokenPublic, create_token
from database.models.service import Service
from database.methods import services, scopes, webkeys



router = APIRouter(
    prefix = '/service',
    tags = ['services'],
    dependencies = [],
)



password_hasher = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl = router.prefix + '/token',
    refreshUrl = router.prefix + '/refresh',
)



async def authenticate_password_credentials(
    service_name: str,
    password: str,
    database: SqliteDatabase,
) -> Service:
    '''### Summary
    Verify the service secret and name (username in oauth terms) by checking against
    our database information.

    ### Parameters
    - `service_name` The service name 
    - `secret` The service registration password 
    - `database` database connector instance 

    ### Returns
    A Service object if authentication succeeded'''
    hashed_secret = password_hasher.hash(
        password = password,
        salt = runtime_settings.hashing_salt,
    )
    service = services.get_for_credentials(
        database = database,
        service_name = service_name,
        secret = hashed_secret, 
    )
    if service is None:
        raise HTTPException(
            status_code = 400,
            detail = 'Incorrect service name or secret'
        )
    return service



async def authenticate_token(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
    database: SqliteDatabase = Depends(database_dependency),
) -> Service:
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

    service = services.get_by_name(database, service_name = token_data.subject)
    if service is None:
        print(f'Service not found for token_data: {token_data.model_dump_json(indent = 2)}')
        raise credential_validation_exception

    # If someone tries to login with a previous token lineage this likely means the refresh
    # key was stolen at some point. We invalidate all existing tokens by creating a new 
    # token lineage.
    if token_data.lineage != service.token_lineage:
        print(f'Token lineage {token_data.lineage} does not match expected {service.token_lineage}')
        services.update_lineage(database, service = service)
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
    return service 



@router.post('/token')
async def register_service_for_access_code(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    database: SqliteDatabase = Depends(database_dependency),
) -> TokenPublic:
    '''### Summary'''
    service = await authenticate_password_credentials(
        service_name = form.username,
        password = form.password,
        database = database,
    )
    webkey = webkeys.get_latest_key(database = database)
    access_token = TokenData(
        sub = service.service_name,
        kid = webkey.key_id,
        lineage = service.token_lineage,
        scopes = service.scopes,
    )
    refresh_token = TokenData(
        sub = service.service_name,
        kid = webkey.key_id,
        lineage = service.token_lineage,
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
    service: Annotated[
        Service,
        Security(
            authenticate_token,
            scopes = [ScopeValues.token_refreh.scope_string],
        )
    ],
    database: SqliteDatabase = Depends(database_dependency),
):
    '''### Summary
    Issue a new set of tokens for the service. We issue both a new access_token and
    a new refresh_token for the same lineage value that is currently active.'''
    webkey = webkeys.get_latest_key(database = database)
    access_token = TokenData(
        sub = service.service_name,
        kid = webkey.key_id,
        lineage = service.token_lineage,
        scopes = service.scopes,
    )
    refresh_token = TokenData(
        sub = service.service_name,
        kid = webkey.key_id,
        lineage = service.token_lineage,
        scopes = [ScopeValues.token_refreh.value],
    )

    access_token = create_token(
        data = access_token,
        webkey = webkey,
        expires = timedelta(hours = 6)
    )
    refresh_token = create_token(
        data = refresh_token,
        webkey = webkey,
        expires = timedelta(days = 90)
    )
    return TokenPublic(
        access_token = access_token,
        refresh_token = refresh_token,
        token_type = 'bearer',
    )
