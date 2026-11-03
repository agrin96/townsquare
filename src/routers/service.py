from __future__ import annotations
import jwt
from typing import Annotated, Sequence
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
from pydantic import BaseModel
from runtime import runtime_settings 
from dependencies import database_dependency
from database.values import ScopeValues
from database.connector import SqliteDatabase
from database.models import TokenData
from database.models.scope import Scope, ScopeString

from .security import TokenPublic, create_token, parse_token
from database.models.service import Service
from database.methods import services, scopes, webkeys



router = APIRouter(
    prefix = '/services',
    tags = ['services'],
    dependencies = [],
)



password_hasher = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl = router.prefix + '/token',
    refreshUrl = router.prefix + '/refresh',
)



async def authenticate_service(
    service_name: str,
    secret: str,
    database: SqliteDatabase,
) -> Service:
    '''### Summary
    Verify the service secret and name (username in oauth terms) by checking against
    our database information.

    ### Parameters
    - `service_name` The service name 
    - `secret` The service registration secret token 
    - `database` database connector instance 

    ### Returns
    A Service object if authentication succeeded'''
    service = services.get_for_credentials(
        database = database,
        service_name = service_name,
        secret = secret, 
    )
    if service is None:
        raise HTTPException(
            status_code = 400,
            detail = 'Incorrect service name or secret'
        )
    return service



async def authenticate_service_token(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
    database: SqliteDatabase = Depends(database_dependency),
) -> Service:
    credential_validation_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = 'unable to validate credentials',
    )

    token_data = parse_token(token = token , database = database)
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
        credential_validation_exception.detail = 'expired'
        raise credential_validation_exception

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
    service = await authenticate_service(
        service_name = form.username,
        secret = form.password,
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
        expires = runtime_settings.service_token_lifetime.access 
    )
    refresh_token = create_token(
        data = refresh_token,
        webkey = webkey,
        expires = runtime_settings.service_token_lifetime.refresh 
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
            authenticate_service_token,
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



class ServiceRegisterRequest(BaseModel):
    service_name: str
    secret: str
    scopes: Sequence[str] 



@router.post('/')
def register_service(
    form: ServiceRegisterRequest,
    database: SqliteDatabase = Depends(database_dependency),
):
    #TODO: 1 check agains the current registration token.
    database.execute('BEGIN')
    services.insert(
        database = database,
        service_name = form.service_name,
        secret = form.secret,
    )

    for value in form.scopes:
        scopes.insert(
            database = database,
            scope = Scope(scope = value, provider = form.service_name)
        )
    database.execute('COMMIT')

