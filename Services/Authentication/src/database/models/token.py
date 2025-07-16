from __future__ import annotations
from typing import Annotated, Any
from datetime import datetime, timedelta, timezone
from uuid import UUID
from pydantic import (
    Field,
    BaseModel,
    ConfigDict,
    BeforeValidator,
    PlainSerializer,
)
from .scope import Scope



UUIDString = Annotated[UUID, PlainSerializer(lambda v: str(v))]


def validate_scope(value: Any) -> list[Scope]:
    if isinstance(value, str):
        return [ Scope(scope = v) for v in value.split(' ')]

    if not (isinstance(value, list) or isinstance(value, tuple)):
        return [] 

    if len(value) == 0:
        return [] 

    if (isinstance(value[0], str)):
        return [ Scope(scope = v) for v in value ]

    if (isinstance(value[0], dict)):
        return [ Scope(scope = v['scope']) for v in value]

    if (isinstance(value[0], Scope)):
        return list(value) 
    raise ValueError(f'Unrecognized input for scope: {type(value)} {value}')



class TokenData(BaseModel):
    '''### Summary
    Represents a parsed JWT token or data about to be transformed into a JWT token.

    ### Parameters
    - `subject` This is the token subject whether that is a user id or email or some other
    identifier. Preferrably the identifier should be something we don't care if it gets out.
    - `expiration` The set expiration datetime of the token. After this time, the token
    becomes invalid and a new one must be generated.
    - `lineage` The token lineage is an identifier of the current valid set of access
    and refresh tokens. Each token should have a lineage value checked against the
    lineage value of the user.
    - `key_id` The id of the WebKey which was used to sign this request and as such must
    be used to validate the request.
    - `scopes` A list of Scopes (permissions) associated with this token. These scopes
    are validated against the route securities to grant or deny access.'''
    model_config = ConfigDict(populate_by_name = True, extra = 'ignore')

    subject: str = Field(alias = 'sub')
    lineage: UUIDString
    key_id: UUIDString = Field(alias = 'kid')

    expiration: Annotated[
        datetime,
        PlainSerializer(lambda v: int(v.timestamp()))
    ] = Field(
        alias = 'exp',
        default_factory = lambda: datetime.now(tz = timezone.utc) + timedelta(minutes = 5)
    )

    scopes: Annotated[
        list[Scope],
        BeforeValidator(validate_scope),
        PlainSerializer(lambda value: ' '.join([str(v) for v in value])),
    ] = Field(default_factory = list)

        
    def is_valid_scope(self, security: Scope) -> bool:
        '''### Summary
        Validate security scope against the set of scopes in this token data. Checks if 
        the token data has the permissions required by the security.

        ### Parameters
        - `security` The security scope we are checking against. This is the minimal
        permission needed to access whatever resource we are accessing

        ### Returns
        True if the token data has the necessary permissions required by the security
        scope.'''
        for key in self.scopes:
            if key.contains_scope(scope = security):
                return True
        return False
