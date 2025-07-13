from __future__ import annotations
from typing import Annotated, Any
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer

from .scope import Scope
from .scope_group import ScopeGroup



def validate_scope_group(value: Any) -> list[ScopeGroup]:
    if not (isinstance(value, list) or isinstance(value, tuple) or isinstance(value, list)):
        return list()

    values = tuple(value)
    if len(values) == 0:
        return list()

    if (isinstance(values[0], str)):
        return list(ScopeGroup(group = v) for v in values) 

    if (isinstance(values[0], ScopeGroup)):
        return list(values) 
    raise ValueError(f'Unrecognized input for scope_group: {type(value)} {values}')



def validate_scope(value: Any) -> list[Scope]:
    if not (isinstance(value, list) or isinstance(value, tuple)):
        return [] 

    if len(value) == 0:
        return [] 

    if (isinstance(value[0], str)):
        return [ Scope(scope = v) for v in value ]

    if (isinstance(value[0], Scope)):
        return list(value) 
    raise ValueError(f'Unrecognized input for scope_group: {type(value)} {value}')



def serialize_scope_group(values: list[ScopeGroup]) -> list[str]:
    return [v.group for v in values]



class TokenData(BaseModel):
    model_config = ConfigDict(populate_by_name = True, extra = 'ignore')

    subject: str = Field(serialization_alias = 'sub')

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
    ] = Field(default_factory = list)

    scope_groups: Annotated[
        list[ScopeGroup],
        PlainSerializer(serialize_scope_group),
        BeforeValidator(validate_scope_group),
    ] = Field(default_factory = list)

    @property
    def total_scopes(self) -> set[Scope]:
        unified = set(self.scopes)
        for group in self.scope_groups:
            group_scopes = set(group.scopes)
            unified = unified.intersection(group_scopes)
        return unified

    def is_valid_scope_group(self, group: ScopeGroup) -> bool:
        values = [sg.group for sg in self.scope_groups]
        return group.group in values

    def is_valid_scope(self, scope: Scope) -> bool:
        scopes = self.total_scopes
        return scope in scopes
