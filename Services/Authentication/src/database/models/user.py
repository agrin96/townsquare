from __future__ import annotations
from uuid import UUID, uuid4
from typing import Any
from pydantic import BaseModel, Field

from .scope import Scope
from .token import TokenData
from .scope_group import ScopeGroup



class UserBase(BaseModel):
    email: str | None = None


 
SET_BY_DATABASE: Any = object()
class DatabaseUser(UserBase):
    id: int = SET_BY_DATABASE 
    identifier: UUID = Field(default_factory = uuid4)
    hashed_password: str | None = None



class User(UserBase):
    identifier: UUID = Field(default_factory = uuid4)
    scopes: list[Scope] = Field(default_factory = list)
    scope_groups: list[ScopeGroup] = Field(default_factory = list)

    @property
    def token_data(self) -> TokenData:
        return TokenData(
            subject = str(self.identifier),
            scopes = self.scopes,
            scope_groups = self.scope_groups,
        )



class UserPublic(UserBase):
    pass
