from __future__ import annotations
from uuid import UUID, uuid4
from typing import Any
from pydantic import BaseModel, Field

from .scope import Scope
from .token import TokenData



class UserBase(BaseModel):
    email: str | None = None
    identifier: UUID = Field(default_factory = uuid4)


 
SET_BY_DATABASE: Any = object()
class DatabaseUser(UserBase):
    '''### Summary
    Raw database representation of our user. May include data uncessary throughout most
    of our application.

    ### Parameters
    - `id` The internal database id of this row
    - `identifier` The user unique id we can pass around our services
    - `email` The email of the user
    - `hashed_password` The hashed password of the user created at registration'''
    id: int = SET_BY_DATABASE 
    hashed_password: str | None = None



class User(UserBase):
    '''### Summary
    Internal user representation. Contains data from multiple tables.

    ### Parameters
    - `identifier` The user unique id we can pass around our services
    - `email` The email of the user
    - `scopes` The set of scopes assigned to this user'''
    scopes: list[Scope] = Field(default_factory = list)

    @property
    def token_data(self) -> TokenData:
        return TokenData(
            subject = str(self.identifier),
            scopes = self.scopes,
        )



class UserPublic(UserBase):
    '''### Summary
    Public user interface. Safe to return in authenticated routes 

    ### Parameters
    - `identifier` The user unique id we can pass around our services
    - `email` The email of the user'''
    pass
