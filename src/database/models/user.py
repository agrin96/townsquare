from __future__ import annotations
from uuid import uuid4
from pydantic import BaseModel, Field

from .scope import Scope
from common import UUIDString



class UserBase(BaseModel):
    email: str | None = None



class UserRequest(UserBase):
    '''### Summary
    Represents the possible options for a route request based on the User object. The
    request object is different in that all the fields are optional since not every
    field may be needed.
    
    ### Parameters
    - `id` The internal database id of this row
    - `identifier` The user unique id we can pass around our services
    - `email` The email of the user
    - `token_lineage` The token lineage is an identifier of the current valid set of 
    access and refresh tokens. Each token should have a lineage value checked against the
    lineage value of the user.'''
    id: int | None = None
    email: str | None = None
    identifier: UUIDString | None = None
    token_lineage: UUIDString | None = None


 
class DatabaseUser(UserBase):
    '''### Summary
    Raw database representation of our user. May include data uncessary throughout most
    of our application.

    ### Parameters
    - `id` The internal database id of this row
    - `identifier` The user unique id we can pass around our services
    - `email` The email of the user
    - `token_lineage` The token lineage is an identifier of the current valid set of 
    access and refresh tokens. Each token should have a lineage value checked against the
    lineage value of the user.
    - `hashed_password` The hashed password of the user created at registration'''
    id: int
    identifier: UUIDString
    hashed_password: str
    token_lineage: UUIDString



class User(UserBase):
    '''### Summary
    Internal user representation. Contains data from multiple tables.

    ### Parameters
    - `identifier` The user unique id we can pass around our services
    - `email` The email of the user
    - `token_lineage` The token lineage is an identifier of the current valid set of 
    access and refresh tokens. Each token should have a lineage value checked against the
    lineage value of the user.
    - `scopes` The set of scopes assigned to this user'''
    scopes: list[Scope] = Field(default_factory = list)
    identifier: UUIDString = Field(default_factory = uuid4)
    token_lineage: UUIDString = Field(default_factory = uuid4)



class UserPublic(UserBase):
    '''### Summary
    Public user interface. Safe to return in authenticated routes 

    ### Parameters
    - `identifier` The user unique id we can pass around our services
    - `email` The email of the user'''
    identifier: UUIDString
