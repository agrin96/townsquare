from __future__ import annotations
from uuid import uuid4
from pydantic import BaseModel, Field

from .scope import Scope
from common import UUIDString



class ServiceBase(BaseModel):
    service_name: str



class DatabaseService(ServiceBase):
    '''### Summary
    Raw database representation of our service. May include data uncessary throughout most
    of our application.

    ### Parameters
    - `id` The internal database id of this row
    - `service_name` the self-identified service name. e.g. "payments-service-hash" 
    - `token_lineage` The token lineage is an identifier of the current valid set of 
    access and refresh tokens. Each token should have a lineage value checked against the
    lineage value of the service.
    - `hashed_password` The hashed password of the user created at registration'''
    id: int
    hashed_secret: str
    token_lineage: UUIDString



class Service(ServiceBase):
    '''### Summary
    Internal service representation. Contains data from multiple tables.

    ### Parameters
    - `service_name` the self-identified service name. e.g. "payments-service-hash" 
    - `token_lineage` The token lineage is an identifier of the current valid set of 
    access and refresh tokens. Each token should have a lineage value checked against the
    lineage value of the service.
    - `scopes` The set of scopes assigned to this service'''
    scopes: list[Scope] = Field(default_factory = list)
    token_lineage: UUIDString = Field(default_factory = uuid4)
