from __future__ import annotations
from pydantic import BaseModel, Field
from .scope import Scope



class DatabaseScopeGroup(BaseModel):
    id: int
    group_name: str 



class ScopeGroup(BaseModel):
    group: str 
    scopes: list[Scope] = Field(default_factory = list)
    
    def __hash__(self) -> int:
        return hash((self.group, str([str(v) for v in self.scopes])))

    def __str__(self) -> str:
        return f"group:{self.group}"
