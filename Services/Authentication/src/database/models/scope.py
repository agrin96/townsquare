from __future__ import annotations
from typing import Annotated, Any
from pydantic import BaseModel, BeforeValidator, PlainSerializer



def parse_to_scope_string(v: Any) -> tuple[str, ...]:
    if isinstance(v, str):
        return tuple(v.split(':'))
    if isinstance(v, tuple):
        return v
    if isinstance(v, list):
        return tuple(v)
    raise ValueError()



ScopeString = Annotated[
    tuple[str, ...],
    BeforeValidator(parse_to_scope_string),
    PlainSerializer(lambda v: ':'.join(v)),
]



class Scope(BaseModel):
    scope: ScopeString

    def __hash__(self) -> int:
        return hash(self.scope)
    
    def __str__(self) -> str:
        return self.model_dump()['scope']



class DatabaseScope(BaseModel):
    id: int
    scope: ScopeString 

    def __hash__(self) -> int:
        return hash(self.scope)
