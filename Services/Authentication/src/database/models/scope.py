from __future__ import annotations
from typing import Annotated, Any, Sequence
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
    Sequence[str],
    BeforeValidator(parse_to_scope_string),
    PlainSerializer(lambda v: ':'.join(v)),
]



class ScopeBase(BaseModel):
    scope: ScopeString 

    def __hash__(self) -> int:
        return hash(self.scope)
    
    def __str__(self) -> str:
        return self.model_dump()['scope']

    def contains_scope(self, scope: Scope) -> bool:
        '''### Summary
        Determines if this scope encompases the permissions defined by the argument
        scope. This can happen if a more specific permission is being compared with a 
        less specfic permission

        ### Example
        ```
        self = ('authentication', 'user', 'self')
        scope = ('authentication', 'user', 'self', 'read')
        returns True
        ```

        ### Parameters
        - `scope` The permission we are checking against the current scope.

        ### Returns
        True if the current Scope contains all the permissions of the passed scope.'''
        def recursor(parts: Sequence[str]):
            if len(parts) == 0:
                return False
            if parts == self.scope:
                return True
            return recursor(parts = parts[:-1])
        return recursor(scope.scope)



class DatabaseScope(ScopeBase):
    '''### Summary
    Raw database representation of a scope row. May include data uncessary throughout most
    of our application.
    
    ### Parameters
    - `id` The internal database id of this row.
    - `scope` The heirarchical sequence of permisssions from broadest to most specific.'''
    id: int



class Scope(ScopeBase):
    '''### Summary
    Provides an interface for storing a colon separated string values as a sequence of
    strings; typically a tuple. Serves only to wrap the scope value and provide pydantic
    functionality.
    
    ### Parameters:
    - `scope` The heirarchical sequence of permisssions from broadest to most specific.'''





