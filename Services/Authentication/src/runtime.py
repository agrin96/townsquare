from enum import Enum
from typing import Any
from datetime import timedelta
from pydantic_settings import BaseSettings, SettingsConfigDict



SET_FROM_ENVIRONMENT: Any = object()
class Runtime(BaseSettings):
    '''### Summary
    Runtime settings for Authentication Service

    ### Parameters
    - `secret_key` The secret key is a generated random hash used as a seed phrase for
    token generation. This will be used to sign tokens and check their authenticity.
    - `token_expiration` How long a token should be valid for. Otherwise a new token needs
    to be issued. This essentially controls how long a user stays logged in.'''
    model_config = SettingsConfigDict(
        env_nested_delimiter = '___',
        env_file = 'prod.env',
    )
    hashing_salt: bytes         = 'meow my name is a cat'.encode()
    service_password: str       = SET_FROM_ENVIRONMENT
    token_expiration: timedelta = timedelta(seconds = 3_600)
    database_file: str          = './test.sqlite' 



runtime_settings = Runtime()
'''### Summary
Application level global settings. Should only be run once on startup and is treated
as a singleton object. Only import needed from this module.'''



__all__ = [
    'runtime_settings'
]
