from enum import Enum
from pathlib import Path
from typing import Any
from datetime import timedelta
from pydantic_settings import BaseSettings, SettingsConfigDict



class Algorithm(str, Enum):
    '''### Parameters
    - `RSA256` If using RSA then you will need to generate a secret key using OPENSSL.
    This is done by running "openssl genrsa -out private.pem 2048". This key can be
    exported to your environment via "export SECRET_KEY=$(cat private.pem)"
    - `HS256` If using this algorithm it is enough to generate a random hex string for
    use as your private key. "openssl rand -hex 32"
    '''
    RS256 = 'RS256'
    HS256 = 'HS256'
    HS384 = 'HS384'



SET_FROM_ENVIRONMENT: Any = object()
class Runtime(BaseSettings):
    '''### Summary
    Runtime settings for Authentication Service

    ### Parameters
    - `secret_key` The secret key is a generated random hash used as a seed phrase for
    token generation. This will be used to sign tokens and check their authenticity.
    - `scopes_enabled` Whether to take into account scope validations or not. If enabled
    JWT token scopes will be checked against user assigned scopes.
    - `algorithm` The algorithm to use for generating JWTs. Research shows that RSA256 is
    the most common so that is what we will stick with.
    - `token_expiration` How long a token should be valid for. Otherwise a new token needs
    to be issued. This essentially controls how long a user stays logged in.'''
    model_config = SettingsConfigDict(
        env_nested_delimiter = '___',
        env_file = 'prod.env',
    )
    secret_key: str             = SET_FROM_ENVIRONMENT
    public_key: str             = SET_FROM_ENVIRONMENT
    hashing_salt: bytes         = 'meow my name is a cat'.encode()
    scopes_enabled: bool        = False
    algorithm: Algorithm        = Algorithm.RS256
    token_expiration: timedelta = timedelta(seconds = 3_600)
    # database_file: str          = ':memory:' 
    database_file: str          = './test.sqlite' 



runtime_settings = Runtime()
'''### Summary
Application level global settings. Should only be run once on startup and is treated
as a singleton object. Only import needed from this module.'''



__all__ = [
    'runtime_settings'
]
