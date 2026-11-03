from typing import Any
from datetime import timedelta
from pydantic_settings import BaseSettings, SettingsConfigDict
    


class CertificateRotationSettings(BaseSettings):
    '''### Summary
    Controls the key rotation system. Determines how long keys live and when they should
    expire
    
    ### Parameters
    - `key_lifetime` How many days a key should be active at most.
    - `rotate_key_days_remaining` When there are this many days remaining in the current
    keys lifecycle, we should create a enw key to be the current.
    - `expire_key_days_remaining` At how many days remaining we should completly expire
    the current (previous) key. We keep this above zero since we want to expire before 
    the actual date, otherwise there would be 3 keys.
    '''
    key_lifetime: timedelta = timedelta(days = 90)
    rotate_key_days_remaining: timedelta = timedelta(days = 40)
    expire_key_days_remaining: timedelta = timedelta(days = 2)

    

class TokenLifetime(BaseSettings):
    access: timedelta
    refresh: timedelta



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

    certificate_rotation: CertificateRotationSettings = CertificateRotationSettings()
    user_token_lifetime: TokenLifetime = TokenLifetime(
        access = timedelta(minutes = 10),
        refresh = timedelta(days = 30)
    )
    service_token_lifetime: TokenLifetime = TokenLifetime(
        access = timedelta(days = 18),
        refresh = timedelta(days = 180)
    )



runtime_settings = Runtime()
'''### Summary
Application level global settings. Should only be run once on startup and is treated
as a singleton object. Only import needed from this module.'''



__all__ = [
    'runtime_settings'
]
