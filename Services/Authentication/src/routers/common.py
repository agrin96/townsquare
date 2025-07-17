
from __future__ import annotations
import jwt
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel
from database.models.jwk import WebKey
from database.models.token import TokenData



class TokenPublic(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str | None = None



def create_token(data: TokenData, webkey: WebKey, expires: timedelta | None = None):
    '''### Summary'''
    payload = data.model_dump() 
    if expires:
        expiration = datetime.now(tz = timezone.utc) + expires
        payload['exp'] = expiration

    return jwt.encode(
        payload = payload,
        key = webkey.private_pem,
        algorithm = webkey.algorithm.value,
    ) 
