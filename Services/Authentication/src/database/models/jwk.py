from __future__ import annotations
import base64
from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pydantic import BaseModel, ConfigDict, Field, PlainSerializer



UUIDString = Annotated[UUID, PlainSerializer(lambda v: str(v))]



class KeyType(str, Enum):
    RSA = 'RSA'
    ELIPTIC_CURVE = 'EC'
    OCTET = 'oct'



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



class WebKeyUse(str, Enum):
    SIG = 'sig'
    ENC = 'enc'



class WebKeyBase(BaseModel):
    key_id: UUIDString 
    algorithm: Algorithm
    key_type: KeyType
    use: WebKeyUse
    private_pem: bytes
    certificate: bytes 

    @property
    def public_pem(self) -> bytes:
        private_key = serialization.load_pem_private_key(self.private_pem, password = None)
        assert isinstance(private_key, RSAPrivateKey), 'Only RSAPrivateKey is supported'
        return private_key.public_key().public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @property
    def webkey(self) -> WebKey:
        return WebKey(**self.model_dump())



class DatabaseWebKey(WebKeyBase):
    pass



class WebKey(WebKeyBase):
    key_id: UUIDString = Field(default_factory = uuid4)
    algorithm: Algorithm = Algorithm.RS256
    key_type: KeyType = KeyType.RSA
    use: WebKeyUse = WebKeyUse.SIG
    private_pem: bytes 
    certificate: bytes 

    @property
    def modulus(self) -> str:
        private_key = serialization.load_pem_private_key(self.private_pem, password = None)
        assert isinstance(private_key, RSAPrivateKey), 'Only RSAPrivateKey is supported'
        if self.algorithm == Algorithm.RS256:
            modulus = private_key.public_key().public_numbers().n.to_bytes(256)
            return base64.urlsafe_b64encode(modulus).decode('utf-8')
        raise ValueError('Only RS256 is currently implemented') 


    @property
    def exponent(self) -> str:
        private_key = serialization.load_pem_private_key(self.private_pem, password = None)
        assert isinstance(private_key, RSAPrivateKey), 'Only RSAPrivateKey is supported'
        if self.algorithm == Algorithm.RS256:
            exponent = private_key.public_key().public_numbers().e.to_bytes(3)
            return base64.urlsafe_b64encode(exponent).decode('utf-8')
        raise ValueError('Only RS256 is currently implemented') 


    @property
    def certificate_sha(self) -> str:
        loaded_certificate = x509.load_der_x509_certificate(self.certificate)
        der = loaded_certificate.public_bytes(serialization.Encoding.DER) 

        sha_hash = hashes.Hash(hashes.SHA1())
        sha_hash.update(der)
        hashed = sha_hash.finalize()

        return base64.urlsafe_b64encode(hashed).decode('utf-8')


    @property
    def not_valid_after(self) -> datetime:
        loaded_certificate = x509.load_der_x509_certificate(self.certificate)
        return loaded_certificate.not_valid_after_utc


    @property
    def not_valid_before(self) -> datetime:
        loaded_certificate = x509.load_der_x509_certificate(self.certificate)
        return loaded_certificate.not_valid_before_utc

    
    @property
    def public(self) -> WebKeyPublic:
        return WebKeyPublic(**{
            **self.model_dump(),
            'modulus': self.modulus,
            'exponent': self.exponent,
            'certificate': base64.urlsafe_b64encode(self.certificate).decode('utf-8'),
            'certificate_hash': self.certificate_sha,
        })



class WebKeyPublic(BaseModel):
    model_config = ConfigDict(extra = 'ignore', populate_by_name = True)

    key_type: KeyType = Field(alias = 'kty')
    algorithm: Algorithm = Field(alias = 'alg')
    key_id: UUIDString = Field(alias = 'kid')
    use: WebKeyUse
    modulus: str = Field(alias = 'n')
    exponent: str = Field(alias = 'e')
    certificate: str = Field(alias = 'x5c')
    certificate_hash: str = Field(alias = 'x5t')


    @property
    def public_pem(self) -> str:
        modulus = int.from_bytes(base64.urlsafe_b64decode(self.modulus))
        exponent = int.from_bytes(base64.urlsafe_b64decode(self.exponent))

        return rsa.RSAPublicNumbers(modulus, exponent).public_key().public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')
    

    @property
    def not_valid_before(self) -> datetime:
        decoded = base64.urlsafe_b64decode(self.certificate)
        loaded_certificate = x509.load_der_x509_certificate(decoded)
        return loaded_certificate.not_valid_before_utc


    @property
    def not_valid_after(self) -> datetime:
        decoded = base64.urlsafe_b64decode(self.certificate)
        loaded_certificate = x509.load_der_x509_certificate(decoded)
        return loaded_certificate.not_valid_after_utc

