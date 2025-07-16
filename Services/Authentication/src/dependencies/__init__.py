from __future__ import annotations
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

from runtime import runtime_settings
from database.models.jwk import WebKey
from database.connector import SqliteDatabase



async def database_dependency():
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    try:
        yield database
    finally:
        database.close()



def create_webkey():
    private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    private_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'ByteBrushSoftware LLC'),
    ])
    certificate = x509.CertificateBuilder(
        subject_name = name,
        issuer_name = name,
        public_key = public_key,
        serial_number = x509.random_serial_number(),
        not_valid_before = datetime.now(tz = timezone.utc),
        not_valid_after = datetime.now(tz = timezone.utc) + timedelta(days = 90),
    ).sign(
        private_key = private_key,
        algorithm = hashes.SHA256(),
    )
    return WebKey(
        private_pem = private_pem,
        certificate = certificate.public_bytes(serialization.Encoding.DER),
    )


__all__ = [
    'database_dependency'
]

