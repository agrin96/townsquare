from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone
import os

from fastapi import FastAPI
from runtime import runtime_settings
from filelock import FileLock, Timeout
from contextlib import asynccontextmanager

import routers
from database.connector import SqliteDatabase
from database.tables import create_tables
from database.values import (
    create_serivice_admin,
    create_scope_values,
    run_certificate_rotation,
)



@asynccontextmanager
async def lifespan(app: FastAPI):
    database = SqliteDatabase(database_file = runtime_settings.database_file)
    create_tables(database = database) 
    print('Created database tables')
    
    create_scope_values(database = database)
    print('Inserted predefined scope values')

    create_serivice_admin(database = database)
    print('Created service admin')

    # NOTE: When running with multiple workers this prevents us from launching several 
    # background tasks at the same time.
    lock = FileLock('certificate_rotation.lock', timeout = 3)
    try:
        lock.acquire()
        asyncio.create_task(run_certificate_rotation())
        print('Launched certificate rotation')
    except Timeout:
        print('certificate_rotation locked by another worker.')

    yield
    # drop_tables(database = database)
    database.close()
    lock.release()
    os.remove(lock.lock_file)
    


app = FastAPI(lifespan = lifespan)
app.include_router(routers.user.router)
app.include_router(routers.service.router)


# TODO: 
# 7. Add service registration method (service_name + password (random hash from source env))
# 8. Add service endpoint for registering new scopes
# 9. Add super admin method for CRUDing scopes/users/services.


def main():
    # database = SqliteDatabase(':memory:') 
    # database = SqliteDatabase(database_file = runtime_settings.database_file)
    # user = users.get_by_email(database = database, email = 'aleksandr@gmail.com')
    # print(user)
    # is_subscope = ScopeValues.user_self_full.value.contains_scope(scope = ScopeValues.user_self_read.value)
    # print(is_subscope)
    #
    # is_subscope = ScopeValues.user_self_read.value.contains_scope(scope = ScopeValues.user_self_full.value)
    # print(is_subscope)
    import base64
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    private_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )
    print(private_pem)

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    n_bytes = numbers.n.to_bytes(256)
    print(n_bytes.hex())
    e_bytes = numbers.e.to_bytes(3)
    print(base64.b64encode(e_bytes).decode('utf-8'))
    print(int.from_bytes(base64.b64decode('AQAB')))

    public_pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print(public_pem)

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
    # Calculate SHA-1 hash of the DER-encoded certificate
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    sha1_hash = hashes.Hash(hashes.SHA1())
    sha1_hash.update(certificate_der)
    x5t_bytes = sha1_hash.finalize()
    # x5t = base64.urlsafe_b64encode(x5t_bytes).decode('utf-8').rstrip('=')
    x5t = base64.urlsafe_b64encode(x5t_bytes).decode('utf-8')
    print('X5T: ', x5t)
    
    # Base64 encode the DER-encoded certificate for x5c
    x5c_entry = base64.b64encode(certificate_der).decode('utf-8')
    x5c = [x5c_entry] # For a self-signed certificate, the chain contains only itself.
    print(x5c)

    # decode the not until and not after
    key = base64.b64decode(x5c[0])
    rebuilt_certificate = x509.load_der_x509_certificate(key)
    print(rebuilt_certificate.not_valid_after_utc)




if __name__ == "__main__":
    main()
