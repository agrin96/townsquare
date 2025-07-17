from __future__ import annotations
import asyncio
from enum import Enum
from argon2 import PasswordHasher
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

from runtime import runtime_settings
from database.models import Scope
from database.models.jwk import WebKey
from database.methods import users, scopes, webkeys
from database.connector import SqliteDatabase



class ScopeValues(Enum):
    '''### Summary
    Here we define the scopes that are used and valid for this service. These are built in
    and do not require additional setup. Additional scopes must be regested via dedicated
    serivce or admin methods.'''
    status                   = Scope(scope = ('authentication', 'status'))
    token_refreh             = Scope(scope = ('authentication', 'token', 'refresh'))
    user_self_read           = Scope(scope = ('authentication', 'user', 'self', 'read'))
    user_self_deregister     = Scope(scope = ('authentication', 'user', 'self', 'deregister'))
    user_self_full           = Scope(scope = ('authentication', 'user', 'self'))
    user_register            = Scope(scope = ('authentication', 'user', 'register'))
    admin_lineage_invalidate = Scope(scope = ('authentication', 'admin', 'user', 'lineage', 'invalidate'))
    admin_user_full          = Scope(scope = ('authentication', 'admin', 'user'))
    admin_service            = Scope(scope = ('authentication',))

    @property
    def scope_string(self) -> str:
        return self.value.model_dump()['scope']



def create_scope_values(database: SqliteDatabase):
    '''### Summary
    Populates our scopes table with an initial set of values to dictate minimal required
    permissions for the authentication service. Run this in a lifecycle event'''
    with database:
        database.executemany(
            statements = 'INSERT OR IGNORE INTO scopes VALUES (NULL, @scope);',
            sequenceofbindings = [scope.value.model_dump() for scope in ScopeValues]
        )



def create_serivice_admin(database: SqliteDatabase):
    '''### Summary
    Create a default service level admin user for this service. The service admin role
    has a password which is generated from the service env. This is set only once.'''
    hashed_password = PasswordHasher().hash(
        password = runtime_settings.service_password,
        salt = runtime_settings.hashing_salt,
    )

    database.execute('BEGIN')
    admin_user = users.create(
        database = database,
        email = 'service-admin',
        hashed_password = hashed_password, 
        ignore_if_exists = True,
    )
    scopes.assign_scopes_to_user(
        database = database,
        user_id = admin_user.id,
        assignments = [ScopeValues.admin_service.value]
    )
    database.execute('COMMIT')




async def run_certificate_rotation():
    '''### Summary
    Certificates need to be rotated/expired after some set periods. Our strategy is to
    keep at most 2 certificates active at a time: "current" and "previous" where the
    current is the most recent key and the previous will be the one that will expire. 
    Run this function from a background process in lifecycle to automatically manage
    key rotations.
    
    ### Parameters
    - `database` A database connection instance'''  
    while True:
        database = SqliteDatabase(database_file = runtime_settings.database_file)
        current_keys = webkeys.get_keys(database)
        if len(current_keys) == 0:
            print('Creating new key for empty database')
            new_webkey = create_webkey() 
            webkeys.insert(database, key = new_webkey)

        timenow = datetime.now(tz = timezone.utc)
        if len(current_keys) == 1:
            # We only have a current key. If the current key is expiring in 40 days or 
            # less, we can create a new current key (rotate keys). 
            print('Checking current key for rotation need')
            ttl = current_keys[0].not_valid_after - timenow
            if ttl <= runtime_settings.certificate_rotation.rotate_key_days_remaining:
                new_webkey = create_webkey()
                webkeys.insert(database, key = new_webkey)

        if len(current_keys) == 2:
            current, previous = current_keys[0], current_keys[1]

            # If the preivous key is expiring in 3 days or less, we can invalidate it.
            # and delete it.
            ttl = previous.not_valid_after - timenow
            if ttl <= runtime_settings.certificate_rotation.expire_key_days_remaining:
                webkeys.delete(database = database, key = previous)

            # If the current key is expiring in 40 days or less, we can create a new 
            # current key (rotate keys)
            ttl = current.not_valid_after - timenow
            if ttl <= runtime_settings.certificate_rotation.rotate_key_days_remaining:
                new_webkey = create_webkey()
                webkeys.insert(database, key = new_webkey)

        print('certificate rotation cycle complete')
        database.close()
        await asyncio.sleep(60 * 60 * 24)



def create_webkey():
    '''### Summary
    Create a new webkey and sign it using the certificate information. Note that the 
    subject and issuer can be the same, but for third party validations you'd need a 
    reputable CA to be the issuer.

    The name information is a set of attributes dictated by @cryptography.hazmat._oid.NameOID
    These are components of your certificate signature data and allow people to identify
    the signing organization. All the fields are optional and you can provide as many as
    you want/need.

    ### Returns
    A WebKey object.'''
    private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    private_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    subject_information = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'Penguia'),
    ])
    issuer_information = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'Penguia'),
    ])

    certificate = x509.CertificateBuilder(
        subject_name = subject_information,
        issuer_name = issuer_information,
        public_key = public_key,
        serial_number = x509.random_serial_number(),
        not_valid_before = datetime.now(tz = timezone.utc),
        not_valid_after = (
            datetime.now(tz = timezone.utc)
            + runtime_settings.certificate_rotation.key_lifetime
        ),
    ).sign(
        private_key = private_key,
        algorithm = hashes.SHA256(),
    )
    return WebKey(
        private_pem = private_pem,
        certificate = certificate.public_bytes(serialization.Encoding.DER),
    )
