/*
Store JWKs which we rotate and use to sign and verify our transactions. We use asymmetric
RSA keys by default since this is basically standard. The expires value dictates when
this key will no longer be valid. We should rotate the key well before this time. At and
given time we will only actively allow 2 keys to be valid.
*/
CREATE TABLE IF NOT EXISTS json_web_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT,
    key_type TEXT,
    use TEXT,
    private_pem BLOB,
    certificate BLOB
);
