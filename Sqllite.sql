CREATE TABLE ssn_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_ssn BLOB NOT NULL,
    nonce BLOB NOT NULL
);
