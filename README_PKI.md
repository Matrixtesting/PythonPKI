# Private PKI Utility for Mbed TLS, Mutual TLS, and EAP-TLS Testing

This directory contains a small Python-based private Public Key Infrastructure (PKI) utility intended for development and laboratory use.

The utility consists of:

- `generate_pki.py`
  - Creates or reuses a private root Certificate Authority (CA).
  - Issues a TLS server certificate and private key.
  - Issues an EAP-TLS / mutual-TLS client certificate and private key.
  - Exports the client identity as a PKCS#12 (`.p12`) bundle.
- `renew_client.py`
  - Renews or replaces an individual client identity using the existing CA.
  - Preserves the previous active client credential set in an archive.
  - Supports command-line overrides for identity, validity period, configuration file, and PKCS#12 password.
- `cfg.txt`
  - Defines PKI paths, identity fields, RSA key sizes, certificate lifetimes, Subject Alternative Names, and the PKCS#12 export password.

The immediate use case is a Windows Mbed TLS 4.1.1 TLS 1.3 client/server test. The same private PKI layout is also intended to support later mutual TLS and 802.1X/EAP-TLS testing.

> **Important:** These scripts are development/test utilities. They are not a complete production CA platform. In particular, production CA private keys should normally be protected by stronger operational controls, encrypted storage, HSM-backed keys, access controls, auditing, revocation infrastructure, and formal issuance procedures.

---

## 1. Requirements

The scripts require Python 3 and the `cryptography` package.

Example:

```cmd
python --version
python -m pip install cryptography
```

The project that originally used these scripts was tested with a project-local Python installation, but the scripts themselves are not tied to a specific Python installation directory.

---

## 2. PKI Model

The PKI created by these tools uses a simple one-level hierarchy:

```text
Private Root CA
    |
    +-- TLS Server Certificate
    |
    `-- Client / Supplicant Certificate
```

The root CA signs both server and client certificates.

```text
                       Private Root CA
                         ca.key
                         ca.pem
                            |
             +--------------+--------------+
             |                             |
             v                             v
       server.pem                     client.pem
       server.key                     client.key
                                      client.p12
```

The CA private key is used only for certificate issuance.

The CA public certificate can be distributed to systems that need to trust certificates issued by the CA.

---

## 3. Generated Directory Structure

With the default configuration:

```ini
[PATHS]
base_dir = enterprise_pki
```

the generated structure is:

```text
enterprise_pki\
|
|-- ca\
|   |-- ca.key
|   `-- ca.pem
|
|-- server\
|   |-- server.key
|   `-- server.pem
|
`-- clients\
    `-- <client-common-name>\
        |-- active\
        |   |-- client.key
        |   |-- client.pem
        |   `-- client.p12
        |
        `-- archive\
            `-- <timestamp>\
                |-- client.key
                |-- client.pem
                `-- client.p12
```

The `archive` directory is populated by `renew_client.py` when an existing active client credential set is replaced.

---

## 4. File Descriptions

### `ca.key`

The RSA private key for the private root CA.

This is the most sensitive file produced by the utility. It is used to sign server and client certificates.

It should never be:

- committed to Git,
- distributed to clients,
- copied into the Mbed TLS application project,
- placed on embedded devices,
- included in release packages.

For laboratory use the current implementation stores it as an unencrypted PEM file. That simplifies testing but is not an appropriate production CA-key protection model.

### `ca.pem`

The public X.509 certificate for the private root CA.

This file is not secret. Systems use it as a trust anchor when validating certificates issued by this CA.

For the local Mbed TLS client/server test, copy or rename it to:

```text
certs\test-ca.pem
```

The Mbed TLS client uses `test-ca.pem` to validate `server.pem`.

### `server.key`

The private RSA key belonging to the TLS server.

For the current Mbed TLS server test it is copied locally to:

```text
certs\server.key
```

The Mbed TLS server loads this key at runtime.

Do not commit this file to Git.

### `server.pem`

The X.509 TLS server certificate.

It is signed by the private root CA.

The refactored generator creates it with:

```text
Basic Constraints:
    CA = FALSE

Extended Key Usage:
    TLS Web Server Authentication

Key Usage:
    Digital Signature

Subject Alternative Names:
    DNS names from SERVER.san_dns
    IP addresses from SERVER.san_ip
```

For the localhost Mbed TLS test the recommended SAN values are:

```text
DNS:localhost
IP:127.0.0.1
```

### `client.key`

The private RSA key for the client or supplicant identity.

It is intended for later mutual TLS, EAP-TLS, and 802.1X supplicant testing.

It is not needed for the initial server-authentication-only HTTPS test.

Do not commit this file to Git.

### `client.pem`

The X.509 client certificate.

It is signed by the private root CA.

The refactored generator creates it with:

```text
Basic Constraints:
    CA = FALSE

Extended Key Usage:
    TLS Web Client Authentication

Key Usage:
    Digital Signature

Subject Alternative Name:
    RFC822 / email identity
```

The RFC822 Subject Alternative Name is configured using:

```ini
san_email =
```

This value is intentionally separate from the Common Name.

### `client.p12`

A PKCS#12 package containing:

- client private key,
- client certificate,
- root CA certificate.

It is useful for importing the client identity into operating systems, browsers, supplicants, or certificate stores that support PKCS#12.

The file is encrypted using the password configured by:

```ini
p12_password =
```

or supplied through the renewal command line.

PKCS#12 password protection should be treated as transport/import protection, not as a substitute for strong private-key custody.

---

## 5. Recommended `cfg.txt`

A configuration suitable for the Mbed TLS localhost test is:

```ini
[PATHS]
base_dir = enterprise_pki


[ROOT_CA]
country = US
organization = Mbed TLS Test Lab
common_name = Mbed TLS Test Root CA
key_bits = 3072
valid_days = 3650


[SERVER]
country = US
organization = Mbed TLS Test Lab
common_name = localhost

key_bits = 2048
valid_days = 825

san_dns = localhost
san_ip = 127.0.0.1


[CLIENT]
country = US
organization = Mbed TLS Test Lab
common_name = test-client-001

key_bits = 2048
valid_days = 825

san_email = test-client-001@lab.local

p12_password = ChangeThisTestPassword
```

---

## 6. Configuration Reference

### `[PATHS]`

#### `base_dir`

Example:

```ini
base_dir = enterprise_pki
```

Defines the root directory into which all PKI files are written.

Relative paths are resolved relative to the current working directory.

### `[ROOT_CA]`

#### `country`

Example:

```ini
country = US
```

Sets the X.509 Country Name field.

#### `organization`

Example:

```ini
organization = Mbed TLS Test Lab
```

Sets the X.509 Organization field.

#### `common_name`

Example:

```ini
common_name = Mbed TLS Test Root CA
```

Sets the CA certificate Common Name.

#### `key_bits`

Example:

```ini
key_bits = 3072
```

Defines the RSA key size for the CA. The refactored scripts reject RSA sizes below 2048 bits.

#### `valid_days`

Example:

```ini
valid_days = 3650
```

Defines the lifetime of the CA certificate.

A long-lived test CA reduces the need to recreate the trust hierarchy during a development project. The CA should not be casually regenerated once clients or servers depend on it.

### `[SERVER]`

#### `country`

Sets the server certificate Country Name.

#### `organization`

Sets the server certificate Organization field.

#### `common_name`

For the localhost test:

```ini
common_name = localhost
```

Modern hostname verification is based on the Subject Alternative Name extension rather than relying on the Common Name.

#### `key_bits`

Example:

```ini
key_bits = 2048
```

Defines the RSA private-key size for the TLS server.

#### `valid_days`

Example:

```ini
valid_days = 825
```

Defines the validity period of the issued server certificate.

#### `san_dns`

Example:

```ini
san_dns = localhost
```

Defines DNS Subject Alternative Names. The refactored generator accepts comma-separated values.

Example:

```ini
san_dns = localhost,testserver.local,mbedtls-test.lab.local
```

#### `san_ip`

Example:

```ini
san_ip = 127.0.0.1
```

Defines IP-address Subject Alternative Names. Comma-separated values are supported.

Example:

```ini
san_ip = 127.0.0.1,192.168.1.25
```

The script parses these as actual IP-address SAN entries rather than DNS strings.

For the local Windows Mbed TLS test:

```ini
san_dns = localhost
san_ip = 127.0.0.1
```

allows either hostname or loopback-IP testing.

### `[CLIENT]`

#### `country`

Sets the client certificate Country Name.

#### `organization`

Sets the client certificate Organization field.

#### `common_name`

Example:

```ini
common_name = test-client-001
```

Defines the client Common Name.

The current scripts also use this value as part of the client directory path:

```text
clients\<common_name>\
```

The renewal script therefore validates the CN so it cannot contain unsafe Windows filename characters.

#### `key_bits`

Example:

```ini
key_bits = 2048
```

Defines the client RSA key size.

#### `valid_days`

Example:

```ini
valid_days = 825
```

Defines the client certificate validity period.

`renew_client.py` also supports overriding this value on the command line.

#### `san_email`

Example:

```ini
san_email = test-client-001@lab.local
```

Defines the client's RFC822 Subject Alternative Name.

This field is required by the refactored design and does not silently fall back to the Common Name.

#### `p12_password`

Example:

```ini
p12_password = ChangeThisTestPassword
```

Defines the password used when exporting `client.p12`.

Do not use a production secret in a configuration file committed to source control.

---

## 7. `generate_pki.py`

`generate_pki.py` is responsible for initial PKI creation and general certificate issuance.

Its most important design rule is:

> The root CA is persistent.

Older versions of the script regenerated the CA every time the script was run. That behavior is dangerous once any certificates have been deployed because replacing the CA immediately changes the trust hierarchy.

The refactored behavior is:

```text
Does ca.key and ca.pem exist?
        |
        +-- No --> Create new root CA
        |
        `-- Yes --> Load and reuse existing root CA
```

The CA is replaced only when explicitly requested.

### Normal PKI Generation

```cmd
python generate_pki.py
```

The script reads `cfg.txt` by default.

A different configuration file can be supplied:

```cmd
python generate_pki.py --config custom_cfg.txt
```

### CA Reuse

When both:

```text
enterprise_pki\ca\ca.key
enterprise_pki\ca\ca.pem
```

exist, the script loads them rather than generating a new CA.

Before reuse, the refactored script verifies:

- both files exist together,
- the private key is RSA,
- the public key in `ca.pem` matches `ca.key`,
- the certificate has `BasicConstraints CA=TRUE`.

### Explicit CA Replacement

To intentionally replace the root CA:

```cmd
python generate_pki.py --recreate-ca
```

This operation is destructive from a trust perspective.

A newly created CA will not validate certificates issued by the previous CA. Any system that trusts the old CA must be updated.

### Root CA Certificate Contents

The generated CA certificate includes:

```text
Basic Constraints:
    CA = TRUE

Key Usage:
    Digital Signature
    Certificate Sign
    CRL Sign

Subject Key Identifier

Authority Key Identifier
```

The CA certificate is self-signed using SHA-256.

### Server Certificate Generation

The server certificate is generated using a new RSA key.

It includes:

```text
Basic Constraints:
    CA = FALSE

Key Usage:
    Digital Signature

Extended Key Usage:
    TLS Web Server Authentication

Subject Alternative Name:
    DNS entries
    IP-address entries

Subject Key Identifier

Authority Key Identifier
```

For the TLS 1.3-only Mbed TLS server, RSA key encipherment is intentionally not requested.

### Client Certificate Generation

The client certificate includes:

```text
Basic Constraints:
    CA = FALSE

Key Usage:
    Digital Signature

Extended Key Usage:
    TLS Web Client Authentication

Subject Alternative Name:
    RFC822 identity

Subject Key Identifier

Authority Key Identifier
```

This certificate is intended for future Mbed TLS mutual-TLS testing and EAP-TLS/802.1X authentication.

### Certificate Clock Skew

The refactored scripts set `notBefore` slightly before the current UTC time:

```text
notBefore = current UTC time - 5 minutes
```

This reduces failures caused by small clock differences between issuing and validating systems.

---

## 8. `renew_client.py`

`renew_client.py` replaces an existing client identity while preserving the current root CA.

It is intended for:

- certificate renewal,
- replacing a client private key,
- issuing a different validity period,
- changing a client SAN,
- generating an updated PKCS#12 bundle.

It does not regenerate the CA.

### Basic Renewal

Using all values from `cfg.txt`:

```cmd
python renew_client.py
```

### Override the Client Common Name

```cmd
python renew_client.py --cn "device02@lab.local"
```

Short form:

```cmd
python renew_client.py -n "device02@lab.local"
```

### Override the Client SAN

```cmd
python renew_client.py --cn "device02" --san "device02@lab.local"
```

The Common Name and RFC822 SAN are intentionally independent.

### Override the Validity Period

```cmd
python renew_client.py --cn "pos-terminal-14@lab.local" --days 30
```

The renewal script rejects validity periods less than or equal to zero.

The refactored design also verifies that the requested client certificate does not outlive the root CA certificate.

### Alternate Configuration File

```cmd
python renew_client.py --config custom_cfg.txt
```

### Override the PKCS#12 Password

```cmd
python renew_client.py --password "SecurePass123!"
```

A password passed directly on the command line may be visible in shell history or process inspection.

The refactored design also supports:

```cmd
python renew_client.py --password-file p12_password.txt
```

### Renewal Transaction Model

The key safety improvement is ordering.

Unsafe model:

```text
Archive current credentials
        |
Generate replacement
```

If generation fails, the client may be left without active credentials.

Refactored model:

```text
Load and validate CA
        |
Generate new key and certificate in memory
        |
Create PKCS#12 package
        |
Write complete set into staging directory
        |
Reload and validate staged files
        |
Archive existing active directory
        |
Rename staged directory to active
        |
Complete
```

If activation fails after the old identity has been archived, the script attempts to restore the previous active directory.

### Staging Validation

Before touching the old active credentials, the staged replacement set is reloaded and checked:

- PEM private key parses,
- PEM certificate parses,
- key matches certificate,
- PKCS#12 opens with the expected password,
- PKCS#12 contains both key and certificate,
- PKCS#12 key and certificate match.

### Client Credential Archiving

Existing active credentials are moved to:

```text
clients\<client-cn>\archive\<timestamp>\
```

Example:

```text
enterprise_pki\
`-- clients\
    `-- test-client-001\
        |-- active\
        |   |-- client.key
        |   |-- client.pem
        |   `-- client.p12
        |
        `-- archive\
            `-- 20260929_185501_123456Z\
                |-- client.key
                |-- client.pem
                `-- client.p12
```

Microseconds are included in the timestamp to reduce collision risk.

### CA Validation During Renewal

Before issuing a replacement certificate, the refactored renewal design checks:

- `ca.key` exists,
- `ca.pem` exists,
- they exist together,
- the CA key is RSA,
- the key matches the CA certificate,
- `BasicConstraints` exists,
- `BasicConstraints.ca` is true,
- `KeyUsage` exists,
- `KeyUsage.keyCertSign` is true,
- the CA is currently valid.

If any check fails, renewal stops before modifying active client credentials.

---

## 9. Mbed TLS Project Integration

Keep the Python PKI data separate from the application repository.

Example:

```text
PKI tooling / generated data
    enterprise_pki\
        ca\
        server\
        clients\

Mbed TLS project
    certs\
        cacert.pem
        test-ca.pem
        server.pem
        server.key
```

For the Windows TLS test, copy:

```text
enterprise_pki\ca\ca.pem
        ->
mbedtls-test\certs\test-ca.pem
```

Copy:

```text
enterprise_pki\server\server.pem
        ->
mbedtls-test\certs\server.pem
```

Copy:

```text
enterprise_pki\server\server.key
        ->
mbedtls-test\certs\server.key
```

The previously downloaded public CA bundle remains:

```text
mbedtls-test\certs\cacert.pem
```

### `cacert.pem` vs `test-ca.pem`

`cacert.pem` is the public CA bundle used when connecting to public HTTPS servers such as Cloudflare.

`test-ca.pem` is the public certificate for the private CA generated by this utility and is used when connecting to the local test server.

A public CA bundle cannot validate `server.pem` because `server.pem` was signed by the private test CA.

```text
test-ca.pem
     |
     | validates signature
     v
server.pem
     |
     +-- server.key
```

### Current TLS Test Certificate Set

```text
certs\
|-- cacert.pem
|-- test-ca.pem
|-- server.pem
`-- server.key
```

Runtime copies are placed under:

```text
out\build\gcc-debug\certs\
```

The client uses `test-ca.pem` for localhost testing.

The server uses `server.pem` and `server.key`.

The server does not need the CA certificate during the initial server-authentication-only test because it is not yet authenticating clients.

---

## 10. Future Mutual TLS

When mutual TLS is enabled:

```text
CLIENT                               SERVER

test-ca.pem                          test-ca.pem
client.pem                           server.pem
client.key                           server.key
```

The client verifies the server certificate.

The server verifies the client certificate.

Both certificates are signed by the same private root CA.

---

## 11. Future EAP-TLS / 802.1X Use

The client certificate is intentionally generated with:

```text
Extended Key Usage:
    clientAuth
```

and an RFC822 SAN.

That makes the certificate structure suitable for later EAP-TLS experiments.

The PKCS#12 bundle is useful for importing a client identity into operating systems and supplicants that support `.p12` or `.pfx`.

The embedded RT1062 device may ultimately use a different provisioning/storage format even though the same CA issues the certificate.

---

## 12. Git and Source-Control Policy

Generated private-key material should not be committed.

At minimum, ignore:

```gitignore
*.key
*.key.pem
*.p12
*.pfx
```

For a development repository, it is often simpler to ignore the entire generated PKI tree:

```gitignore
/enterprise_pki/
```

For the Mbed TLS application repository, generated test files can remain untracked:

```gitignore
/certs/test-ca.pem
/certs/server.pem
/certs/server.key
```

The CA private key should never be placed in the application repository.

---

## 13. Recommended Separation of Responsibilities

```text
pki-tools\
|-- generate_pki.py
|-- renew_client.py
|-- cfg.txt
`-- README.md

generated-local-data\
`-- enterprise_pki\
    |-- ca\
    |-- server\
    `-- clients\

mbedtls-test\
|-- client\
|-- server\
|-- certs\
|-- CMakeLists.txt
`-- ...
```

The PKI tool repository can be public if it does not contain secrets.

The generated credential directory should remain private/local.

---

## 14. Security Notes

### Root CA Key

`ca.key` is the critical trust secret.

Anyone who obtains it can issue certificates trusted by systems that trust `ca.pem`.

### Server Private Key

`server.key` proves possession of the server identity.

### Client Private Key

`client.key` proves possession of the client identity.

For EAP-TLS this becomes the device or supplicant authentication secret.

### Unencrypted PEM Keys

The current scripts intentionally write PEM private keys without encryption to simplify Mbed TLS laboratory testing.

That is not a final production key-storage design.

For embedded production work, key storage may ultimately move to:

- secure element,
- hardware-backed key store,
- protected flash,
- PSA Crypto key slots,
- device-specific provisioning.

---

## 15. Certificate Lifetime Rules

The refactored renewal design prevents issuance of a client certificate whose expiration date is later than the CA certificate expiration.

This avoids creating a client certificate that outlives its issuer.

The same principle should eventually be applied consistently to all issuance paths.

---

## 16. Testing the Generated Files

Confirm expected files exist:

```cmd
dir enterprise_pki\ca
dir enterprise_pki\server
dir enterprise_pki\clients
```

Expected CA files:

```text
ca.key
ca.pem
```

Expected server files:

```text
server.key
server.pem
```

Expected client files:

```text
client.key
client.pem
client.p12
```

PEM certificate files should begin with:

```text
-----BEGIN CERTIFICATE-----
```

and end with:

```text
-----END CERTIFICATE-----
```

Do not paste private-key contents into public tickets, GitHub issues, documentation, or chat logs.

---

## 17. Typical Initial Workflow

```text
1. Edit cfg.txt.
2. Run generate_pki.py.
3. Confirm enterprise_pki\ca\ca.pem exists.
4. Confirm enterprise_pki\server\server.pem exists.
5. Confirm enterprise_pki\server\server.key exists.
6. Copy ca.pem to the Mbed TLS project as test-ca.pem.
7. Copy server.pem to the Mbed TLS project.
8. Copy server.key to the Mbed TLS project.
9. Build mbedtls_server.exe and mbedtls_client.exe.
10. Run the local TLS 1.3 client/server test.
```

---

## 18. Typical Client Renewal Workflow

```text
1. Confirm the existing CA is intact.
2. Run renew_client.py.
3. New credentials are generated in staging.
4. Staged credentials are reloaded and validated.
5. Previous active credentials are archived.
6. New credentials become active.
7. Deploy/import the new client identity as appropriate.
```

Example:

```cmd
python renew_client.py --cn "device02@lab.local" --san "device02@lab.local" --days 90
```

---

## 19. Troubleshooting

### `cfg.txt` not found

Run the script from the correct directory or provide:

```cmd
python generate_pki.py --config path\to\cfg.txt
```

or:

```cmd
python renew_client.py --config path\to\cfg.txt
```

### CA files are incomplete

If only one of these exists:

```text
ca.key
ca.pem
```

the refactored scripts should stop rather than guess how to recover.

Restore the matching pair or deliberately create a new CA.

### CA key does not match CA certificate

Locate the correct CA pair.

Do not override the check.

### Server hostname verification fails

For localhost testing, confirm:

```ini
san_dns = localhost
```

and connect using:

```text
localhost
```

For IP-address testing, confirm:

```ini
san_ip = 127.0.0.1
```

A DNS SAN containing the text `127.0.0.1` is not equivalent to an IP-address SAN.

### Client SAN error

Use an email-style RFC822 identity such as:

```ini
san_email = device01@lab.local
```

### PKCS#12 password problems

For `renew_client.py`, the password can come from:

1. `--password`,
2. `--password-file`,
3. `cfg.txt`.

### Renewal leaves no active identity

The refactored renewal design is intended to avoid this through staging and rollback.

If testing reveals a failure in this logic, do not deploy the script further until the transaction behavior has been corrected and retested.

---

## 20. Validation Status

The scripts described here were refactored from earlier development utilities.

The design has been reviewed for:

- persistent CA handling,
- certificate/key matching,
- explicit SAN handling,
- TLS 1.3-oriented server certificate usage,
- client EAP-TLS usage,
- certificate renewal staging,
- credential archival,
- rollback intent,
- Git/private-key separation.

The scripts should still be functionally tested before being treated as production-quality tooling.

Recommended tests include:

```text
Fresh CA creation
Existing CA reuse
Explicit CA recreation
Server certificate SAN inspection
Client certificate SAN inspection
CA/key mismatch detection
Missing CA file detection
Expired CA detection
Client renewal
Archive creation
PKCS#12 import
Renewal failure before activation
Activation rollback behavior
```

---

## 21. Intended Project Progression

```text
1. TLS 1.3 Windows client against public HTTPS server
2. TLS 1.3 Windows client against local private-CA server
3. Local server certificate validation
4. Mutual TLS
5. Client certificate renewal
6. HTTPS application tests
7. Embedded RT1062 TLS client
8. EAP-TLS / 802.1X integration
9. Final embedded Mbed TLS feature pruning
```

The same private root CA can support these development milestones as long as the CA is kept intact and trusted consistently.

---

## 22. Summary

`generate_pki.py` establishes and maintains the private trust hierarchy.

`renew_client.py` replaces individual client identities without replacing the root CA.

`cfg.txt` defines identity, lifetime, key-size, SAN, and output-path policy.

The key operational rules are:

```text
Do not casually regenerate the CA.

Do not commit private keys.

Keep the CA private key outside the application project.

Use test-ca.pem to validate locally issued certificates.

Use cacert.pem only for public Internet PKI trust.

Use SANs for server identity validation.

Keep clientAuth and serverAuth purposes distinct.

Stage and validate replacement client credentials before retiring the current set.
```

This provides a small, understandable PKI suitable for controlled Mbed TLS development while preserving a path toward mutual TLS and EAP-TLS testing.
