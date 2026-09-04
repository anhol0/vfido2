# vAuth

vAuth is a Lamellix Labs virtual FIDO2 authenticator for Linux. It exposes a
virtual security key through `/dev/uhid`, implements selected CTAP2 operations,
uses PAM for user verification, and keeps credential records in an
AES-256-GCM-encrypted database. Database security material and credential keys
are protected by the system TPM.

The credential database is stored at `/var/lib/vauth/credentials.v1`. vAuth
supports resident and non-resident credentials, user presence and verification,
self-attestation, and TPM-backed assertion signing.

See [ROADMAP.md](ROADMAP.md) for work remaining before using vAuth with
production credentials.

## Build and test

The build requires CMake, a C++20 compiler, pkg-config, TinyCBOR, OpenSSL,
TPM2-TSS ESAPI/FAPI/RC/MU, and PAM development files.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The resulting executable is `build/vauth`. The software-TPM integration test is
enabled when `swtpm` and the TPM2/FAPI command-line tools are installed.

## Provision database security objects

TPM2-TSS FAPI must be provisioned once for the system. Skip the first command if
`tss2_provision` has already completed successfully:

```sh
sudo tss2_provision
```

vAuth provisioning creates an authorized sealed database key at
`/HS/SRK/vauth-database-key` and an authorized rollback counter at
`/nv/Owner/vauth-db-generation`. Normal startup never creates or replaces these
objects.

For a system service, create an encrypted systemd credential and provision vAuth
with it:

```sh
sudo install -d -m 0700 /etc/credstore.encrypted
sudo systemd-creds encrypt --name=vauth-db-auth - \
  /etc/credstore.encrypted/vauth-db-auth
sudo systemd-run --wait --pipe --property=Type=oneshot \
  --property=LoadCredentialEncrypted=vauth-db-auth:/etc/credstore.encrypted/vauth-db-auth \
  /usr/local/bin/vauth provision
```

Enter a non-empty authorization of at most 32 bytes when prompted. Keep recovery
material separately: clearing the TPM or losing this authorization makes the
database unrecoverable. The example service configuration is available at
[`config/vauth.service.example`](config/vauth.service.example).

For local development, pass a mode-`0600` authorization file directly:

```sh
sudo ./build/vauth provision --auth-file .dev/vauth-db-auth
sudo ./build/vauth run --auth-file .dev/vauth-db-auth
```

Provisioning generates the database key and rollback counter. The transient TPM
parent is recreated when vAuth starts, and individual credential keys are
created when passkeys are registered.
