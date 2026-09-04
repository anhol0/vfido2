# vAuth

A Lamellix Labs virtual FIDO2 authenticator for Linux-based systems.

See [ROADMAP.md](ROADMAP.md) for the security and feature work remaining before
using vAuth with real credentials.

## Database security setup

The credential database is stored at `/var/lib/vauth/credentials.v1`. Its
AES-256-GCM key is generated and sealed by TPM2-TSS FAPI at
`/HS/SRK/vauth-database-key` together with the TPM counter value observed at
provisioning. A separately authorized TPM NV counter at
`/nv/Owner/vauth-db-generation` detects replacement with an older, otherwise
valid database. Recording the counter origin allows provisioning on TPMs whose
new counters begin above one because of earlier counter use.

Credential signing keys are children of an authenticated deterministic primary
that is recreated as a transient TPM object when the daemon starts. The parent
uses no persistent handle, and each credential receives a non-empty
authorization derived from the sealed database key and credential ID. Public
and private TPM child blobs remain inside the encrypted credential database.
Creating the transient primary uses the TPM owner hierarchy with its normal
empty hierarchy authorization; if an administrator sets an owner hierarchy
authorization, startup fails rather than bypassing it. The primary and its
children use their own non-empty derived authorizations.

Normal daemon startup never creates or replaces either persistent store-security
object: the sealed key and rollback counter are provisioning-only. Provisioning
is an explicit administrative operation:

```sh
sudo tss2_provision
sudo install -d -m 0700 /etc/credstore.encrypted
sudo systemd-creds encrypt --name=vauth-db-auth - \
  /etc/credstore.encrypted/vauth-db-auth
sudo systemd-run --wait --pipe --property=Type=oneshot \
  --property=LoadCredentialEncrypted=vauth-db-auth:/etc/credstore.encrypted/vauth-db-auth \
  /usr/local/bin/vauth provision
```

Enter a non-empty authorization of at most 32 bytes when `systemd-creds`
prompts. Keep its recovery material separately; losing the authorization or
clearing the TPM makes the database unrecoverable.

Debug builds provide a development-only command for removing every credential
while preserving the sealed database key and rollback-counter objects:

```sh
sudo systemctl stop vauth
sudo ./build/vauth clear-store --yes --auth-file .dev/vauth-db-auth
```

The command authenticates and loads the existing database, commits an encrypted
empty collection atomically, and advances the rollback counter. It refuses to
run while another current vAuth process holds the store lock. An older database
copy cannot be restored after the counter advances. Non-Debug builds do not
advertise or accept `clear-store`.

[`config/vauth.service.example`](config/vauth.service.example) shows how to pass
the encrypted credential to the daemon. The service identity must be able to
open `/dev/uhid`, the TPM resource-manager device, and the FAPI system keystore.
It must also be the intended PAM authentication identity for this single-user
authenticator.

PCR binding is intentionally not enabled yet: a fixed PCR policy can make the
database unavailable after routine boot or software updates. Add it only with a
tested signed-policy and recovery procedure.

This design protects database confidentiality, detects offline tampering and
rollback, and requires authorization for TPM object use. It cannot protect
secrets from a live root compromise that can inspect or inject into the daemon.
Credential child blobs are bound to the source TPM and deterministic parent, so
copying the database and its plaintext encryption key to a different TPM does
not make the credentials portable.

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

When `swtpm` and the TPM2/FAPI command-line tools are installed, CTest also runs
the isolated software-TPM provisioning and authorization test.
