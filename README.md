# vFIDO2

Windows Hello for Linux-based systems.

## Database security setup

The credential database is stored at `/var/lib/vfido/credentials.v1`. Its
AES-256-GCM key is generated and sealed by TPM2-TSS FAPI at
`/HS/SRK/vfido-database-key`. A separately authorized TPM NV counter at
`/nv/Owner/vfido-db-generation` detects replacement with an older, otherwise
valid database.

Normal daemon startup never creates or replaces either TPM object. Provisioning
is an explicit administrative operation:

```sh
sudo tss2_provision
sudo install -d -m 0700 /etc/credstore.encrypted
sudo systemd-creds encrypt --name=vfido-db-auth - \
  /etc/credstore.encrypted/vfido-db-auth
sudo systemd-run --wait --pipe --property=Type=oneshot \
  --property=LoadCredentialEncrypted=vfido-db-auth:/etc/credstore.encrypted/vfido-db-auth \
  /usr/local/bin/vfido provision
```

Enter a non-empty authorization of at most 32 bytes when `systemd-creds`
prompts. Keep its recovery material separately; losing the authorization or
clearing the TPM makes the database unrecoverable.

For an existing `/etc/vfido2/cred.bin`, stop the daemon and run `migrate` after
provisioning:

```sh
sudo systemd-run --wait --pipe --property=Type=oneshot \
  --property=LoadCredentialEncrypted=vfido-db-auth:/etc/credstore.encrypted/vfido-db-auth \
  /usr/local/bin/vfido migrate
```

Migration authenticates and validates the legacy database, writes and reloads
the new versioned database, and only then deletes the old raw-key NV index. The
old encrypted file is retained for audit/recovery handling.

[`config/vfido.service.example`](config/vfido.service.example) shows how to pass
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

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

When `swtpm` and the TPM2/FAPI command-line tools are installed, CTest also runs
the isolated software-TPM provisioning and authorization test.
