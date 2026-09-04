#!/usr/bin/env bash
set -euo pipefail

test_binary=$1
profile_directory=$2
test_directory=$(mktemp -d /tmp/vauth-swtpm-test.XXXXXX)
server_socket=$test_directory/server.sock
control_socket=$server_socket.ctrl

cleanup() {
    if [[ -S $control_socket ]]; then
        swtpm_ioctl --unix "$control_socket" -s >/dev/null 2>&1 || true
    fi
    rm -rf -- "$test_directory"
}
trap cleanup EXIT

mkdir -m 700 \
    "$test_directory/state" \
    "$test_directory/user" \
    "$test_directory/system" \
    "$test_directory/log"

cat >"$test_directory/fapi-config.json" <<EOF
{
  "profile_name": "P_ECCP256SHA256",
  "profile_dir": "$profile_directory",
  "user_dir": "$test_directory/user",
  "system_dir": "$test_directory/system",
  "tcti": "swtpm:path=$server_socket",
  "ek_cert_less": "yes",
  "system_pcrs": [],
  "log_dir": "$test_directory/log/",
  "firmware_log_file": "/dev/null",
  "ima_log_file": "/dev/null"
}
EOF

swtpm socket \
    --tpm2 \
    --tpmstate "dir=$test_directory/state" \
    --ctrl "type=unixio,path=$control_socket" \
    --server "type=unixio,path=$server_socket" \
    --flags not-need-init \
    --daemon

tcti="swtpm:path=$server_socket"
tpm2_startup -c -T "$tcti"
TSS2_FAPICONF="$test_directory/fapi-config.json" tss2_provision

# A new TPM counter is not required to begin at one. Exercise provisioning
# after an earlier counter has advanced and been deleted.
history_index=0x0180ffff
tpm2_nvdefine "$history_index" \
    -C o \
    -s 8 \
    -a "ownerread|ownerwrite|nt=counter" \
    -T "$tcti"
tpm2_nvincrement "$history_index" -C o -T "$tcti"
tpm2_nvincrement "$history_index" -C o -T "$tcti"
tpm2_nvundefine "$history_index" -C o -T "$tcti"

TSS2_FAPICONF="$test_directory/fapi-config.json" \
    "$test_binary" setup \
    "$test_directory/credentials.v1" \
    correct-horse-battery \
    incorrect-authorization

tpm2_flushcontext -t -T "$tcti"
tpm2_clear -c p -T "$tcti"
TSS2_FAPICONF="$test_directory/fapi-config.json" \
    "$test_binary" verify-tpm-clear correct-horse-battery
