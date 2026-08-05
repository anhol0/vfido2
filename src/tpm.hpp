#pragma once
#include <cstdint>
#include <vector>
#include <tss2/tss2_esys.h>

static constexpr TPMI_RH_NV_INDEX STORE_KEY_NV_INDEX = 0x01500001;
static constexpr uint16_t         STORE_KEY_SIZE      = 32;

// Returns 32 bit encryption key.
// On the first run generates it using TPM 
// On subsequent runs gets it from the TPM NVRAM
std::vector<uint8_t> get_or_create_store_key();
