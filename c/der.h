#pragma once

#include <stdint.h>
#include <stddef.h>

// Convert DER-encoded ECDSA signature to raw 64-byte r||s format.
// der_sig: input DER signature (0x30 || len || ...)
// der_len: length of DER signature
// raw_out: output buffer, must be at least 64 bytes
// Returns 0 on success, nonzero on error.
int der_to_raw(const uint8_t *der_sig, size_t der_len, uint8_t *raw_out);
