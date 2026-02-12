#pragma once

#include <stdint.h>
#include <stddef.h>
#include "eval.h"

// Evaluate an xsig machine001 program.
// Returns 1 if verification succeeds (final stack == [1]), 0 otherwise.
int run_machine001(const uint8_t *xpubkey, size_t xpubkey_len,
                   const uint8_t *xsig, size_t xsig_len,
                   const uint8_t *msg, size_t msg_len);

// Like run_machine001 but with a device context for OP_DEVICEID.
int run_machine001_with_context(const uint8_t *xpubkey, size_t xpubkey_len,
                                const uint8_t *xsig, size_t xsig_len,
                                const uint8_t *msg, size_t msg_len,
                                const device_context_t *ctx);
