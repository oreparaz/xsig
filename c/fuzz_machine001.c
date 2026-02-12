#include <stdint.h>
#include <stddef.h>
#include "xsig.h"
#include "eval.h"

// Fuzz the main entry point: run_machine001.
// Split input into xpubkey, xsig, and msg using the first bytes as lengths.
// Bit 7 of data[0] signals a 32-byte device_id follows the header.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    size_t xsig_len = data[0] & 0x7F;
    int has_device_id = (data[0] & 0x80) != 0;
    size_t msg_len = data[1];
    size_t offset = 2;

    device_context_t dctx;
    const device_context_t *ctx_ptr = NULL;
    if (has_device_id) {
        if (offset + 32 > size) return 0;
        dctx.device_id = data + offset;
        dctx.device_id_len = 32;
        ctx_ptr = &dctx;
        offset += 32;
    }

    if (offset + xsig_len > size) return 0;
    const uint8_t *xsig = data + offset;
    offset += xsig_len;

    if (offset + msg_len > size) return 0;
    const uint8_t *msg = data + offset;
    offset += msg_len;

    size_t xpubkey_len = size - offset;
    const uint8_t *xpubkey = data + offset;

    run_machine001_with_context(xpubkey, xpubkey_len, xsig, xsig_len, msg, msg_len, ctx_ptr);

    return 0;
}
