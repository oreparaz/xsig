#include <stdint.h>
#include <stddef.h>
#include "xsig.h"

// Fuzz the main entry point: run_machine001.
// Split input into xpubkey, xsig, and msg using the first two bytes as lengths.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    size_t xsig_len = data[0];
    size_t msg_len = data[1];
    size_t offset = 2;

    if (offset + xsig_len > size) return 0;
    const uint8_t *xsig = data + offset;
    offset += xsig_len;

    if (offset + msg_len > size) return 0;
    const uint8_t *msg = data + offset;
    offset += msg_len;

    size_t xpubkey_len = size - offset;
    const uint8_t *xpubkey = data + offset;

    run_machine001(xpubkey, xpubkey_len, xsig, xsig_len, msg, msg_len);

    return 0;
}
