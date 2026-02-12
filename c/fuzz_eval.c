#include <stdint.h>
#include <stddef.h>
#include "eval.h"

// Fuzz the bytecode evaluator directly with arbitrary bytecode.
// First byte: low nibble = msg length (0..15), bit 4 = has device_id.
// If has_device_id, next 32 bytes are the device ID.
// Remaining bytes are bytecode.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    size_t msg_len = data[0] & 0x0F;
    int has_device_id = (data[0] & 0x10) != 0;
    size_t offset = 1;

    if (offset + msg_len > size) return 0;
    const uint8_t *msg = data + offset;
    offset += msg_len;

    device_context_t dctx;
    eval_t e;
    eval_init(&e);

    if (has_device_id) {
        if (offset + 32 > size) return 0;
        dctx.device_id = data + offset;
        dctx.device_id_len = 32;
        e.ctx = &dctx;
        offset += 32;
    }

    const uint8_t *code = data + offset;
    size_t code_len = size - offset;

    eval_with_xmsg(&e, code, code_len, msg, msg_len);

    return 0;
}
