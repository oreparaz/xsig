#include <stdint.h>
#include <stddef.h>
#include "eval.h"

// Fuzz the bytecode evaluator directly with arbitrary bytecode.
// First byte selects msg length (0..15), rest is bytecode.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    size_t msg_len = data[0] & 0x0F;
    size_t offset = 1;

    if (offset + msg_len > size) return 0;
    const uint8_t *msg = data + offset;
    offset += msg_len;

    const uint8_t *code = data + offset;
    size_t code_len = size - offset;

    eval_t e;
    eval_init(&e);
    eval_with_xmsg(&e, code, code_len, msg, msg_len);

    return 0;
}
